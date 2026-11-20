"""Tests for the Plaid Balance integration.

Covers the configuration gate, model invariants (one active connection per
user), exchange-token guards, balance-update precedence (available vs
current), dashboard integration safety, and that no transaction/raw-payload
storage paths exist.

All Plaid SDK interactions are mocked; tests never hit the network.
"""

from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash

# Other test modules (test_cash_risk_score, test_projection_engine) install
# sys.modules stubs for ``app`` / ``app.models`` / ``app.cashflow``. Pytest
# collects test files in alphabetical order, and conftest.py is imported
# BEFORE any test file, so it captures the real references first. Pull them
# from there to guarantee we test against the real Flask app + ORM models.
from conftest import (  # noqa: E402
    _db as db,
    _Balance as Balance,
    _User as User,
    _PlaidConnection as PlaidConnection,
    _Email as Email,
    _plaid_service as plaid_service,
)
from app.crypto_utils import encrypt_password  # crypto_utils is never stubbed


# ── Helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def plaid_user(flask_app):
    """Create a fresh User with no Plaid connection for each test."""
    with flask_app.app_context():
        user = User(
            email=f"plaid-user-{datetime.utcnow().timestamp()}@test.local",
            password=generate_password_hash("testpw", method="scrypt"),
            name="Plaid User",
            admin=True,
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    yield user_id

    with flask_app.app_context():
        # Clean up Plaid connection + balances + user.
        PlaidConnection.query.filter_by(user_id=user_id).delete()
        Balance.query.filter_by(user_id=user_id).delete()
        User.query.filter_by(id=user_id).delete()
        db.session.commit()


def _configure_plaid(flask_app, **overrides):
    cfg = {
        "PLAID_CLIENT_ID": "client-id",
        "PLAID_SECRET": "secret",
        "PLAID_ENV": "sandbox",
        "PLAID_PRODUCTS": "auth",
        "PLAID_COUNTRY_CODES": "US",
        "PLAID_REDIRECT_URI": "",
    }
    cfg.update(overrides)
    flask_app.config.update(cfg)


def _deconfigure_plaid(flask_app):
    for k in (
        "PLAID_CLIENT_ID",
        "PLAID_SECRET",
        "PLAID_ENV",
        "PLAID_PRODUCTS",
        "PLAID_REDIRECT_URI",
    ):
        flask_app.config[k] = ""


def _make_balances_response(account_id, *, available, current, last_updated_datetime=None):
    balances = SimpleNamespace(
        available=available,
        current=current,
        last_updated_datetime=last_updated_datetime,
    )
    account = SimpleNamespace(account_id=account_id, balances=balances)
    return SimpleNamespace(accounts=[account])


def _make_item_response(last_successful_update=None):
    transactions = SimpleNamespace(last_successful_update=last_successful_update)
    status = SimpleNamespace(transactions=transactions)
    return SimpleNamespace(status=status)


def _add_connection(user_id, **overrides):
    defaults = dict(
        user_id=user_id,
        encrypted_access_token=encrypt_password("access-sandbox-test"),
        plaid_item_id="item-1",
        plaid_account_id="acct-1",
        institution_name="Test Bank",
        account_name="Checking",
        account_mask="0001",
        account_type="depository",
        account_subtype="checking",
        is_active=True,
    )
    defaults.update(overrides)
    conn = PlaidConnection(**defaults)
    db.session.add(conn)
    db.session.commit()
    return conn


# ── Freshness helpers ────────────────────────────────────────────────────────


def test_transactions_freshness_reads_top_level_item_get_status():
    stale_nested = SimpleNamespace(
        status=SimpleNamespace(
            transactions=SimpleNamespace(
                last_successful_update="2026-01-01T00:00:00Z"
            )
        )
    )
    response = SimpleNamespace(
        status=SimpleNamespace(
            transactions=SimpleNamespace(
                last_successful_update="2026-01-02T00:00:00Z"
            )
        ),
        item=stale_nested,
    )

    assert (
        plaid_service._transactions_last_successful_update(response)
        == "2026-01-02T00:00:00Z"
    )


def test_transactions_freshness_keeps_legacy_nested_fallback():
    response = {
        "item": {
            "status": {
                "transactions": {
                    "last_successful_update": "2026-01-03T00:00:00Z"
                }
            }
        }
    }

    assert (
        plaid_service._transactions_last_successful_update(response)
        == "2026-01-03T00:00:00Z"
    )


# ── Configuration ────────────────────────────────────────────────────────────


class TestPlaidConfigured:
    def test_not_configured_when_missing_values(self, flask_app):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
            assert plaid_service.plaid_is_configured() is False

    def test_configured_when_all_required_values_present(self, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            assert plaid_service.plaid_is_configured() is True
            _deconfigure_plaid(flask_app)

    def test_balance_product_filtered_from_link_products(self, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app, PLAID_PRODUCTS="auth,balance,transactions")
            products = plaid_service.get_configured_products()
            assert "balance" not in products
            assert "auth" in products
            _deconfigure_plaid(flask_app)


# ── Settings page status ─────────────────────────────────────────────────────


class TestSettingsPlaidStatus:
    def test_status_not_configured(self, auth_client, flask_app):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
        resp = auth_client.get("/api/v1/plaid/status")
        assert resp.status_code == 200
        body = resp.get_json()["data"]
        assert body["configured"] is False
        assert body["connected"] is False

    def test_status_configured_not_connected(self, auth_client, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        resp = auth_client.get("/api/v1/plaid/status")
        body = resp.get_json()["data"]
        assert body["configured"] is True
        assert body["connected"] is False
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_link_token_blocked_when_not_configured(self, auth_client, flask_app):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
        resp = auth_client.post("/api/v1/plaid/link-token")
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["code"] == "plaid_not_configured"


# ── Link token creation request shape ──────────────────────────────────────


class TestLinkTokenRequest:
    """Verify the LinkTokenCreateRequest passed to the Plaid SDK."""

    def _captured_request(self, mock_client):
        # ``link_token_create`` is called with a single positional arg —
        # the LinkTokenCreateRequest model. We need its dict form to assert
        # against, since redirect_uri is set via **kwargs into the model.
        assert mock_client.return_value.link_token_create.called
        args, _ = mock_client.return_value.link_token_create.call_args
        req = args[0]
        # Plaid SDK request models behave like dicts.
        try:
            return req.to_dict()
        except Exception:
            return dict(req)

    def test_includes_redirect_uri_when_configured(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(
                flask_app,
                PLAID_REDIRECT_URI="https://app.example.com/settings?plaid_oauth_return=1",
            )
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.link_token_create.return_value = (
                    SimpleNamespace(link_token="link-sandbox-xyz")
                )
                token = plaid_service.create_link_token_for_user(user)
            assert token == "link-sandbox-xyz"
            req = self._captured_request(mock_client)
            # Plaid rejects redirect_uri values containing a query string, so
            # the service must strip it before calling /link/token/create.
            assert req.get("redirect_uri") == "https://app.example.com/settings"
            _deconfigure_plaid(flask_app)

    def test_omits_redirect_uri_when_not_configured(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app, PLAID_REDIRECT_URI="")
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.link_token_create.return_value = (
                    SimpleNamespace(link_token="link-sandbox-no-oauth")
                )
                plaid_service.create_link_token_for_user(user)
            req = self._captured_request(mock_client)
            # Either missing entirely, or explicitly empty/None — never a
            # stray value that would force OAuth on a non-OAuth user.
            assert not req.get("redirect_uri")
            _deconfigure_plaid(flask_app)

    def test_balance_product_filtered_from_link_token_request(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app, PLAID_PRODUCTS="auth,balance,transactions")
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.link_token_create.return_value = (
                    SimpleNamespace(link_token="link-x")
                )
                plaid_service.create_link_token_for_user(user)
            req = self._captured_request(mock_client)
            products = req.get("products") or []
            product_values = [
                getattr(p, "value", None) or str(p) for p in products
            ]
            assert "balance" not in product_values
            assert "auth" in product_values

    def test_link_token_endpoint_returns_only_link_token(
        self, auth_client, flask_app
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "_plaid_client") as mock_client:
            mock_client.return_value.link_token_create.return_value = (
                SimpleNamespace(link_token="link-resp")
            )
            resp = auth_client.post("/api/v1/plaid/link-token")
        assert resp.status_code == 200
        data = resp.get_json()["data"]
        assert data == {"link_token": "link-resp"}
        # No access_token / secret keys must leak into the JSON payload.
        for forbidden in ("access_token", "encrypted_access_token", "secret"):
            assert forbidden not in data


# ── Exchange-token auth surface ────────────────────────────────────────────


class TestExchangeTokenAuthSurface:
    def test_exchange_requires_login(self, client):
        resp = client.post(
            "/api/v1/plaid/exchange-token",
            json={"public_token": "x", "metadata": {}},
        )
        # Unauthenticated callers must not reach the handler.
        assert resp.status_code in (401, 403)

    def test_exchange_does_not_accept_user_id_from_client(
        self, auth_client, flask_app, plaid_user
    ):
        # Even if a malicious client passes a user_id, the endpoint must
        # ignore it and act on the authenticated session user only.
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "_plaid_client") as mock_client:
            mock_client.return_value.item_public_token_exchange.return_value = (
                SimpleNamespace(item_id="item-1", access_token="access-leak-test")
            )
            resp = auth_client.post(
                "/api/v1/plaid/exchange-token",
                json={
                    "public_token": "ptok",
                    "user_id": plaid_user,  # must be ignored
                    "metadata": {
                        "institution": {"institution_id": "i", "name": "n"},
                        "accounts": [
                            {
                                "id": "acct-leak",
                                "type": "depository",
                                "subtype": "checking",
                            }
                        ],
                    },
                },
            )
        # Response should be a normal status payload — never echo a token.
        body = resp.get_json() or {}
        flat = repr(body)
        assert "access-leak-test" not in flat
        assert "access_token" not in flat
        assert "encrypted_access_token" not in flat


# ── Settings page renders OAuth-aware Plaid JS ─────────────────────────────


class TestSettingsPageOAuthMarkup:
    """The settings template must include the OAuth resume logic for Plaid."""

    def _settings_html(self, auth_client):
        resp = auth_client.get("/settings")
        assert resp.status_code == 200
        return resp.get_data(as_text=True)

    def test_uses_session_storage_for_oauth_link_token_resume(self, auth_client):
        html = self._settings_html(auth_client)
        # OAuth resume must reuse the original link token from the first launch.
        assert "sessionStorage" in html
        assert "plaid.oauth.link_token" in html
        assert "loadOAuthLinkToken" in html

    def test_renders_oauth_state_id_detection(self, auth_client):
        html = self._settings_html(auth_client)
        assert "oauth_state_id" in html

    def test_renders_received_redirect_uri_for_oauth_resume(self, auth_client):
        html = self._settings_html(auth_client)
        assert "receivedRedirectUri" in html
        assert "window.location.href" in html

    def test_plaid_script_does_not_log_tokens(self, auth_client):
        html = self._settings_html(auth_client)
        # Defensive: no console.log of public_token / access_token anywhere.
        for forbidden in (
            "console.log(public_token",
            "console.log(access_token",
            "console.log(metadata",
        ):
            assert forbidden not in html

    def test_settings_page_renders_with_oauth_return_params(self, auth_client):
        # The exact landing URL Plaid uses after an OAuth bank redirect.
        # Must render with 200 and preserve the query string for the JS.
        resp = auth_client.get("/settings?plaid_oauth_return=1&oauth_state_id=test")
        assert resp.status_code == 200
        # Confirm the route did not redirect or strip the params before the
        # template ran — the JS detection hooks must still be in the HTML.
        html = resp.get_data(as_text=True)
        assert "oauth_state_id" in html
        assert "plaid_oauth_return" in html

    def test_settings_route_does_not_redirect_on_oauth_query(self, auth_client):
        # A GET to /settings with OAuth params must not 30x — that would
        # strip oauth_state_id before window.location.href can capture it.
        resp = auth_client.get(
            "/settings?plaid_oauth_return=1&oauth_state_id=abc",
            follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_resume_oauth_does_not_create_a_new_link_token(self, auth_client):
        html = self._settings_html(auth_client)
        # Pull just the resumeOAuth function body and make sure it does not
        # call the link-token endpoint. The OAuth resume MUST reuse the
        # link_token stored before the bank redirect.
        marker = "function resumeOAuth"
        idx = html.find(marker)
        assert idx != -1, "resumeOAuth function not found in settings template"
        # End at the next top-level function definition.
        end = html.find("function removeConnection", idx)
        assert end != -1
        body = html[idx:end]
        assert "/api/v1/plaid/link-token" not in body
        # Confirm receivedRedirectUri is still wired up to window.location.href.
        assert "receivedRedirectUri" in body
        assert "window.location.href" in body

    def test_start_link_stores_link_token_in_session_storage(self, auth_client):
        html = self._settings_html(auth_client)
        marker = "function startLink"
        idx = html.find(marker)
        assert idx != -1
        end = html.find("function resumeOAuth", idx)
        assert end != -1
        body = html[idx:end]
        # The first launch must persist the link_token before opening Link,
        # otherwise OAuth resume has nothing to reuse.
        assert "storeOAuthLinkToken" in body

    def test_url_cleanup_is_deferred_until_exchange_or_exit(self, auth_client):
        html = self._settings_html(auth_client)
        # The cleanup function is allowed to exist, but resumeOAuth itself
        # must NOT call it inline after handler.open(); the only legitimate
        # callers are exchangePublicToken (success) and the onExit handler.
        resume_start = html.find("function resumeOAuth")
        resume_end = html.find("function removeConnection", resume_start)
        assert resume_start != -1 and resume_end != -1
        resume_body = html[resume_start:resume_end]
        # Allow cleanupOAuthUrl in the no-link-token early-return branch,
        # but make sure it does NOT appear after handler.open() in the
        # normal-resume path.
        open_idx = resume_body.find("handler.open()")
        assert open_idx != -1
        after_open = resume_body[open_idx:]
        assert "cleanupOAuthUrl" not in after_open, (
            "cleanupOAuthUrl must not run synchronously after handler.open(); "
            "defer it to onSuccess or onExit so Plaid Link is not racing the URL."
        )

    def test_resume_in_progress_guard_present(self, auth_client):
        html = self._settings_html(auth_client)
        # Spec marker — guard exists to prevent duplicate Plaid.create() calls.
        assert "pycashflow_plaid_oauth_resume_in_progress" in html

    def test_completing_plaid_connection_message_present(self, auth_client):
        html = self._settings_html(auth_client)
        # User-facing resume status.
        assert "Completing Plaid connection" in html

    def test_session_expired_message_present(self, auth_client):
        html = self._settings_html(auth_client)
        assert "Plaid connection session expired" in html

    def test_on_exit_reports_diagnostics_to_server(self, auth_client):
        html = self._settings_html(auth_client)
        # Plaid Link surfaces OAuth handoff failures only client-side. The
        # template must forward whitelisted onExit diagnostics so the server
        # log captures them.
        assert "/api/v1/plaid/link-exit" in html
        assert "reportLinkExit" in html
        assert "display_message" in html
        # User-facing message stays generic; detailed error fields go only
        # to the server log.
        assert "Plaid Link did not complete. Please try again." in html
        assert "formatLinkExitMessage" not in html


# ── Link exit diagnostics endpoint ─────────────────────────────────────────


class TestLinkExitDiagnostics:
    def test_endpoint_requires_login(self, client):
        resp = client.post("/api/v1/plaid/link-exit", json={})
        assert resp.status_code in (401, 403)

    def test_endpoint_logs_whitelisted_fields(self, auth_client, flask_app, caplog):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        import logging as _logging
        caplog.set_level(_logging.WARNING, logger="app.plaid_service")
        resp = auth_client.post(
            "/api/v1/plaid/link-exit",
            json={
                "error": {
                    "error_type": "INVALID_FIELD",
                    "error_code": "INVALID_FIELD",
                    "error_message": "redirect_uri must be registered",
                    "display_message": "Please contact support",
                },
                "metadata": {
                    "status": "requires_credentials",
                    "link_session_id": "ls-1",
                    "request_id": "rq-1",
                    "institution_name": "Bank of America",
                },
            },
        )
        assert resp.status_code == 204
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "INVALID_FIELD" in text
        assert "redirect_uri must be registered" in text
        assert "Bank of America" in text
        # Must not log unexpected attacker-supplied keys.
        assert "encrypted_access_token" not in text
        assert "access_token" not in text

    def test_endpoint_scrubs_control_chars_to_prevent_log_injection(
        self, auth_client, flask_app, caplog
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        import logging as _logging
        caplog.set_level(_logging.WARNING, logger="app.plaid_service")
        resp = auth_client.post(
            "/api/v1/plaid/link-exit",
            json={
                "error": {
                    "error_message": "real msg\nFORGED line",
                    "error_code": "CODE\r\nINJECT",
                },
                "metadata": {
                    "institution_name": "Bank\x00null\x1b[31m",
                },
            },
        )
        assert resp.status_code == 204
        # Every emitted log record must be a single line — the attacker's
        # CR/LF/NUL must not appear in the message body.
        for record in caplog.records:
            msg = record.getMessage()
            assert "\n" not in msg
            assert "\r" not in msg
            assert "\x00" not in msg
            assert "\x1b" not in msg

    def test_endpoint_ignores_non_whitelisted_fields(
        self, auth_client, flask_app, caplog
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        import logging as _logging
        caplog.set_level(_logging.WARNING, logger="app.plaid_service")
        resp = auth_client.post(
            "/api/v1/plaid/link-exit",
            json={
                "error": {
                    "error_type": "ITEM_ERROR",
                    "secret_exfil": "should-not-appear",
                    "access_token": "should-not-appear-either",
                },
                "metadata": {
                    "status": "choose_device",
                    "credit_card_number": "4111111111111111",
                },
            },
        )
        assert resp.status_code == 204
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "ITEM_ERROR" in text
        assert "choose_device" in text
        assert "should-not-appear" not in text
        assert "4111111111111111" not in text


# ── Exchange token ──────────────────────────────────────────────────────────


class TestExchangePublicToken:
    def _mock_exchange(self, item_id="item-x", access_token="access-x"):
        return SimpleNamespace(item_id=item_id, access_token=access_token)

    def test_stores_minimal_metadata_and_encrypts_token(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "ins_1", "name": "First Bank"},
                "accounts": [
                    {
                        "id": "acct-checking-1",
                        "name": "Primary Checking",
                        "mask": "1234",
                        "type": "depository",
                        "subtype": "checking",
                        "iso_currency_code": "USD",
                    }
                ],
            }
            with patch.object(
                plaid_service, "_plaid_client"
            ) as mock_client:
                mock_client.return_value.item_public_token_exchange.return_value = (
                    self._mock_exchange(item_id="item-abc", access_token="access-secret")
                )
                conn = plaid_service.exchange_public_token_for_user(
                    user, "public-token-123", metadata
                )

            assert conn.user_id == user.id
            assert conn.plaid_item_id == "item-abc"
            assert conn.plaid_account_id == "acct-checking-1"
            assert conn.institution_name == "First Bank"
            assert conn.account_mask == "1234"
            # Ensure token is encrypted, not plaintext.
            assert conn.encrypted_access_token != "access-secret"
            # No "balance"/queried balance field exists on this model.
            for forbidden in ("balance", "available_balance", "current_balance",
                              "raw_response", "transactions"):
                assert not hasattr(conn, forbidden), (
                    f"PlaidConnection must not store {forbidden!r}"
                )
            _deconfigure_plaid(flask_app)

    def test_rejects_when_already_connected(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "ins_1", "name": "First"},
                "accounts": [
                    {"id": "acct-2", "type": "depository", "subtype": "checking"}
                ],
            }
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.item_public_token_exchange.return_value = (
                    self._mock_exchange()
                )
                with pytest.raises(plaid_service.PlaidServiceError) as ei:
                    plaid_service.exchange_public_token_for_user(
                        user, "ptok", metadata
                    )
                assert ei.value.code == "plaid_already_connected"
            _deconfigure_plaid(flask_app)

    def test_rejects_unsupported_account_type(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "i", "name": "n"},
                "accounts": [
                    {"id": "acct-c", "type": "credit", "subtype": "credit card"}
                ],
            }
            with pytest.raises(plaid_service.PlaidServiceError) as ei:
                plaid_service.exchange_public_token_for_user(user, "ptok", metadata)
            assert ei.value.code in (
                "plaid_unsupported_account_type",
                "plaid_unsupported_account_subtype",
            )
            _deconfigure_plaid(flask_app)

    def test_rejects_multiple_accounts(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "i", "name": "n"},
                "accounts": [
                    {"id": "a", "type": "depository", "subtype": "checking"},
                    {"id": "b", "type": "depository", "subtype": "checking"},
                ],
            }
            with pytest.raises(plaid_service.PlaidServiceError) as ei:
                plaid_service.exchange_public_token_for_user(user, "ptok", metadata)
            assert ei.value.code == "plaid_select_one_account"
            _deconfigure_plaid(flask_app)

    def test_rejects_when_account_id_missing(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "i", "name": "n"},
                "accounts": [
                    {"type": "depository", "subtype": "checking", "name": "Checking"}
                ],
            }
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                with pytest.raises(plaid_service.PlaidServiceError) as ei:
                    plaid_service.exchange_public_token_for_user(user, "ptok", metadata)
                assert ei.value.code == "plaid_missing_account_id"
                assert not mock_client.return_value.item_public_token_exchange.called
            assert PlaidConnection.query.filter_by(user_id=user.id).count() == 0
            _deconfigure_plaid(flask_app)

    def test_rejects_when_account_id_blank(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            metadata = {
                "institution": {"institution_id": "i", "name": "n"},
                "accounts": [
                    {"id": "   ", "type": "depository", "subtype": "checking"}
                ],
            }
            with pytest.raises(plaid_service.PlaidServiceError) as ei:
                plaid_service.exchange_public_token_for_user(user, "ptok", metadata)
            assert ei.value.code == "plaid_missing_account_id"
            assert PlaidConnection.query.filter_by(user_id=user.id).count() == 0
            _deconfigure_plaid(flask_app)


# ── Remove connection ───────────────────────────────────────────────────────


class TestRemoveConnection:
    def test_calls_item_remove_and_deletes_local_record(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                plaid_service.remove_plaid_connection_for_user(user)
                assert mock_client.return_value.item_remove.called
            assert PlaidConnection.query.filter_by(user_id=user.id).count() == 0
            _deconfigure_plaid(flask_app)

    def test_removes_local_even_if_item_remove_fails(self, flask_app, plaid_user):
        from plaid.exceptions import ApiException

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.item_remove.side_effect = ApiException()
                plaid_service.remove_plaid_connection_for_user(user)
            assert PlaidConnection.query.filter_by(user_id=user.id).count() == 0
            _deconfigure_plaid(flask_app)

    def test_balance_rows_remain_after_removal(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            db.session.add(Balance(user_id=plaid_user, amount=1234.0, date=date.today()))
            db.session.commit()
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connection_for_user(user)
            assert Balance.query.filter_by(user_id=plaid_user).count() == 1
            _deconfigure_plaid(flask_app)


class TestRemoveConnectionsBulk:
    def test_calls_item_remove_for_every_user(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            other = User(
                email=f"plaid-bulk-{datetime.utcnow().timestamp()}@test.local",
                password=generate_password_hash("pw", method="scrypt"),
                name="Other",
                admin=True,
                is_active=True,
            )
            db.session.add(other)
            db.session.commit()
            other_id = other.id
            _add_connection(plaid_user)
            _add_connection(
                other_id,
                encrypted_access_token=encrypt_password("access-sandbox-other"),
                plaid_item_id="item-other",
            )

            with patch.object(plaid_service, "_plaid_client") as mock_client:
                removed = plaid_service.remove_plaid_connections_for_user_ids(
                    [plaid_user, other_id], commit=True
                )
                assert removed == 2
                assert mock_client.return_value.item_remove.call_count == 2

            assert PlaidConnection.query.filter_by(user_id=plaid_user).count() == 0
            assert PlaidConnection.query.filter_by(user_id=other_id).count() == 0

            User.query.filter_by(id=other_id).delete()
            db.session.commit()
            _deconfigure_plaid(flask_app)

    def test_noop_when_no_user_ids(self, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                removed = plaid_service.remove_plaid_connections_for_user_ids([])
                assert removed == 0
                assert not mock_client.return_value.item_remove.called
            _deconfigure_plaid(flask_app)

    def test_swallows_item_remove_failures(self, flask_app, plaid_user):
        from plaid.exceptions import ApiException

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.item_remove.side_effect = ApiException()
                removed = plaid_service.remove_plaid_connections_for_user_ids(
                    [plaid_user], commit=True
                )
            assert removed == 1
            assert PlaidConnection.query.filter_by(user_id=plaid_user).count() == 0
            _deconfigure_plaid(flask_app)


class TestRealtimeCooldownSurvivesReconnect:
    """Deleting and re-adding a Plaid account must not reset the 24-hour
    /accounts/balance/get rate limit."""

    def _mock_exchange(self, item_id="item-x", access_token="access-x"):
        return SimpleNamespace(item_id=item_id, access_token=access_token)

    def test_remove_preserves_cooldown_on_user(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            cooldown_at = datetime.utcnow() - timedelta(hours=1)
            _add_connection(plaid_user, last_realtime_balance_at=cooldown_at)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connection_for_user(user)
            db.session.refresh(user)
            assert user.last_plaid_realtime_balance_at == cooldown_at
            _deconfigure_plaid(flask_app)

    def test_remove_bulk_preserves_cooldown_on_user(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            cooldown_at = datetime.utcnow() - timedelta(hours=2)
            _add_connection(plaid_user, last_realtime_balance_at=cooldown_at)
            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connections_for_user_ids(
                    [plaid_user], commit=True
                )
            user = User.query.get(plaid_user)
            assert user.last_plaid_realtime_balance_at == cooldown_at
            _deconfigure_plaid(flask_app)

    def test_remove_bulk_keeps_newest_cooldown_across_multiple_connections(
        self, flask_app, plaid_user
    ):
        """Multiple PlaidConnection rows for one user (e.g. an inactive
        leftover + an active one) must not let bulk delete move the user's
        cooldown backward — keep the newest timestamp regardless of row
        iteration order."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            older = datetime.utcnow() - timedelta(hours=20)
            newer = datetime.utcnow() - timedelta(hours=1)
            _add_connection(
                plaid_user,
                plaid_item_id="item-old",
                plaid_account_id="acct-old",
                is_active=False,
                last_realtime_balance_at=older,
            )
            _add_connection(
                plaid_user,
                plaid_item_id="item-new",
                plaid_account_id="acct-new",
                last_realtime_balance_at=newer,
            )
            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connections_for_user_ids(
                    [plaid_user], commit=True
                )
            user = User.query.get(plaid_user)
            assert user.last_plaid_realtime_balance_at == newer
            _deconfigure_plaid(flask_app)

    def test_remove_without_prior_realtime_call_leaves_user_null(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connection_for_user(user)
            db.session.refresh(user)
            assert user.last_plaid_realtime_balance_at is None
            _deconfigure_plaid(flask_app)

    def test_reconnect_restores_cooldown_on_new_connection(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            cooldown_at = datetime.utcnow() - timedelta(hours=1)
            _add_connection(plaid_user, last_realtime_balance_at=cooldown_at)
            user = User.query.get(plaid_user)

            with patch.object(plaid_service, "_plaid_client"):
                plaid_service.remove_plaid_connection_for_user(user)

            metadata = {
                "institution": {"institution_id": "ins_9", "name": "Re-Add Bank"},
                "accounts": [
                    {
                        "id": "acct-reconnect-1",
                        "name": "Checking",
                        "mask": "9999",
                        "type": "depository",
                        "subtype": "checking",
                        "iso_currency_code": "USD",
                    }
                ],
            }
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.item_public_token_exchange.return_value = (
                    self._mock_exchange(
                        item_id="item-reconnect", access_token="access-reconnect"
                    )
                )
                new_conn = plaid_service.exchange_public_token_for_user(
                    user, "public-token-reconnect", metadata
                )

            assert new_conn.last_realtime_balance_at == cooldown_at
            _deconfigure_plaid(flask_app)


# ── Balance update ──────────────────────────────────────────────────────────


class TestUpdateBalance:
    def test_noop_when_not_configured(self, flask_app, plaid_user):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "not_configured"

    def test_noop_when_no_active_connection(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "no_connection"
            _deconfigure_plaid(flask_app)

    def test_uses_available_balance_when_present(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=500.25, current=600.00)
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "ok"
            assert result["source"] == "plaid_available_balance"
            today_row = (
                Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            )
            assert today_row is not None
            assert float(today_row.amount) == pytest.approx(500.25)
            _deconfigure_plaid(flask_app)

    def test_falls_back_to_current_when_available_is_none(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=None, current=800.10)
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["source"] == "plaid_current_balance_fallback"
            today_row = (
                Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            )
            assert float(today_row.amount) == pytest.approx(800.10)
            _deconfigure_plaid(flask_app)

    def test_does_not_overwrite_when_both_balances_are_none(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            existing = Balance(user_id=plaid_user, amount=999.99, date=date.today())
            db.session.add(existing)
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=None, current=None)
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            today_row = (
                Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            )
            assert float(today_row.amount) == pytest.approx(999.99)

            conn = (
                PlaidConnection.query.filter_by(user_id=plaid_user, is_active=True).first()
            )
            assert conn.last_sync_status == "no_balance_value"
            assert conn.last_sync_error  # non-empty, non-sensitive
            _deconfigure_plaid(flask_app)

    def test_updates_existing_row_instead_of_creating_duplicate(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            db.session.add(Balance(user_id=plaid_user, amount=100.0, date=date.today()))
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=250.0, current=300.0)
                )
                plaid_service.update_plaid_balance_for_user(user)

            rows = Balance.query.filter_by(user_id=plaid_user, date=date.today()).all()
            assert len(rows) == 1
            assert float(rows[0].amount) == pytest.approx(250.0)
            _deconfigure_plaid(flask_app)

    def test_creates_today_row_when_missing(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=42.0, current=None)
                )
                plaid_service.update_plaid_balance_for_user(user)

            row = (
                Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            )
            assert row is not None
            assert float(row.amount) == pytest.approx(42.0)
            _deconfigure_plaid(flask_app)

    def test_safe_wrapper_swallows_unexpected_errors(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.side_effect = RuntimeError(
                    "boom"
                )
                # Must not raise.
                plaid_service.safe_update_plaid_balance_for_user(user)
            _deconfigure_plaid(flask_app)

    def test_skips_when_cache_older_than_last_realtime(self, flask_app, plaid_user):
        """Plaid's cached balance is stale relative to our live one — don't overwrite.

        Belt-and-suspenders alongside the 5-minute time guard: when Plaid
        explicitly tells us ``balances.last_updated_datetime`` is older than
        our last real-time refresh, we know /accounts/get is returning
        stale data and the live row must stay put — even if the time guard
        has already elapsed.
        """
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            # Pretend the real-time refresh ran ~10 minutes ago — past the
            # 5-minute time guard, so we rely on the cache-timestamp check.
            conn.last_realtime_balance_at = datetime.utcnow() - timedelta(minutes=10)
            db.session.commit()
            db.session.add(
                Balance(user_id=plaid_user, amount=1234.56, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                # Plaid's cache was last refreshed BEFORE our real-time call.
                stale_cache_ts = (
                    datetime.utcnow() - timedelta(hours=2)
                ).replace(tzinfo=timezone.utc).isoformat()
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response(
                        "acct-1",
                        available=100.0,
                        current=100.0,
                        last_updated_datetime=stale_cache_ts,
                    )
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "cache_older_than_realtime"
            # Live value is untouched.
            row = Balance.query.filter_by(
                user_id=plaid_user, date=date.today()
            ).first()
            assert float(row.amount) == pytest.approx(1234.56)
            _deconfigure_plaid(flask_app)

    def test_proceeds_when_cache_newer_than_last_realtime(self, flask_app, plaid_user):
        """If Plaid's cache caught up after our real-time refresh, sync as normal."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            conn.last_realtime_balance_at = datetime.utcnow() - timedelta(hours=2)
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                fresh_cache_ts = (
                    datetime.utcnow() - timedelta(minutes=5)
                ).replace(tzinfo=timezone.utc).isoformat()
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response(
                        "acct-1",
                        available=200.0,
                        current=250.0,
                        last_updated_datetime=fresh_cache_ts,
                    )
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "ok"
            row = Balance.query.filter_by(
                user_id=plaid_user, date=date.today()
            ).first()
            assert float(row.amount) == pytest.approx(200.0)
            _deconfigure_plaid(flask_app)

    def test_skips_after_recent_realtime_refresh(self, flask_app, plaid_user):
        """A just-written real-time balance must not be clobbered by the cached sync.

        Plaid does not guarantee /accounts/get reflects a fresh
        /accounts/balance/get immediately, so the dashboard auto-sync must
        skip while the realtime value is still within the protection window.
        """
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            conn.last_realtime_balance_at = datetime.utcnow()
            db.session.commit()
            db.session.add(
                Balance(user_id=plaid_user, amount=1234.56, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                # Simulate a stale cached value that would clobber the live one.
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=100.0, current=100.0)
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "realtime_recent"
            # Live value is untouched.
            row = Balance.query.filter_by(
                user_id=plaid_user, date=date.today()
            ).first()
            assert float(row.amount) == pytest.approx(1234.56)
            _deconfigure_plaid(flask_app)


# ── Email balance vs Plaid cached sync precedence ───────────────────────────


def _add_email_config(user_id: int, balance_email_datetime=None, **overrides):
    """Insert an Email config row for *user_id* with optional timestamp."""
    defaults = dict(
        user_id=user_id,
        email="bank-alerts@example.com",
        password=encrypt_password("imap-pw"),
        server="imap.example.com",
        subjectstr="Daily balance",
        startstr="$",
        endstr=" USD",
        balance_email_datetime=balance_email_datetime,
    )
    defaults.update(overrides)
    cfg = Email(**defaults)
    db.session.add(cfg)
    db.session.commit()
    return cfg


class TestEmailBalanceVsPlaidCachedSync:
    """The dashboard /accounts/get sync must not overwrite a newer email-derived
    balance with stale Plaid cached data.
    """

    def test_skips_when_email_newer_than_plaid_cache(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(minutes=5)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=1234.56, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    stale_cache_ts = (
                        datetime.utcnow() - timedelta(hours=2)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=10.0,
                            current=10.0,
                            last_updated_datetime=stale_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_email_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(1234.56)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_skips_when_plaid_cache_freshness_missing(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(minutes=10)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=2222.22, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=50.0,
                            current=50.0,
                            last_updated_datetime=None,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_email_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(2222.22)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_updates_when_plaid_cache_newer_than_email(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(hours=3)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=100.0, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_cache_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=777.0,
                            current=800.0,
                            last_updated_datetime=fresh_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(777.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_transactions_freshness_can_allow_update_when_balance_timestamp_is_old(
        self, flask_app, plaid_user
    ):
        """Prefer /item/get Transactions freshness over account balance freshness."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(hours=1)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=100.0, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    old_balance_ts = (
                        datetime.utcnow() - timedelta(hours=3)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    fresh_transactions_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=888.0,
                            current=900.0,
                            last_updated_datetime=old_balance_ts,
                        )
                    )
                    mock_client.return_value.item_get.return_value = _make_item_response(
                        last_successful_update=fresh_transactions_ts
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)

                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(888.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_transactions_freshness_wins_over_newer_balance_timestamp(
        self, flask_app, plaid_user
    ):
        """A stale Transactions timestamp blocks even with fresher balance timestamp."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(hours=1)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=1234.56, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_balance_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    stale_transactions_ts = (
                        datetime.utcnow() - timedelta(hours=3)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=10.0,
                            current=10.0,
                            last_updated_datetime=fresh_balance_ts,
                        )
                    )
                    mock_client.return_value.item_get.return_value = _make_item_response(
                        last_successful_update=stale_transactions_ts
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)

                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_email_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(1234.56)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_updates_when_old_email_predates_fresh_plaid_cache(
        self, flask_app, plaid_user
    ):
        """An old email balance must not block a Plaid cached value whose
        freshness is newer than the email — the comparison is purely
        timestamp-vs-timestamp.
        """
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(days=3)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_cache_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=321.0,
                            current=400.0,
                            last_updated_datetime=fresh_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(321.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_updates_when_email_config_has_no_balance_timestamp(
        self, flask_app, plaid_user
    ):
        """An Email config without a recorded balance timestamp is a no-op
        for the skip rule — the normal Plaid sync still proceeds."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            _add_email_config(plaid_user, balance_email_datetime=None)

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1", available=55.5, current=60.0
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(55.5)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_uses_newest_timestamp_across_multiple_email_configs(
        self, flask_app, plaid_user
    ):
        """If a user has more than one Email row, the newest balance timestamp
        wins — a stale one must not be picked over a fresher one.
        """
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            old_ts = datetime.utcnow() - timedelta(days=2)
            fresh_ts = datetime.utcnow() - timedelta(minutes=2)
            _add_email_config(plaid_user, balance_email_datetime=old_ts)
            _add_email_config(
                plaid_user,
                balance_email_datetime=fresh_ts,
                email="bank-alerts-2@example.com",
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=4242.42, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    stale_cache_ts = (
                        datetime.utcnow() - timedelta(hours=1)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=1.0,
                            current=1.0,
                            last_updated_datetime=stale_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_email_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(4242.42)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_realtime_refresh_not_blocked_by_email_skip_rule(
        self, flask_app, plaid_user
    ):
        """Manual /accounts/balance/get is user-triggered and must remain
        free to update today's balance even when an email balance is newer.
        """
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            email_ts = datetime.utcnow() - timedelta(minutes=1)
            _add_email_config(plaid_user, balance_email_datetime=email_ts)
            db.session.add(
                Balance(user_id=plaid_user, amount=10.0, date=date.today())
            )
            db.session.commit()

            user = User.query.get(plaid_user)
            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_balance_get.return_value = (
                        _make_balances_response(
                            "acct-1", available=999.0, current=1000.0
                        )
                    )
                    result = plaid_service.realtime_update_plaid_balance_for_user(
                        user
                    )
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(999.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_dashboard_still_loads_when_email_skip_fires(
        self, auth_client, flask_app
    ):
        """The dashboard must continue to render and use the existing balance
        row when the Plaid cached sync is skipped because the email balance
        is newer.
        """
        from conftest import _ADMIN_USER_ID

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(_ADMIN_USER_ID)
            email_ts = datetime.utcnow() - timedelta(minutes=3)
            _add_email_config(_ADMIN_USER_ID, balance_email_datetime=email_ts)
            # Replace the seeded admin balance with a known email-derived value.
            Balance.query.filter_by(
                user_id=_ADMIN_USER_ID, date=date.today()
            ).delete()
            db.session.add(
                Balance(user_id=_ADMIN_USER_ID, amount=8888.88, date=date.today())
            )
            db.session.commit()
        try:
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                stale_cache_ts = (
                    datetime.utcnow() - timedelta(hours=2)
                ).replace(tzinfo=timezone.utc).isoformat()
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response(
                        "acct-1",
                        available=1.0,
                        current=1.0,
                        last_updated_datetime=stale_cache_ts,
                    )
                )
                resp = auth_client.get("/")
            assert resp.status_code == 200
            with flask_app.app_context():
                row = Balance.query.filter_by(
                    user_id=_ADMIN_USER_ID, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(8888.88)
        finally:
            with flask_app.app_context():
                Email.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                PlaidConnection.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                Balance.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                # Re-seed the original admin balance so other tests using the
                # same fixture see the expected starting state.
                db.session.add(
                    Balance(
                        user_id=_ADMIN_USER_ID,
                        amount="5000.00",
                        date=date.today(),
                    )
                )
                db.session.commit()
                _deconfigure_plaid(flask_app)


# ── Manual balance entry vs Plaid cached sync precedence ────────────────────


class TestManualBalanceVsPlaidCachedSync:
    """The dashboard /accounts/get sync must not overwrite a newer manually
    entered balance with stale Plaid cached data. This sits alongside the
    existing email and real-time refresh staleness checks.
    """

    def test_skips_when_manual_entry_newer_than_plaid_cache(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(minutes=5)
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=1234.56, date=date.today())
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    stale_cache_ts = (
                        datetime.utcnow() - timedelta(hours=2)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=10.0,
                            current=10.0,
                            last_updated_datetime=stale_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_manual_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(1234.56)
            finally:
                _deconfigure_plaid(flask_app)

    def test_skips_when_manual_exists_and_cache_freshness_missing(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(minutes=10)
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=2222.22, date=date.today())
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=50.0,
                            current=50.0,
                            last_updated_datetime=None,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_manual_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(2222.22)
            finally:
                _deconfigure_plaid(flask_app)

    def test_updates_when_plaid_cache_newer_than_manual_entry(
        self, flask_app, plaid_user
    ):
        """Cache freshness newer than the manual entry must not be blocked by
        the manual timestamp (email/real-time checks also pass here)."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(hours=3)
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=100.0, date=date.today())
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_cache_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=777.0,
                            current=800.0,
                            last_updated_datetime=fresh_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(777.0)
            finally:
                _deconfigure_plaid(flask_app)

    def test_old_manual_entry_does_not_block_fresh_plaid_cache(
        self, flask_app, plaid_user
    ):
        """An old manual entry must not block a Plaid cached value whose
        freshness is newer — the comparison is purely timestamp-vs-timestamp,
        never the balance row date or today's calendar day."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(days=3)
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_cache_ts = (
                        datetime.utcnow() - timedelta(minutes=5)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=321.0,
                            current=400.0,
                            last_updated_datetime=fresh_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(321.0)
            finally:
                _deconfigure_plaid(flask_app)

    def test_proceeds_only_when_manual_email_and_realtime_all_allow(
        self, flask_app, plaid_user
    ):
        """Cached update proceeds when the cache is fresher than every
        protected timestamp (manual + email + real-time)."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            conn.last_realtime_balance_at = datetime.utcnow() - timedelta(hours=6)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(hours=4)
            )
            _add_email_config(
                plaid_user,
                balance_email_datetime=datetime.utcnow() - timedelta(hours=5),
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    fresh_cache_ts = (
                        datetime.utcnow() - timedelta(minutes=1)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=555.0,
                            current=600.0,
                            last_updated_datetime=fresh_cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(555.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_manual_blocks_even_when_email_and_realtime_would_allow(
        self, flask_app, plaid_user
    ):
        """A newer manual entry alone is enough to skip, even if the email and
        real-time checks would individually permit the update."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            # Real-time well in the past (past the 5-minute window and older
            # than the cache), email old too — only the manual entry is fresh.
            conn.last_realtime_balance_at = datetime.utcnow() - timedelta(hours=6)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(minutes=1)
            )
            _add_email_config(
                plaid_user,
                balance_email_datetime=datetime.utcnow() - timedelta(hours=5),
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=4321.0, date=date.today())
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    cache_ts = (
                        datetime.utcnow() - timedelta(minutes=30)
                    ).replace(tzinfo=timezone.utc).isoformat()
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1",
                            available=9.0,
                            current=9.0,
                            last_updated_datetime=cache_ts,
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "skipped"
                assert result["reason"] == "skipped_cached_plaid_update_manual_newer"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(4321.0)
            finally:
                Email.query.filter_by(user_id=plaid_user).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_realtime_refresh_not_blocked_by_manual_skip_rule(
        self, flask_app, plaid_user
    ):
        """Manual /accounts/balance/get is user-triggered and must remain free
        to update today's balance even when a manual entry is newer."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(minutes=1)
            )
            db.session.add(
                Balance(user_id=plaid_user, amount=10.0, date=date.today())
            )
            db.session.commit()

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_balance_get.return_value = (
                        _make_balances_response(
                            "acct-1", available=999.0, current=1000.0
                        )
                    )
                    result = plaid_service.realtime_update_plaid_balance_for_user(
                        user
                    )
                assert result["status"] == "ok"
                row = Balance.query.filter_by(
                    user_id=plaid_user, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(999.0)
            finally:
                _deconfigure_plaid(flask_app)

    def test_cached_sync_does_not_set_manual_timestamp(
        self, flask_app, plaid_user
    ):
        """A cached /accounts/get update must never stamp the manual entry
        timestamp — only genuine manual entries do."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            assert user.last_manual_balance_entry_at is None

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_get.return_value = (
                        _make_balances_response(
                            "acct-1", available=42.0, current=42.0
                        )
                    )
                    result = plaid_service.update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                refreshed = User.query.get(plaid_user)
                assert refreshed.last_manual_balance_entry_at is None
            finally:
                _deconfigure_plaid(flask_app)

    def test_realtime_refresh_does_not_set_manual_timestamp(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            assert user.last_manual_balance_entry_at is None

            try:
                with patch.object(plaid_service, "_plaid_client") as mock_client:
                    mock_client.return_value.accounts_balance_get.return_value = (
                        _make_balances_response(
                            "acct-1", available=88.0, current=88.0
                        )
                    )
                    result = plaid_service.realtime_update_plaid_balance_for_user(
                        user
                    )
                assert result["status"] == "ok"
                refreshed = User.query.get(plaid_user)
                assert refreshed.last_manual_balance_entry_at is None
            finally:
                _deconfigure_plaid(flask_app)

    def test_dashboard_still_loads_when_manual_skip_fires(
        self, auth_client, flask_app
    ):
        """The dashboard must continue to render and use the existing balance
        row when the Plaid cached sync is skipped because a manual entry is
        newer than Plaid's cached freshness."""
        from conftest import _ADMIN_USER_ID

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(_ADMIN_USER_ID)
            user = User.query.get(_ADMIN_USER_ID)
            user.last_manual_balance_entry_at = (
                datetime.utcnow() - timedelta(minutes=3)
            )
            Balance.query.filter_by(
                user_id=_ADMIN_USER_ID, date=date.today()
            ).delete()
            db.session.add(
                Balance(user_id=_ADMIN_USER_ID, amount=8888.88, date=date.today())
            )
            db.session.commit()
        try:
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                stale_cache_ts = (
                    datetime.utcnow() - timedelta(hours=2)
                ).replace(tzinfo=timezone.utc).isoformat()
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response(
                        "acct-1",
                        available=1.0,
                        current=1.0,
                        last_updated_datetime=stale_cache_ts,
                    )
                )
                resp = auth_client.get("/")
            assert resp.status_code == 200
            with flask_app.app_context():
                row = Balance.query.filter_by(
                    user_id=_ADMIN_USER_ID, date=date.today()
                ).first()
                assert float(row.amount) == pytest.approx(8888.88)
        finally:
            with flask_app.app_context():
                PlaidConnection.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                Balance.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                admin = User.query.get(_ADMIN_USER_ID)
                admin.last_manual_balance_entry_at = None
                db.session.add(
                    Balance(
                        user_id=_ADMIN_USER_ID,
                        amount="5000.00",
                        date=date.today(),
                    )
                )
                db.session.commit()
                _deconfigure_plaid(flask_app)


# ── Dashboard integration ───────────────────────────────────────────────────


class TestDashboardIntegration:
    def test_dashboard_page_calls_update(self, auth_client, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "safe_update_plaid_balance_for_user") as mock_upd:
            # main.py imported the symbol directly; patch the imported name too.
            with patch("app.main.safe_update_plaid_balance_for_user") as mock_main_upd:
                resp = auth_client.get("/")
                assert resp.status_code == 200
                assert mock_main_upd.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_api_dashboard_calls_update(self, auth_client, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch("app.api.routes.data.safe_update_plaid_balance_for_user") as mock_upd:
            resp = auth_client.get("/api/v1/dashboard")
            assert resp.status_code == 200
            assert mock_upd.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_dashboard_still_loads_when_plaid_errors(self, auth_client, flask_app):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        # The safe wrapper around update_plaid_balance_for_user must swallow
        # any exception from the inner function so the dashboard still renders.
        with patch.object(plaid_service, "update_plaid_balance_for_user") as mock_inner:
            mock_inner.side_effect = RuntimeError("boom")
            try:
                resp = auth_client.get("/")
            except RuntimeError:
                pytest.fail("Dashboard should not propagate Plaid errors")
            assert resp.status_code == 200
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


# ── Guest write restrictions ────────────────────────────────────────────────


class TestGuestWriteRestrictions:
    """Guest (admin=False) users must not be able to mutate Plaid state."""

    @pytest.fixture()
    def guest_client(self, flask_app):
        with flask_app.app_context():
            owner = User(
                email=f"plaid-owner-{datetime.utcnow().timestamp()}@test.local",
                password=generate_password_hash("pw", method="scrypt"),
                name="Owner",
                admin=True,
                is_account_owner=True,
                is_active=True,
            )
            db.session.add(owner)
            db.session.commit()
            guest = User(
                email=f"plaid-guest-{datetime.utcnow().timestamp()}@test.local",
                password=generate_password_hash("pw", method="scrypt"),
                name="Guest",
                admin=False,
                is_active=True,
                is_account_owner=False,
                owner_user_id=owner.id,
                account_owner_id=owner.id,
            )
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id
            owner_id = owner.id

        c = flask_app.test_client()
        with c.session_transaction() as sess:
            sess["_user_id"] = str(guest_id)
            sess["_fresh"] = True

        yield c

        with flask_app.app_context():
            PlaidConnection.query.filter(
                PlaidConnection.user_id.in_([guest_id, owner_id])
            ).delete(synchronize_session=False)
            User.query.filter(User.id.in_([guest_id, owner_id])).delete(
                synchronize_session=False
            )
            db.session.commit()

    def _csrf_headers(self, client):
        html = client.get("/settings").get_data(as_text=True)
        marker = 'meta name="csrf-token" content="'
        idx = html.find(marker)
        assert idx != -1
        start = idx + len(marker)
        end = html.find('"', start)
        token = html[start:end]
        return {"X-CSRFToken": token}

    def test_exchange_token_forbidden_for_guest(self, flask_app, guest_client):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "_plaid_client") as mock_client:
            resp = guest_client.post(
                "/api/v1/plaid/exchange-token",
                headers=self._csrf_headers(guest_client),
                json={
                    "public_token": "ptok",
                    "metadata": {
                        "institution": {"institution_id": "i", "name": "n"},
                        "accounts": [
                            {"id": "a", "type": "depository", "subtype": "checking"}
                        ],
                    },
                },
            )
            assert resp.status_code == 403
            assert resp.get_json()["code"] == "forbidden"
            assert not mock_client.return_value.item_public_token_exchange.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_remove_forbidden_for_guest(self, flask_app, guest_client):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        resp = guest_client.post("/api/v1/plaid/remove", headers=self._csrf_headers(guest_client))
        assert resp.status_code == 403
        assert resp.get_json()["code"] == "forbidden"
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_remove_delete_forbidden_for_guest(self, flask_app, guest_client):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        resp = guest_client.delete("/api/v1/plaid/remove", headers=self._csrf_headers(guest_client))
        assert resp.status_code == 403
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_update_balance_forbidden_for_guest(self, flask_app, guest_client):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "update_plaid_balance_for_user") as mock_upd:
            resp = guest_client.post("/api/v1/plaid/update-balance", headers=self._csrf_headers(guest_client))
            assert resp.status_code == 403
            assert not mock_upd.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_status_allowed_for_guest(self, flask_app, guest_client):
        """Read-only status endpoint must remain accessible."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
        resp = guest_client.get("/api/v1/plaid/status")
        assert resp.status_code == 200
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


# ── Model invariants ────────────────────────────────────────────────────────


class TestModelInvariants:
    def test_no_transaction_or_raw_payload_columns(self):
        cols = {c.name for c in PlaidConnection.__table__.columns}
        for forbidden in (
            "transactions",
            "raw_response",
            "balance",
            "available_balance",
            "current_balance",
            "routing_number",
            "account_number",
        ):
            assert forbidden not in cols, (
                f"PlaidConnection must not have column {forbidden!r}"
            )

    def test_unique_active_connection_per_user(self, flask_app, plaid_user):
        from sqlalchemy.exc import IntegrityError

        with flask_app.app_context():
            _add_connection(plaid_user)
            db.session.add(
                PlaidConnection(
                    user_id=plaid_user,
                    encrypted_access_token=encrypt_password("y"),
                    plaid_item_id="item-2",
                    plaid_account_id="acct-2",
                    is_active=True,
                )
            )
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()


# ── Real-time balance refresh (/accounts/balance/get) ────────────────────────


class TestRealtimeBalanceRefresh:
    """Service-layer tests for ``realtime_update_plaid_balance_for_user``.

    Covers the 24-hour cooldown, the available/current fallback, today-row
    upsert, and the requirement that no /accounts/get behavior is changed.
    """

    def test_noop_when_not_configured(self, flask_app, plaid_user):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "not_configured"

    def test_noop_when_no_active_connection(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            assert result["reason"] == "no_connection"
            _deconfigure_plaid(flask_app)

    def test_calls_accounts_balance_get_with_account_id_option(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=123.45, current=200.00)
                )
                # The legacy /accounts/get path must not be invoked.
                mock_client.return_value.accounts_get.side_effect = AssertionError(
                    "realtime refresh must not call /accounts/get"
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
                assert result["status"] == "ok"
                assert result["source"] == "plaid_realtime_available_balance"
                assert result["amount"] == pytest.approx(123.45)
                # Plaid SDK was called with the stored plaid_account_id filter.
                args, kwargs = mock_client.return_value.accounts_balance_get.call_args
                req = args[0] if args else kwargs.get("request")
                options = getattr(req, "options", None)
                account_ids = getattr(options, "account_ids", None)
                assert list(account_ids) == ["acct-1"]
            _deconfigure_plaid(flask_app)

    def test_prefers_available_over_current(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=500.25, current=600.00)
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["source"] == "plaid_realtime_available_balance"
            row = Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            assert float(row.amount) == pytest.approx(500.25)
            _deconfigure_plaid(flask_app)

    def test_falls_back_to_current_when_available_is_none(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=None, current=800.10)
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["source"] == "plaid_realtime_current_balance_fallback"
            row = Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            assert float(row.amount) == pytest.approx(800.10)
            _deconfigure_plaid(flask_app)

    def test_does_not_overwrite_when_both_balances_are_none(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            db.session.add(
                Balance(user_id=plaid_user, amount=999.99, date=date.today())
            )
            db.session.commit()
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=None, current=None)
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["status"] == "skipped"
            row = Balance.query.filter_by(user_id=plaid_user, date=date.today()).first()
            assert float(row.amount) == pytest.approx(999.99)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            # Cooldown still consumed because Plaid was called and billed.
            assert conn.last_realtime_balance_at is not None
            assert conn.last_realtime_refresh_status == "no_balance_value"
            _deconfigure_plaid(flask_app)

    def test_updates_existing_today_row_instead_of_creating_duplicate(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            db.session.add(
                Balance(user_id=plaid_user, amount=100.0, date=date.today())
            )
            db.session.commit()
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=250.0, current=300.0)
                )
                plaid_service.realtime_update_plaid_balance_for_user(user)
            rows = Balance.query.filter_by(
                user_id=plaid_user, date=date.today()
            ).all()
            assert len(rows) == 1
            assert float(rows[0].amount) == pytest.approx(250.0)
            _deconfigure_plaid(flask_app)

    def test_creates_today_row_when_missing(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=42.0, current=None)
                )
                plaid_service.realtime_update_plaid_balance_for_user(user)
            row = Balance.query.filter_by(
                user_id=plaid_user, date=date.today()
            ).first()
            assert row is not None
            assert float(row.amount) == pytest.approx(42.0)
            _deconfigure_plaid(flask_app)

    def test_24h_cooldown_blocks_second_call(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=20.0)
                )
                first = plaid_service.realtime_update_plaid_balance_for_user(user)
                second = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert first["status"] == "ok"
            assert second["status"] == "rate_limited"
            assert second["reason"] == "cooldown_active"
            assert second["retry_after_seconds"] > 0
            # Only one paid Plaid call should have been made.
            assert mock_client.return_value.accounts_balance_get.call_count == 1
            _deconfigure_plaid(flask_app)

    def test_cooldown_expires_after_24_hours(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            # Pretend the last refresh was just over 24h ago.
            conn.last_realtime_balance_at = datetime.utcnow() - timedelta(
                hours=24, minutes=1
            )
            db.session.commit()
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=77.0, current=None)
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["status"] == "ok"
            assert mock_client.return_value.accounts_balance_get.call_count == 1
            _deconfigure_plaid(flask_app)

    def test_failed_call_still_consumes_cooldown(self, flask_app, plaid_user):
        """Plaid charges per attempt — failures must consume the 24h window."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.side_effect = (
                    RuntimeError("boom")
                )
                first = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert first["status"] == "error"
            assert first["reason"] == "unexpected_error"
            # Second call within the window must NOT trigger another Plaid call.
            with patch.object(plaid_service, "_plaid_client") as mock_client2:
                second = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert second["status"] == "rate_limited"
            assert mock_client2.return_value.accounts_balance_get.call_count == 0
            _deconfigure_plaid(flask_app)

    def test_does_not_overwrite_regular_sync_status(self, flask_app, plaid_user):
        """A realtime failure must not clobber last_sync_status from /accounts/get."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            conn.last_sync_status = "plaid_available_balance"
            conn.last_sync_error = None
            db.session.commit()

            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.side_effect = (
                    RuntimeError("boom")
                )
                plaid_service.realtime_update_plaid_balance_for_user(user)

            conn = PlaidConnection.query.filter_by(
                user_id=plaid_user, is_active=True
            ).first()
            # Automatic sync status is untouched.
            assert conn.last_sync_status == "plaid_available_balance"
            assert conn.last_sync_error is None
            # Dedicated realtime status reflects the failure.
            assert conn.last_realtime_refresh_status == "plaid_realtime_unexpected_error"
            assert conn.last_realtime_refresh_error
            _deconfigure_plaid(flask_app)

    def test_does_not_run_on_dashboard_load(self, auth_client, flask_app):
        """The dashboard load must continue to use /accounts/get only, never the paid endpoint."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(
            plaid_service, "realtime_update_plaid_balance_for_user"
        ) as mock_realtime:
            resp = auth_client.get("/")
            assert resp.status_code == 200
            assert not mock_realtime.called
        with patch("app.api.routes.data.safe_update_plaid_balance_for_user"):
            with patch.object(
                plaid_service, "realtime_update_plaid_balance_for_user"
            ) as mock_realtime:
                resp = auth_client.get("/api/v1/dashboard")
                assert resp.status_code == 200
                assert not mock_realtime.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


def _csrf_headers_for(client):
    """Fetch a CSRF token via the settings page so cookie-auth API writes work.

    The realtime-balance route uses ``require_bearer=True``; tests using
    Flask-Login cookie auth must therefore also send a valid X-CSRFToken.
    """
    html = client.get("/settings").get_data(as_text=True)
    marker = 'meta name="csrf-token" content="'
    idx = html.find(marker)
    assert idx != -1, "CSRF token meta tag not found in /settings"
    start = idx + len(marker)
    end = html.find('"', start)
    return {"X-CSRFToken": html[start:end]}


class TestRealtimeBalanceAPIRoute:
    def test_requires_authentication(self, flask_app):
        client = flask_app.test_client()
        resp = client.post("/api/v1/plaid/realtime-balance")
        # Unauthenticated requests should be rejected (401 or 403, not 200).
        assert resp.status_code in (401, 403)

    def test_does_not_accept_user_id_from_client(
        self, auth_client, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        headers = _csrf_headers_for(auth_client)
        with patch.object(plaid_service, "_plaid_client") as mock_client:
            mock_client.return_value.accounts_balance_get.return_value = (
                _make_balances_response("acct-1", available=1.0, current=2.0)
            )
            # Spoofing a different user_id in the body must be ignored —
            # the route operates only on the authenticated user.
            resp = auth_client.post(
                "/api/v1/plaid/realtime-balance",
                headers=headers,
                json={"user_id": plaid_user},
            )
        # The seeded admin user has no Plaid connection, so the call returns
        # plaid_no_connection — NOT a successful refresh of the spoofed user.
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["code"] == "plaid_no_connection"
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_returns_429_with_retry_after_on_cooldown(
        self, auth_client, flask_app
    ):
        from conftest import _ADMIN_USER_ID

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(_ADMIN_USER_ID)
        try:
            headers = _csrf_headers_for(auth_client)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=5.0, current=6.0)
                )
                first = auth_client.post(
                    "/api/v1/plaid/realtime-balance", headers=headers
                )
                second = auth_client.post(
                    "/api/v1/plaid/realtime-balance", headers=headers
                )
            assert first.status_code == 200
            assert first.get_json()["data"]["success"] is True
            assert second.status_code == 429
            body = second.get_json()
            assert body["code"] == "plaid_realtime_cooldown"
            assert body["retry_after_seconds"] > 0
            assert body["next_available_refresh_at"]
            assert "Retry-After" in second.headers
        finally:
            with flask_app.app_context():
                PlaidConnection.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                Balance.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_response_never_includes_access_token(
        self, auth_client, flask_app
    ):
        from conftest import _ADMIN_USER_ID

        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(_ADMIN_USER_ID)
        try:
            headers = _csrf_headers_for(auth_client)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.return_value = (
                    _make_balances_response("acct-1", available=11.0, current=12.0)
                )
                resp = auth_client.post(
                    "/api/v1/plaid/realtime-balance", headers=headers
                )
            assert resp.status_code == 200
            raw = resp.get_data(as_text=True)
            for forbidden_substr in (
                "access_token",
                "encrypted_access_token",
                "access-sandbox-test",
            ):
                assert forbidden_substr not in raw
        finally:
            with flask_app.app_context():
                PlaidConnection.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                Balance.query.filter_by(user_id=_ADMIN_USER_ID).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)


class TestRealtimeBalanceGuestRestrictions:
    """Guest (admin=False) users must not be able to trigger a paid refresh."""

    @pytest.fixture()
    def guest_client(self, flask_app):
        with flask_app.app_context():
            owner = User(
                email=f"plaid-rt-owner-{datetime.utcnow().timestamp()}@test.local",
                password=generate_password_hash("pw", method="scrypt"),
                name="Owner",
                admin=True,
                is_account_owner=True,
                is_active=True,
            )
            db.session.add(owner)
            db.session.commit()
            guest = User(
                email=f"plaid-rt-guest-{datetime.utcnow().timestamp()}@test.local",
                password=generate_password_hash("pw", method="scrypt"),
                name="Guest",
                admin=False,
                is_active=True,
                is_account_owner=False,
                owner_user_id=owner.id,
                account_owner_id=owner.id,
            )
            db.session.add(guest)
            db.session.commit()
            guest_id = guest.id
            owner_id = owner.id

        c = flask_app.test_client()
        with c.session_transaction() as sess:
            sess["_user_id"] = str(guest_id)
            sess["_fresh"] = True

        yield c

        with flask_app.app_context():
            PlaidConnection.query.filter(
                PlaidConnection.user_id.in_([guest_id, owner_id])
            ).delete(synchronize_session=False)
            User.query.filter(User.id.in_([guest_id, owner_id])).delete(
                synchronize_session=False
            )
            db.session.commit()

    def _csrf_headers(self, client):
        html = client.get("/settings").get_data(as_text=True)
        marker = 'meta name="csrf-token" content="'
        idx = html.find(marker)
        assert idx != -1
        start = idx + len(marker)
        end = html.find('"', start)
        return {"X-CSRFToken": html[start:end]}

    def test_guest_forbidden(self, flask_app, guest_client):
        with flask_app.app_context():
            _configure_plaid(flask_app)
        with patch.object(plaid_service, "realtime_update_plaid_balance_for_user") as mock_upd:
            resp = guest_client.post(
                "/api/v1/plaid/realtime-balance",
                headers=self._csrf_headers(guest_client),
            )
        assert resp.status_code == 403
        assert resp.get_json()["code"] == "forbidden"
        assert not mock_upd.called
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


# ── Connection health: expiring / expired consent ───────────────────────────
#
# Some institutions (Chase from Feb 2027) let consumers choose how long a
# connection stays active. Plaid reports the end date as
# ``item.consent_expiration_time`` on /item/get and returns
# ITEM_LOGIN_REQUIRED once it passes. These tests cover recording the date,
# flagging connections that need the user, and surfacing both in the UI.


def _utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _plaid_api_exception(error_code, error_type="ITEM_ERROR"):
    import json

    from plaid.exceptions import ApiException

    exc = ApiException(status=400, reason="Bad Request")
    exc.body = json.dumps(
        {
            "error_type": error_type,
            "error_code": error_code,
            "error_message": "the login details of this item have changed",
            "request_id": "req-test",
        }
    )
    return exc


def _make_item_get_response(
    consent_expiration_time=None, error_code=None, last_successful_update=None
):
    error = SimpleNamespace(error_code=error_code) if error_code else None
    item = SimpleNamespace(
        consent_expiration_time=consent_expiration_time, error=error
    )
    status = SimpleNamespace(
        transactions=SimpleNamespace(last_successful_update=last_successful_update)
    )
    return SimpleNamespace(item=item, status=status)


def _reload_connection(user_id):
    db.session.expire_all()
    return PlaidConnection.query.filter_by(user_id=user_id).one()


class TestCachedSyncConnectionHealth:
    @pytest.mark.parametrize(
        "error_code",
        ["ITEM_LOGIN_REQUIRED", "USER_PERMISSION_REVOKED", "USER_ACCOUNT_REVOKED"],
    )
    def test_reconnect_error_flags_connection(self, flask_app, plaid_user, error_code):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.side_effect = (
                    _plaid_api_exception(error_code)
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result == {"status": "error", "reason": "reconnect_required"}
            conn = _reload_connection(plaid_user)
            assert conn.reconnect_required_at is not None
            assert conn.last_sync_status == "reconnect_required"
            assert "connect it again" in conn.last_sync_error
            assert Balance.query.filter_by(user_id=plaid_user).count() == 0
            _deconfigure_plaid(flask_app)

    def test_generic_api_error_does_not_flag_connection(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.side_effect = (
                    _plaid_api_exception("INTERNAL_SERVER_ERROR", "API_ERROR")
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result == {"status": "error", "reason": "plaid_api_error"}
            conn = _reload_connection(plaid_user)
            assert conn.reconnect_required_at is None
            assert conn.last_sync_status == "plaid_api_error"
            _deconfigure_plaid(flask_app)

    def test_repeat_failure_keeps_first_flag_time(self, flask_app, plaid_user):
        first_seen = _utcnow_naive() - timedelta(days=3)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=first_seen)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.side_effect = (
                    _plaid_api_exception("ITEM_LOGIN_REQUIRED")
                )
                plaid_service.update_plaid_balance_for_user(user)
            conn = _reload_connection(plaid_user)
            assert abs((conn.reconnect_required_at - first_seen).total_seconds()) < 1
            _deconfigure_plaid(flask_app)

    def test_successful_sync_clears_flag(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.return_value = (
                    _make_item_get_response()
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "ok"
            conn = _reload_connection(plaid_user)
            assert conn.reconnect_required_at is None
            _deconfigure_plaid(flask_app)

    def test_item_error_on_item_get_flags_connection(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.return_value = (
                    _make_item_get_response(error_code="ITEM_LOGIN_REQUIRED")
                )
                plaid_service.update_plaid_balance_for_user(user)
            conn = _reload_connection(plaid_user)
            assert conn.reconnect_required_at is not None
            _deconfigure_plaid(flask_app)

    @pytest.mark.parametrize(
        "raw",
        [
            datetime(2027, 2, 21, 5, 0, 0, tzinfo=timezone.utc),
            "2027-02-21T05:00:00Z",
        ],
    )
    def test_records_consent_expiration_from_item_get(self, flask_app, plaid_user, raw):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.return_value = (
                    _make_item_get_response(consent_expiration_time=raw)
                )
                plaid_service.update_plaid_balance_for_user(user)
            conn = _reload_connection(plaid_user)
            assert conn.consent_expiration_time == datetime(2027, 2, 21, 5, 0, 0)
            _deconfigure_plaid(flask_app)

    def test_null_consent_expiration_clears_stored_value(self, flask_app, plaid_user):
        """Plaid's null means no expiration is scheduled any more."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(
                plaid_user, consent_expiration_time=datetime(2027, 2, 21, 0, 0, 0)
            )
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.return_value = (
                    _make_item_get_response(consent_expiration_time=None)
                )
                plaid_service.update_plaid_balance_for_user(user)
            conn = _reload_connection(plaid_user)
            assert conn.consent_expiration_time is None
            _deconfigure_plaid(flask_app)

    def test_item_get_failure_keeps_stored_expiration(self, flask_app, plaid_user):
        stored = datetime(2027, 2, 21, 0, 0, 0)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, consent_expiration_time=stored)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.side_effect = (
                    _plaid_api_exception("INTERNAL_SERVER_ERROR", "API_ERROR")
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["status"] == "ok"
            conn = _reload_connection(plaid_user)
            assert conn.consent_expiration_time == stored
            _deconfigure_plaid(flask_app)

    def test_expiration_saved_even_when_balance_update_is_skipped(
        self, flask_app, plaid_user
    ):
        """The manual-newer skip branch returns early; health must persist."""
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
            user = User.query.get(plaid_user)
            user.last_manual_balance_entry_at = _utcnow_naive()
            db.session.commit()
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_get.return_value = (
                    _make_balances_response("acct-1", available=10.0, current=11.0)
                )
                mock_client.return_value.item_get.return_value = (
                    _make_item_get_response(
                        consent_expiration_time="2027-02-21T00:00:00Z"
                    )
                )
                result = plaid_service.update_plaid_balance_for_user(user)
            assert result["reason"] == "skipped_cached_plaid_update_manual_newer"
            db.session.rollback()  # anything left uncommitted is discarded
            conn = _reload_connection(plaid_user)
            assert conn.consent_expiration_time == datetime(2027, 2, 21, 0, 0, 0)
            assert conn.reconnect_required_at is None
            _deconfigure_plaid(flask_app)


class TestConnectionStatusHealthFields:
    def _status_for(self, plaid_user, **conn_overrides):
        _add_connection(plaid_user, **conn_overrides)
        user = User.query.get(plaid_user)
        return plaid_service.get_plaid_connection_status(user)["connection"]

    def test_defaults_when_no_expiration_known(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            conn = self._status_for(plaid_user)
            assert conn["consent_expiration_time"] is None
            assert conn["consent_expires_soon"] is False
            assert conn["reconnect_required"] is False
            _deconfigure_plaid(flask_app)

    def test_expiring_within_warning_window(self, flask_app, plaid_user):
        expires = (_utcnow_naive() + timedelta(days=5)).replace(microsecond=0)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            conn = self._status_for(plaid_user, consent_expiration_time=expires)
            assert conn["consent_expiration_time"] == expires.isoformat() + "Z"
            assert conn["consent_expires_soon"] is True
            assert conn["reconnect_required"] is False
            _deconfigure_plaid(flask_app)

    def test_far_expiration_is_not_soon(self, flask_app, plaid_user):
        expires = _utcnow_naive() + timedelta(
            days=plaid_service.CONSENT_EXPIRY_WARNING_DAYS + 30
        )
        with flask_app.app_context():
            _configure_plaid(flask_app)
            conn = self._status_for(plaid_user, consent_expiration_time=expires)
            assert conn["consent_expires_soon"] is False
            assert conn["reconnect_required"] is False
            _deconfigure_plaid(flask_app)

    def test_past_expiration_means_reconnect_required(self, flask_app, plaid_user):
        expires = _utcnow_naive() - timedelta(hours=1)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            conn = self._status_for(plaid_user, consent_expiration_time=expires)
            assert conn["consent_expires_soon"] is False
            assert conn["reconnect_required"] is True
            _deconfigure_plaid(flask_app)

    def test_flagged_connection_reports_reconnect_required(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            conn = self._status_for(plaid_user, reconnect_required_at=_utcnow_naive())
            assert conn["reconnect_required"] is True
            _deconfigure_plaid(flask_app)

    def test_status_endpoint_exposes_health_fields(
        self, flask_app, plaid_user, login_as
    ):
        expires = (_utcnow_naive() + timedelta(days=3)).replace(microsecond=0)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, consent_expiration_time=expires)
        client = login_as(plaid_user)
        resp = client.get("/api/v1/plaid/status")
        assert resp.status_code == 200
        conn = resp.get_json()["data"]["connection"]
        assert conn["consent_expiration_time"] == expires.isoformat() + "Z"
        assert conn["consent_expires_soon"] is True
        assert conn["reconnect_required"] is False
        # Existing fields are still present (additive change only).
        assert "last_sync_status" in conn
        assert "access_token" not in resp.get_data(as_text=True)
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


class TestRealtimeRefreshConnectionHealth:
    def test_flagged_connection_skips_without_using_cooldown(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result == {"status": "skipped", "reason": "reconnect_required"}
            assert mock_client.return_value.accounts_balance_get.call_count == 0
            conn = _reload_connection(plaid_user)
            assert conn.last_realtime_balance_at is None
            _deconfigure_plaid(flask_app)

    def test_expired_consent_skips_without_using_cooldown(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(
                plaid_user,
                consent_expiration_time=_utcnow_naive() - timedelta(days=1),
            )
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["reason"] == "reconnect_required"
            assert mock_client.return_value.accounts_balance_get.call_count == 0
            assert _reload_connection(plaid_user).last_realtime_balance_at is None
            _deconfigure_plaid(flask_app)

    def test_reconnect_error_during_call_flags_connection(
        self, flask_app, plaid_user
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, last_sync_status="plaid_available_balance")
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.side_effect = (
                    _plaid_api_exception("ITEM_LOGIN_REQUIRED")
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["status"] == "error"
            assert result["reason"] == "reconnect_required"
            conn = _reload_connection(plaid_user)
            assert conn.reconnect_required_at is not None
            assert conn.last_realtime_refresh_status == "reconnect_required"
            # The automatic sync's status column is left alone.
            assert conn.last_sync_status == "plaid_available_balance"
            _deconfigure_plaid(flask_app)

    def test_generic_error_during_call_does_not_flag(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user)
            user = User.query.get(plaid_user)
            with patch.object(plaid_service, "_plaid_client") as mock_client:
                mock_client.return_value.accounts_balance_get.side_effect = (
                    _plaid_api_exception("INSTITUTION_DOWN", "INSTITUTION_ERROR")
                )
                result = plaid_service.realtime_update_plaid_balance_for_user(user)
            assert result["reason"] == "plaid_api_error"
            assert _reload_connection(plaid_user).reconnect_required_at is None
            _deconfigure_plaid(flask_app)

    def test_api_route_returns_409_reconnect_required(
        self, flask_app, plaid_user, login_as
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
        client = login_as(plaid_user)
        headers = _csrf_headers_for(client)
        with patch.object(plaid_service, "_plaid_client") as mock_client:
            resp = client.post("/api/v1/plaid/realtime-balance", headers=headers)
        assert resp.status_code == 409
        body = resp.get_json()
        assert body["code"] == "plaid_reconnect_required"
        assert body["status"] == 409
        assert "Reconnect" in body["error"]
        assert mock_client.return_value.accounts_balance_get.call_count == 0
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_web_route_flashes_reconnect_message(
        self, flask_app, plaid_user, login_as
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
        client = login_as(plaid_user)
        with patch("app.main.safe_update_plaid_balance_for_user"):
            resp = client.post("/refresh_realtime_balance", follow_redirects=True)
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "remove the account, and connect it again" in html
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)


class TestDashboardConnectionAlert:
    def _dashboard_html(self, client):
        # Skip the live Plaid sync: these tests are about rendering only.
        with patch("app.main.safe_update_plaid_balance_for_user"):
            resp = client.get("/")
        assert resp.status_code == 200
        return resp.get_data(as_text=True)

    def test_reconnect_banner_for_owner(self, flask_app, plaid_user, login_as):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
        html = self._dashboard_html(login_as(plaid_user))
        assert 'data-plaid-alert="reconnect_required"' in html
        assert "Test Bank" in html
        assert "remove the account, and connect it again" in html
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_expiring_banner_shows_date(self, flask_app, plaid_user, login_as):
        expires = _utcnow_naive() + timedelta(days=4)
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, consent_expiration_time=expires)
        html = self._dashboard_html(login_as(plaid_user))
        assert 'data-plaid-alert="expires_soon"' in html
        assert expires.strftime("%B %d, %Y") in html
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_no_banner_when_connection_healthy(self, flask_app, plaid_user, login_as):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(
                plaid_user,
                consent_expiration_time=_utcnow_naive() + timedelta(days=120),
            )
        html = self._dashboard_html(login_as(plaid_user))
        assert "data-plaid-alert" not in html
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)

    def test_no_banner_when_plaid_not_configured(self, flask_app, plaid_user, login_as):
        with flask_app.app_context():
            _deconfigure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
        html = self._dashboard_html(login_as(plaid_user))
        assert "data-plaid-alert" not in html

    def test_guest_sees_owner_connection_alert(
        self, flask_app, plaid_user, make_user, login_as
    ):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            _add_connection(plaid_user, reconnect_required_at=_utcnow_naive())
        guest_id = make_user(admin=False, owner_id=plaid_user)
        try:
            html = self._dashboard_html(login_as(guest_id))
            assert 'data-plaid-alert="reconnect_required"' in html
            assert "account owner needs to reconnect" in html
            # Guests can't change settings, so no link or bank name for them.
            assert "remove the account" not in html
        finally:
            with flask_app.app_context():
                User.query.filter_by(id=guest_id).delete()
                db.session.commit()
                _deconfigure_plaid(flask_app)

    def test_alert_lookup_never_raises(self, flask_app, plaid_user):
        with flask_app.app_context():
            _configure_plaid(flask_app)
            user = User.query.get(plaid_user)
            with patch.object(
                plaid_service, "get_active_connection", side_effect=RuntimeError("db")
            ):
                assert plaid_service.get_plaid_connection_alert(user) is None
            _deconfigure_plaid(flask_app)

    def test_settings_page_renders_health_markup(self, auth_client):
        html = auth_client.get("/settings").get_data(as_text=True)
        assert "Connection expires:" in html
        assert "plaid-reconnect-required" in html
        assert "plaid-consent-expiring" in html
