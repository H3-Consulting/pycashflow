"""
Web authentication flow tests (app/auth.py plus the 2FA routes in app/main.py).

Covers password login, the TOTP/backup-code second factor, sign-up, logout,
forgot/set password validation, enabling and disabling 2FA from settings,
passkey management pages, per-request access enforcement, and the security
response headers applied to every web response.
"""

import json

import pyotp
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from app.crypto_utils import encrypt_password


def _flashed(resp, keyword):
    return keyword.lower().encode() in resp.data.lower()


def _session_flashes(client):
    with client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


def _logged_in_user_id(client):
    with client.session_transaction() as sess:
        return sess.get("_user_id")


@pytest.fixture()
def signup_settings(app_ctx, web_models):
    """Snapshot and restore the global sign-up settings rows."""
    snapshot = [
        (row.name, row.value) for row in web_models.Settings.query.filter_by(name="signup")
    ]
    text_snapshot = [
        (row.name, row.value)
        for row in web_models.TextSettings.query.filter_by(name="external_signup_url")
    ]
    web_models.TextSettings.query.filter_by(name="external_signup_url").delete()
    app_ctx.session.commit()

    def _set(disabled):
        web_models.Settings.query.filter_by(name="signup").delete()
        app_ctx.session.add(web_models.Settings(name="signup", value=disabled))
        app_ctx.session.commit()

    yield _set

    web_models.Settings.query.filter_by(name="signup").delete()
    web_models.TextSettings.query.filter_by(name="external_signup_url").delete()
    for name, value in snapshot:
        app_ctx.session.add(web_models.Settings(name=name, value=value))
    for name, value in text_snapshot:
        app_ctx.session.add(web_models.TextSettings(name=name, value=value))
    app_ctx.session.commit()


@pytest.fixture()
def twofa_user(make_user, app_ctx, web_models):
    """An active user with TOTP 2FA enabled and one known backup code."""
    secret = pyotp.random_base32()
    backup = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    uid = make_user(
        twofa_enabled=True,
        twofa_secret=encrypt_password(secret),
        twofa_backup_codes=json.dumps([generate_password_hash(backup, method="scrypt")]),
    )
    email = app_ctx.session.get(web_models.User, uid).email
    return {"id": uid, "email": email, "secret": secret, "backup": backup}


# ── Password login ───────────────────────────────────────────────────────────


class TestLogin:
    def test_valid_credentials_log_in_and_redirect_home(self, client, make_user, web_models, app_ctx):
        uid = make_user(email="login-ok@test.local", balance="1.00")
        resp = client.post(
            "/login", data={"email": "login-ok@test.local", "password": "testpass123"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")
        assert _logged_in_user_id(client) == str(uid)
        assert client.get("/").status_code == 200

    def test_email_is_case_insensitive(self, client, make_user):
        uid = make_user(email="mixed-case@test.local")
        client.post("/login", data={"email": "  Mixed-Case@Test.Local ", "password": "testpass123"})
        assert _logged_in_user_id(client) == str(uid)

    def test_wrong_password_rejected(self, client, make_user):
        make_user(email="login-bad@test.local")
        resp = client.post(
            "/login", data={"email": "login-bad@test.local", "password": "nope"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Please check your login details")
        assert _logged_in_user_id(client) is None

    def test_unknown_email_gets_same_message(self, client):
        resp = client.post(
            "/login", data={"email": "nobody@test.local", "password": "whatever"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Please check your login details")
        assert _logged_in_user_id(client) is None

    def test_inactive_user_cannot_log_in(self, client, make_user):
        make_user(email="pending@test.local", is_active=False)
        resp = client.post(
            "/login", data={"email": "pending@test.local", "password": "testpass123"},
            follow_redirects=True,
        )
        assert _flashed(resp, "pending approval")
        assert _logged_in_user_id(client) is None

    def test_safe_next_is_honoured_after_login(self, client, make_user):
        make_user(email="next-ok@test.local")
        resp = client.post(
            "/login",
            data={"email": "next-ok@test.local", "password": "testpass123", "next": "/schedule"},
            follow_redirects=False,
        )
        assert resp.headers["Location"].endswith("/schedule")

    def test_remember_me_sets_remember_cookie(self, client, make_user):
        make_user(email="remember@test.local")
        client.post(
            "/login",
            data={"email": "remember@test.local", "password": "testpass123", "remember": "on"},
        )
        assert client.get_cookie("remember_token") is not None

    def test_login_page_renders(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b'name="password"' in resp.data


class TestLogout:
    def test_logout_ends_session(self, make_user, login_as):
        c = login_as(make_user(balance="1.00"))
        assert c.get("/").status_code == 200
        resp = c.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        follow = c.get("/", follow_redirects=False)
        assert follow.status_code == 302
        assert "/login" in follow.headers["Location"]

    def test_logout_requires_login(self, client):
        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ── Second factor at login ───────────────────────────────────────────────────


class TestLoginTwoFactor:
    def _start(self, client, user):
        return client.post(
            "/login", data={"email": user["email"], "password": "testpass123"},
            follow_redirects=False,
        )

    def test_password_step_defers_login_until_code(self, client, twofa_user):
        resp = self._start(client, twofa_user)
        assert resp.headers["Location"].endswith("/login/2fa")
        assert _logged_in_user_id(client) is None
        page = client.get("/login/2fa")
        assert page.status_code == 200

    def test_valid_totp_completes_login(self, client, twofa_user):
        self._start(client, twofa_user)
        code = pyotp.TOTP(twofa_user["secret"]).now()
        resp = client.post("/login/2fa", data={"code": code}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/")
        assert _logged_in_user_id(client) == str(twofa_user["id"])

    def test_invalid_totp_rejected(self, client, twofa_user):
        self._start(client, twofa_user)
        resp = client.post("/login/2fa", data={"code": "000000"}, follow_redirects=True)
        assert _flashed(resp, "Invalid or expired verification code")
        assert _logged_in_user_id(client) is None

    def test_backup_code_is_single_use(self, flask_app, client, twofa_user, fresh, web_models):
        self._start(client, twofa_user)
        resp = client.post(
            "/login/2fa", data={"code": twofa_user["backup"], "use_backup": "1"},
            follow_redirects=False,
        )
        assert resp.headers["Location"].endswith("/")
        assert json.loads(fresh(web_models.User, twofa_user["id"]).twofa_backup_codes) == []

        second = flask_app.test_client()
        self._start(second, twofa_user)
        resp = second.post(
            "/login/2fa", data={"code": twofa_user["backup"], "use_backup": "1"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Invalid or already-used backup code")
        assert _logged_in_user_id(second) is None

    def test_2fa_page_without_pending_login_redirects(self, client):
        resp = client.get("/login/2fa", follow_redirects=False)
        assert "/login" in resp.headers["Location"]

    def test_2fa_post_without_pending_login_redirects(self, client):
        resp = client.post("/login/2fa", data={"code": "123456"}, follow_redirects=True)
        assert _flashed(resp, "Session expired")

    def test_pending_user_deleted_mid_flow(self, client, twofa_user, app_ctx, web_models):
        self._start(client, twofa_user)
        app_ctx.session.delete(app_ctx.session.get(web_models.User, twofa_user["id"]))
        app_ctx.session.commit()
        resp = client.post("/login/2fa", data={"code": "123456"}, follow_redirects=True)
        assert _flashed(resp, "User not found")

    def test_next_survives_2fa_step(self, client, twofa_user):
        client.post(
            "/login",
            data={"email": twofa_user["email"], "password": "testpass123", "next": "/settings"},
        )
        code = pyotp.TOTP(twofa_user["secret"]).now()
        resp = client.post("/login/2fa", data={"code": code}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/settings")


# ── Sign-up ──────────────────────────────────────────────────────────────────


class TestSignup:
    def test_signup_page_renders_when_enabled(self, client, signup_settings):
        signup_settings(False)
        resp = client.get("/signup")
        assert resp.status_code == 200
        assert b'name="name"' in resp.data

    def test_signup_page_hidden_when_disabled(self, client, signup_settings):
        signup_settings(True)
        resp = client.get("/signup")
        assert resp.status_code == 200
        assert b'name="name"' not in resp.data

    def test_signup_creates_inactive_owner_and_notifies_admin(
        self, client, signup_settings, auth_module, monkeypatch, web_models
    ):
        signup_settings(False)
        notified = []
        monkeypatch.setattr(auth_module, "send_new_user_notification",
                            lambda name, email: notified.append((name, email)))
        resp = client.post(
            "/signup",
            data={"email": "New.Signup@Test.Local", "name": "New Signup", "password": "Str0ngPass!"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

        user = web_models.User.query.filter_by(email="new.signup@test.local").one()
        assert user.is_active is False
        assert user.admin is True
        assert user.is_global_admin is False
        assert check_password_hash(user.password, "Str0ngPass!")
        assert notified == [("New Signup", "new.signup@test.local")]

    def test_signup_notification_failure_does_not_block(
        self, client, signup_settings, auth_module, monkeypatch, web_models
    ):
        signup_settings(False)

        def _boom(*_a):
            raise RuntimeError("smtp down")

        monkeypatch.setattr(auth_module, "send_new_user_notification", _boom)
        resp = client.post(
            "/signup",
            data={"email": "notify-fail@test.local", "name": "N", "password": "Str0ngPass!"},
        )
        assert resp.status_code == 302
        assert web_models.User.query.filter_by(email="notify-fail@test.local").count() == 1

    def test_duplicate_email_rejected(self, client, signup_settings, make_user, web_models):
        signup_settings(False)
        make_user(email="dupe-signup@test.local")
        resp = client.post(
            "/signup",
            data={"email": "dupe-signup@test.local", "name": "Dup", "password": "Str0ngPass!"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Email address already exists")
        assert web_models.User.query.filter_by(email="dupe-signup@test.local").count() == 1

    def test_signup_post_blocked_when_signups_disabled(self, client, signup_settings, web_models):
        signup_settings(True)
        resp = client.post(
            "/signup",
            data={"email": "blocked-signup@test.local", "name": "Blocked", "password": "Str0ngPass!"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Sign-ups are currently disabled")
        assert web_models.User.query.filter_by(email="blocked-signup@test.local").count() == 0

    @pytest.mark.parametrize(
        "form",
        [
            {"email": "", "name": "No Email", "password": "Str0ngPass!"},
            {"email": "no-password@test.local", "name": "No Password"},
        ],
    )
    def test_signup_requires_email_and_password(self, client, signup_settings, web_models, form):
        signup_settings(False)
        resp = client.post("/signup", data=form, follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, "Email and password are required")
        assert web_models.User.query.filter_by(name=form["name"]).count() == 0


# ── Forgot / set password ────────────────────────────────────────────────────


class TestForgotPassword:
    def test_get_renders_form(self, client):
        assert client.get("/forgot-password").status_code == 200

    def test_empty_email_rejected(self, client):
        resp = client.post("/forgot-password", data={"email": ""})
        assert resp.status_code == 200
        assert _flashed(resp, "Email address is required")

    def test_unknown_email_gets_generic_response_and_no_email(
        self, client, auth_module, monkeypatch
    ):
        sent = []
        monkeypatch.setattr(auth_module, "send_password_setup_email",
                            lambda **kw: sent.append(kw) or True)
        resp = client.post("/forgot-password", data={"email": "ghost@test.local"},
                           follow_redirects=True)
        assert _flashed(resp, "If an account exists for that email")
        assert sent == []

    def test_missing_frontend_base_url_reports_unavailable(
        self, client, flask_app, make_user, monkeypatch
    ):
        make_user(email="reset-nofrontend@test.local")
        monkeypatch.setitem(flask_app.config, "FRONTEND_BASE_URL", "")
        resp = client.post("/forgot-password", data={"email": "reset-nofrontend@test.local"})
        assert resp.status_code == 200
        assert _flashed(resp, "Password reset is currently unavailable")


class TestSetPasswordValidation:
    @pytest.mark.parametrize(
        "password,confirm,message",
        [
            ("", "", "Password is required"),
            ("Abcdefg1", "Abcdefg2", "Passwords do not match"),
            ("Ab1", "Ab1", "at least 8 characters"),
            ("abcdefg1", "abcdefg1", "uppercase and lowercase"),
            ("Abcdefgh", "Abcdefgh", "at least one number"),
        ],
    )
    def test_rejects_weak_or_mismatched_passwords(self, client, password, confirm, message):
        resp = client.post(
            "/auth/set-password/some-token",
            data={"password": password, "confirm_password": confirm},
        )
        assert resp.status_code == 200
        assert _flashed(resp, message)


# ── Enabling / disabling 2FA from settings ───────────────────────────────────


class TestTwoFactorSetup:
    def test_setup_page_renders_qr_and_stashes_secret(self, make_user, login_as):
        c = login_as(make_user())
        resp = c.get("/setup_2fa")
        assert resp.status_code == 200
        assert b"data:image/png;base64," in resp.data
        with c.session_transaction() as sess:
            assert sess.get("twofa_temp_secret")

    def test_full_enable_flow_shows_backup_codes_once(self, make_user, login_as, fresh, web_models):
        uid = make_user()
        c = login_as(uid)
        c.get("/setup_2fa")
        with c.session_transaction() as sess:
            secret = sess["twofa_temp_secret"]

        resp = c.post("/setup_2fa", data={"code": pyotp.TOTP(secret).now()}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/setup_2fa/backup_codes")

        user = fresh(web_models.User, uid)
        assert user.twofa_enabled is True
        assert user.twofa_secret and secret not in user.twofa_secret  # stored encrypted
        assert len(json.loads(user.twofa_backup_codes)) == 10

        codes_page = c.get("/setup_2fa/backup_codes")
        assert codes_page.status_code == 200
        again = c.get("/setup_2fa/backup_codes", follow_redirects=False)
        assert again.status_code == 302
        assert again.headers["Location"].endswith("/settings")

    def test_invalid_code_does_not_enable(self, make_user, login_as, fresh, web_models):
        uid = make_user()
        c = login_as(uid)
        c.get("/setup_2fa")
        resp = c.post("/setup_2fa", data={"code": "000000"}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/setup_2fa")
        assert fresh(web_models.User, uid).twofa_enabled is False

    def test_post_without_setup_session_redirects(self, make_user, login_as):
        c = login_as(make_user())
        resp = c.post("/setup_2fa", data={"code": "123456"}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/setup_2fa")


class TestTwoFactorDisable:
    def test_wrong_password_keeps_2fa(self, twofa_user, login_as, fresh, web_models):
        c = login_as(twofa_user["id"])
        code = pyotp.TOTP(twofa_user["secret"]).now()
        resp = c.post("/disable_2fa", data={"current_password": "wrong", "totp_code": code},
                      follow_redirects=True)
        assert _flashed(resp, "Incorrect password")
        assert fresh(web_models.User, twofa_user["id"]).twofa_enabled is True

    def test_wrong_code_keeps_2fa(self, twofa_user, login_as, fresh, web_models):
        c = login_as(twofa_user["id"])
        resp = c.post("/disable_2fa",
                      data={"current_password": "testpass123", "totp_code": "000000"},
                      follow_redirects=True)
        assert _flashed(resp, "Invalid verification code")
        assert fresh(web_models.User, twofa_user["id"]).twofa_enabled is True

    def test_valid_totp_disables_2fa(self, twofa_user, login_as, fresh, web_models):
        c = login_as(twofa_user["id"])
        code = pyotp.TOTP(twofa_user["secret"]).now()
        resp = c.post("/disable_2fa",
                      data={"current_password": "testpass123", "totp_code": code},
                      follow_redirects=True)
        assert _flashed(resp, "Two-factor authentication has been disabled")
        user = fresh(web_models.User, twofa_user["id"])
        assert user.twofa_enabled is False
        assert user.twofa_secret is None
        assert user.twofa_backup_codes is None

    def test_backup_code_disables_2fa(self, twofa_user, login_as, fresh, web_models):
        c = login_as(twofa_user["id"])
        c.post("/disable_2fa", data={"current_password": "testpass123",
                                     "totp_code": twofa_user["backup"], "use_backup": "1"})
        assert fresh(web_models.User, twofa_user["id"]).twofa_enabled is False


# ── Passkey management pages ─────────────────────────────────────────────────


class TestPasskeyPages:
    def test_manage_page_lists_own_passkeys(self, make_user, login_as, app_ctx, web_models):
        uid = make_user()
        app_ctx.session.add(web_models.PasskeyCredential(
            user_id=uid, credential_id="manage-page-cred", public_key="pk", label="My Laptop Key"))
        app_ctx.session.commit()
        resp = login_as(uid).get("/passkeys")
        assert resp.status_code == 200
        assert b"My Laptop Key" in resp.data

    def test_manage_page_redirects_when_disabled(self, make_user, login_as, flask_app, monkeypatch):
        monkeypatch.setitem(flask_app.config, "PASSKEY_RP_ID", "")
        resp = login_as(make_user()).get("/passkeys", follow_redirects=False)
        assert resp.headers["Location"].endswith("/settings")

    def test_passkey_login_page_redirects_when_disabled(self, client, flask_app, monkeypatch):
        monkeypatch.setitem(flask_app.config, "PASSKEY_RP_ID", "")
        resp = client.get("/passkey_login", follow_redirects=False)
        assert "/login" in resp.headers["Location"]

    def test_login_options_issue_challenge_for_registered_user(
        self, client, make_user, app_ctx, web_models
    ):
        uid = make_user(email="web-passkey-options@test.local")
        app_ctx.session.add(web_models.PasskeyCredential(
            user_id=uid, credential_id="cGFzc2tleS1vcHRpb25z", public_key="pk"))
        app_ctx.session.commit()
        resp = client.post("/passkey_login/options", json={"email": "Web-Passkey-Options@test.local"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["challenge"]
        assert [c["id"] for c in body["allowCredentials"]] == ["cGFzc2tleS1vcHRpb25z"]
        with client.session_transaction() as sess:
            assert sess["passkey_login_user_id"] == uid
            assert sess["passkey_login_challenge"] == body["challenge"]

    def test_login_options_reject_user_without_passkeys(self, client, make_user):
        make_user(email="web-no-passkeys@test.local")
        resp = client.post("/passkey_login/options", json={"email": "web-no-passkeys@test.local"})
        assert resp.status_code == 400

    def test_register_options_exclude_existing_credentials(self, make_user, login_as, app_ctx, web_models):
        uid = make_user()
        app_ctx.session.add(web_models.PasskeyCredential(
            user_id=uid, credential_id="ZXhpc3Rpbmc", public_key="pk"))
        app_ctx.session.commit()
        c = login_as(uid)
        resp = c.post("/passkeys/register/options")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["rp"]["id"] == "localhost"
        assert [x["id"] for x in body["excludeCredentials"]] == ["ZXhpc3Rpbmc"]
        with c.session_transaction() as sess:
            assert sess["passkey_register_challenge"] == body["challenge"]

    def test_register_verify_without_challenge_rejected(self, make_user, login_as):
        resp = login_as(make_user()).post("/passkeys/register/verify", json={"id": "x"})
        assert resp.status_code == 400
        assert "expired" in resp.get_json()["error"]

    def test_delete_own_passkey(self, make_user, login_as, app_ctx, web_models, fresh):
        uid = make_user()
        cred = web_models.PasskeyCredential(user_id=uid, credential_id="delete-own-cred", public_key="pk")
        app_ctx.session.add(cred)
        app_ctx.session.commit()
        cred_id = cred.id
        c = login_as(uid)
        resp = c.post(f"/passkeys/{cred_id}/delete", follow_redirects=False)
        assert resp.headers["Location"].endswith("/passkeys")
        assert "Passkey removed." in _session_flashes(c)
        assert fresh(web_models.PasskeyCredential, cred_id) is None

    def test_cannot_delete_another_users_passkey(self, make_user, login_as, app_ctx, web_models, fresh):
        owner = make_user()
        attacker = make_user()
        cred = web_models.PasskeyCredential(user_id=owner, credential_id="not-yours-cred", public_key="pk")
        app_ctx.session.add(cred)
        app_ctx.session.commit()
        cred_id = cred.id
        c = login_as(attacker)
        c.post(f"/passkeys/{cred_id}/delete", follow_redirects=False)
        assert "Passkey not found." in _session_flashes(c)
        assert fresh(web_models.PasskeyCredential, cred_id) is not None


# ── Per-request access enforcement ───────────────────────────────────────────


class TestAccessEnforcement:
    def test_deactivated_user_loses_access_immediately(self, make_user, login_as, app_ctx, web_models):
        uid = make_user(balance="1.00")
        c = login_as(uid)
        assert c.get("/").status_code == 200

        app_ctx.session.get(web_models.User, uid).is_active = False
        app_ctx.session.commit()

        # Flask-Login treats inactive users as unauthenticated, so every
        # subsequent request is bounced to the login page.
        for path in ("/", "/schedule", "/settings"):
            resp = c.get(path, follow_redirects=False)
            assert resp.status_code == 302
            assert "/login" in resp.headers["Location"]

    def test_deleted_user_session_is_anonymous(self, make_user, login_as, app_ctx, web_models):
        uid = make_user()
        c = login_as(uid)
        app_ctx.session.delete(app_ctx.session.get(web_models.User, uid))
        app_ctx.session.commit()
        resp = c.get("/settings", follow_redirects=False)
        assert "/login" in resp.headers["Location"]

    @pytest.mark.parametrize(
        "path",
        ["/transactions", "/balance", "/export", "/manage_guests", "/global_admin",
         "/setup_2fa", "/passkeys", "/changepw", "/email"],
    )
    def test_additional_protected_pages_require_login(self, client, path):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ── Security headers ─────────────────────────────────────────────────────────


class TestSecurityHeaders:
    def test_html_responses_carry_hardening_headers(self, client):
        resp = client.get("/login")
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert resp.headers["Cache-Control"] == "no-store"
        csp = resp.headers.get("Content-Security-Policy-Report-Only")
        assert csp and "frame-ancestors 'none'" in csp
        assert "Strict-Transport-Security" not in resp.headers

    def test_hsts_only_over_https(self, client):
        resp = client.get("/login", base_url="https://localhost")
        assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]

    def test_csp_enforcing_mode(self, client, flask_app, monkeypatch):
        monkeypatch.setitem(flask_app.config, "CSP_REPORT_ONLY", False)
        resp = client.get("/login")
        assert "Content-Security-Policy" in resp.headers
        assert "Content-Security-Policy-Report-Only" not in resp.headers

    def test_headers_can_be_disabled(self, client, flask_app, monkeypatch):
        monkeypatch.setitem(flask_app.config, "SECURITY_HEADERS_ENABLED", False)
        resp = client.get("/login")
        assert "X-Frame-Options" not in resp.headers

    def test_non_html_responses_stay_cacheable(self, client):
        resp = client.get("/healthz")
        assert "Cache-Control" not in resp.headers
