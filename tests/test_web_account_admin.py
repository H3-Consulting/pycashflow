"""
Web route tests for account settings and user administration in app/main.py.

Covers profile/password changes, the sign-up toggle, email-ingestion and
global SMTP settings, AI settings and on-demand insights, the global admin
panel, user create/update/activate/deactivate/reviewer toggles, guest
management by account owners, and self-service account deletion.
"""

import json
from datetime import datetime, timezone

import pytest
from werkzeug.security import check_password_hash

from app.crypto_utils import decrypt_password, encrypt_password


def _flashed(resp, keyword):
    return keyword.lower().encode() in resp.data.lower()


def _session_flashes(client):
    with client.session_transaction() as sess:
        return [message for _category, message in sess.get("_flashes", [])]


@pytest.fixture()
def owner(make_user):
    return make_user(balance="1000.00")


@pytest.fixture()
def owner_client(owner, login_as):
    return login_as(owner)


@pytest.fixture()
def global_admin(make_user):
    return make_user(is_global_admin=True, balance="1.00")


@pytest.fixture()
def global_client(global_admin, login_as):
    return login_as(global_admin)


@pytest.fixture()
def guest_of(make_user):
    def _guest(owner_id, **kw):
        return make_user(admin=False, owner_id=owner_id, **kw)

    return _guest


# ── Profile & password ───────────────────────────────────────────────────────


class TestChangeProfile:
    def test_wrong_current_password_rejected(self, owner, owner_client, fresh, web_models):
        resp = owner_client.post("/changepw", data={"current": "bad", "name": "New Name"},
                                 follow_redirects=True)
        assert _flashed(resp, "Incorrect current password")
        assert fresh(web_models.User, owner).name == "Web Test User"

    def test_updates_name_and_email(self, owner, owner_client, fresh, web_models):
        resp = owner_client.post(
            "/changepw",
            data={"current": "testpass123", "name": "Renamed", "email": "Renamed-Owner@Test.Local"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Account settings updated successfully")
        user = fresh(web_models.User, owner)
        assert user.name == "Renamed"
        assert user.email == "renamed-owner@test.local"

    def test_email_already_in_use_rejected(self, owner, owner_client, make_user, fresh, web_models):
        make_user(email="taken-email@test.local")
        resp = owner_client.post(
            "/changepw", data={"current": "testpass123", "email": "taken-email@test.local"},
            follow_redirects=True,
        )
        assert _flashed(resp, "already in use")
        assert fresh(web_models.User, owner).email != "taken-email@test.local"

    @pytest.mark.parametrize(
        "password,password2,message",
        [
            ("newpassword1", "", "Please fill in both new password fields"),
            ("newpassword1", "newpassword2", "New passwords do not match"),
            ("short", "short", "at least 8 characters"),
        ],
    )
    def test_new_password_validation(self, owner, owner_client, fresh, web_models,
                                     password, password2, message):
        resp = owner_client.post(
            "/changepw",
            data={"current": "testpass123", "password": password, "password2": password2},
            follow_redirects=True,
        )
        assert _flashed(resp, message)
        assert check_password_hash(fresh(web_models.User, owner).password, "testpass123")

    def test_password_change_succeeds(self, owner, owner_client, fresh, web_models):
        owner_client.post(
            "/changepw",
            data={"current": "testpass123", "password": "brandnewpass", "password2": "brandnewpass"},
        )
        assert check_password_hash(fresh(web_models.User, owner).password, "brandnewpass")


class TestSettingsPage:
    def test_admin_settings_shows_version_and_forms(self, owner_client, monkeypatch):
        monkeypatch.setenv("APP_VERSION", "9.9.9")
        monkeypatch.delenv("DOCKER_TAG", raising=False)
        resp = owner_client.get("/settings")
        assert resp.status_code == 200
        assert b"9.9.9" in resp.data
        assert b'action="/ai_settings"' in resp.data


# ── Sign-up toggle (global admin) ────────────────────────────────────────────


class TestSignupSettings:
    @pytest.fixture(autouse=True)
    def _restore(self, app_ctx, web_models):
        snapshot = [(r.name, r.value) for r in web_models.Settings.query.filter_by(name="signup")]
        text_snapshot = [(r.name, r.value) for r in
                         web_models.TextSettings.query.filter_by(name="external_signup_url")]
        yield
        web_models.Settings.query.filter_by(name="signup").delete()
        web_models.TextSettings.query.filter_by(name="external_signup_url").delete()
        for name, value in snapshot:
            app_ctx.session.add(web_models.Settings(name=name, value=value))
        for name, value in text_snapshot:
            app_ctx.session.add(web_models.TextSettings(name=name, value=value))
        app_ctx.session.commit()

    def test_global_admin_can_disable_and_reenable(self, global_client, web_models, app_ctx):
        web_models.Settings.query.filter_by(name="signup").delete()
        app_ctx.session.commit()

        global_client.post("/signups", data={"signupvalue": "True"})
        app_ctx.session.expire_all()
        assert web_models.Settings.query.filter_by(name="signup").one().value is True

        global_client.post("/signups", data={"signupvalue": "False",
                                             "external_signup_url": "https://example.com/join"})
        app_ctx.session.expire_all()
        assert web_models.Settings.query.filter_by(name="signup").one().value is False
        link = web_models.TextSettings.query.filter_by(name="external_signup_url").one()
        assert link.value == "https://example.com/join"

    def test_non_global_admin_forbidden(self, owner_client, web_models, app_ctx):
        before = [(r.value) for r in web_models.Settings.query.filter_by(name="signup")]
        resp = owner_client.post("/signups", data={"signupvalue": "True"}, follow_redirects=False)
        assert resp.headers["Location"].endswith("/")
        assert "Global admin access required" in _session_flashes(owner_client)
        app_ctx.session.expire_all()
        assert [(r.value) for r in web_models.Settings.query.filter_by(name="signup")] == before


# ── Balance-email ingestion settings ─────────────────────────────────────────


class TestEmailSettings:
    _form = {
        "email": "inbox@example.com",
        "password": "imap-secret",
        "server": "imap.example.com",
        "subject_str": "Balance",
        "start_str": "is $",
        "end_str": ".",
        "allowed_sender": "  Alerts@Bank.COM ",
    }

    def test_create_encrypts_password_and_normalises_sender(self, owner, owner_client, web_models):
        resp = owner_client.post("/email", data=self._form, follow_redirects=False)
        assert resp.headers["Location"].endswith("/settings")
        row = web_models.Email.query.filter_by(user_id=owner).one()
        assert row.server == "imap.example.com"
        assert row.password != "imap-secret"
        assert decrypt_password(row.password) == "imap-secret"
        assert row.allowed_sender == "alerts@bank.com"

    def test_update_blank_password_keeps_existing(self, owner, owner_client, web_models, app_ctx):
        owner_client.post("/email", data=self._form)
        owner_client.post("/email", data={**self._form, "password": "", "server": "imap2.example.com"})
        app_ctx.session.expire_all()
        row = web_models.Email.query.filter_by(user_id=owner).one()
        assert row.server == "imap2.example.com"
        assert decrypt_password(row.password) == "imap-secret"

    def test_update_new_password_replaces(self, owner, owner_client, web_models, app_ctx):
        owner_client.post("/email", data=self._form)
        owner_client.post("/email", data={**self._form, "password": "rotated"})
        app_ctx.session.expire_all()
        row = web_models.Email.query.filter_by(user_id=owner).one()
        assert decrypt_password(row.password) == "rotated"

    def test_delete_settings(self, owner, owner_client, web_models, app_ctx):
        owner_client.post("/email", data=self._form)
        resp = owner_client.post("/email/delete", follow_redirects=True)
        assert _flashed(resp, "Email balance update settings removed")
        app_ctx.session.expire_all()
        assert web_models.Email.query.filter_by(user_id=owner).count() == 0

    def test_delete_when_none_configured(self, owner_client):
        resp = owner_client.post("/email/delete", follow_redirects=True)
        assert _flashed(resp, "No email balance update settings to remove")


class TestGlobalEmailSettings:
    @pytest.fixture(autouse=True)
    def _clean(self, app_ctx, web_models):
        web_models.GlobalEmailSettings.query.delete()
        app_ctx.session.commit()
        yield
        web_models.GlobalEmailSettings.query.delete()
        app_ctx.session.commit()

    def test_create_then_update_keeps_password_when_blank(self, global_client, web_models, app_ctx):
        resp = global_client.post(
            "/global_email_settings",
            data={"email": "noreply@example.com", "password": "smtp-pass", "smtp_server": "smtp.example.com"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Global email settings saved successfully")
        global_client.post(
            "/global_email_settings",
            data={"email": "alerts@example.com", "password": "", "smtp_server": "smtp2.example.com"},
        )
        app_ctx.session.expire_all()
        row = web_models.GlobalEmailSettings.query.one()
        assert row.email == "alerts@example.com"
        assert row.smtp_server == "smtp2.example.com"
        assert decrypt_password(row.password) == "smtp-pass"

    def test_non_global_admin_forbidden(self, owner_client, web_models):
        owner_client.post(
            "/global_email_settings",
            data={"email": "x@example.com", "password": "p", "smtp_server": "s"},
        )
        assert web_models.GlobalEmailSettings.query.count() == 0


# ── AI settings & on-demand insights ─────────────────────────────────────────


_VALID_INSIGHTS = json.dumps({"insights": [
    {"type": "cash_risk", "severity": "low", "title": "Healthy", "description": "All good."}
]})


@pytest.fixture()
def no_do_provider(monkeypatch):
    monkeypatch.delenv("DO_AI_BASE_URL", raising=False)
    monkeypatch.delenv("DO_AI_API_KEY", raising=False)


@pytest.mark.usefixtures("no_do_provider")
class TestAISettings:
    def test_empty_key_without_existing_rejected(self, owner, owner_client, web_models):
        resp = owner_client.post("/ai_settings", data={"api_key": ""}, follow_redirects=True)
        assert _flashed(resp, "API key cannot be empty")
        assert web_models.AISettings.query.filter_by(user_id=owner).count() == 0

    def test_save_key_stores_encrypted(self, owner, owner_client, web_models):
        resp = owner_client.post("/ai_settings", data={"api_key": "sk-test-123"}, follow_redirects=True)
        assert _flashed(resp, "AI settings saved successfully")
        row = web_models.AISettings.query.filter_by(user_id=owner).one()
        assert row.api_key != "sk-test-123"
        assert decrypt_password(row.api_key) == "sk-test-123"
        assert row.model_version is None

    def test_invalid_model_rejected(self, owner, owner_client, main_module, monkeypatch, web_models):
        monkeypatch.setattr(main_module, "validate_model", lambda key, model: (False, "Model not found"))
        resp = owner_client.post("/ai_settings", data={"api_key": "sk-x", "model_version": "gpt-nope"},
                                 follow_redirects=True)
        assert _flashed(resp, "Model not found")
        assert web_models.AISettings.query.filter_by(user_id=owner).count() == 0

    def test_model_only_update_uses_stored_key(self, owner, owner_client, main_module,
                                               monkeypatch, web_models, app_ctx):
        app_ctx.session.add(web_models.AISettings(user_id=owner, api_key=encrypt_password("sk-stored")))
        app_ctx.session.commit()
        seen = {}

        def _validate(key, model):
            seen["key"], seen["model"] = key, model
            return True, None

        monkeypatch.setattr(main_module, "validate_model", _validate)
        owner_client.post("/ai_settings", data={"api_key": "", "model_version": "gpt-4o"})
        assert seen == {"key": "sk-stored", "model": "gpt-4o"}
        app_ctx.session.expire_all()
        assert web_models.AISettings.query.filter_by(user_id=owner).one().model_version == "gpt-4o"

    def test_remove_key(self, owner, owner_client, web_models, app_ctx):
        app_ctx.session.add(web_models.AISettings(user_id=owner, api_key=encrypt_password("sk"),
                                                  model_version="gpt-4o"))
        app_ctx.session.commit()
        resp = owner_client.post("/ai_settings/remove", follow_redirects=True)
        assert _flashed(resp, "OpenAI API key removed")
        app_ctx.session.expire_all()
        row = web_models.AISettings.query.filter_by(user_id=owner).one()
        assert row.api_key is None and row.model_version is None

    def test_guest_cannot_save_ai_settings(self, owner, guest_of, login_as, web_models):
        guest = guest_of(owner)
        login_as(guest).post("/ai_settings", data={"api_key": "sk-guest"})
        assert web_models.AISettings.query.filter_by(user_id=guest).count() == 0


@pytest.mark.usefixtures("no_do_provider")
class TestAIInsightsEndpoint:
    @pytest.fixture()
    def configured(self, owner, app_ctx, web_models):
        app_ctx.session.add(web_models.AISettings(user_id=owner, api_key=encrypt_password("sk")))
        app_ctx.session.commit()
        return owner

    def test_no_provider_returns_400(self, owner_client):
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_success_caches_normalised_insights(self, configured, owner_client, main_module,
                                                monkeypatch, web_models, app_ctx):
        monkeypatch.setattr(main_module, "fetch_insights_for_provider",
                            lambda *a, **kw: _VALID_INSIGHTS)
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 200
        assert resp.get_json()["insights"][0]["title"] == "Healthy"
        app_ctx.session.expire_all()
        row = web_models.AISettings.query.filter_by(user_id=configured).one()
        assert json.loads(row.last_insights)["insights"][0]["title"] == "Healthy"
        assert row.last_updated is not None

    def test_recent_refresh_returns_cache_without_calling_provider(
        self, configured, owner_client, main_module, monkeypatch, web_models, app_ctx
    ):
        row = web_models.AISettings.query.filter_by(user_id=configured).one()
        row.last_insights = _VALID_INSIGHTS
        row.last_updated = datetime.now(timezone.utc)
        app_ctx.session.commit()

        def _should_not_run(*a, **kw):
            raise AssertionError("provider should not be called inside the refresh window")

        monkeypatch.setattr(main_module, "fetch_insights_for_provider", _should_not_run)
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 200
        assert resp.get_json()["insights"][0]["title"] == "Healthy"

    def test_provider_error_returns_502(self, configured, owner_client, main_module, monkeypatch):
        def _raise(*a, **kw):
            raise main_module.AIProviderError("Your API key was rejected.")

        monkeypatch.setattr(main_module, "fetch_insights_for_provider", _raise)
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 502
        assert resp.get_json()["error"]

    def test_malformed_payload_returns_502(self, configured, owner_client, main_module, monkeypatch):
        monkeypatch.setattr(main_module, "fetch_insights_for_provider", lambda *a, **kw: "not json")
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "AI returned invalid JSON."

    def test_unexpected_error_returns_500(self, configured, owner_client, main_module, monkeypatch):
        def _raise(*a, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(main_module, "fetch_insights_for_provider", _raise)
        resp = owner_client.post("/ai_insights")
        assert resp.status_code == 500
        assert "boom" not in resp.get_data(as_text=True)


# ── Global admin panel & user administration ─────────────────────────────────


class TestGlobalAdminPanel:
    def test_panel_lists_users(self, global_client, make_user):
        make_user(email="listed-owner@test.local", name="Listed Owner")
        resp = global_client.get("/global_admin")
        assert resp.status_code == 200
        assert b"listed-owner@test.local" in resp.data

    def test_account_owner_forbidden(self, owner_client):
        resp = owner_client.get("/global_admin", follow_redirects=False)
        assert resp.headers["Location"].endswith("/")
        assert "Global admin access required" in _session_flashes(owner_client)


class TestCreateUser:
    @pytest.mark.parametrize(
        "role,admin,is_global",
        [("global_admin", True, True), ("admin", True, False), ("guest", False, False)],
    )
    def test_global_admin_creates_each_role(self, global_client, web_models, role, admin, is_global):
        email = f"created-{role}@test.local"
        resp = global_client.post(
            "/create_user",
            data={"name": f"Created {role}", "email": email.upper(), "password": "longenough", "role": role},
            follow_redirects=False,
        )
        assert resp.headers["Location"].endswith("/global_admin")
        user = web_models.User.query.filter_by(email=email).one()
        assert user.admin is admin
        assert user.is_global_admin is is_global
        assert user.is_active is True
        assert user.account_owner_id is None
        assert check_password_hash(user.password, "longenough")

    def test_account_owner_can_only_create_linked_guests(self, owner, owner_client, web_models):
        resp = owner_client.post(
            "/create_user",
            data={"name": "Owner Made", "email": "owner-made@test.local", "password": "longenough",
                  "role": "global_admin"},
            follow_redirects=False,
        )
        assert resp.headers["Location"].endswith("/manage_guests")
        user = web_models.User.query.filter_by(email="owner-made@test.local").one()
        assert user.admin is False
        assert user.is_global_admin is False
        assert user.account_owner_id == owner
        assert user.owner_user_id == owner

    @pytest.mark.parametrize(
        "form,message",
        [
            ({"name": "", "email": "a@test.local", "password": "longenough"}, "Name must be between"),
            ({"name": "N", "email": "", "password": "longenough"}, "Email must be between"),
            ({"name": "N", "email": "short-pw@test.local", "password": "short"}, "at least 8 characters"),
        ],
    )
    def test_validation_errors(self, global_client, web_models, form, message):
        global_client.post("/create_user", data=form)
        assert any(message in m for m in _session_flashes(global_client))
        if form["email"]:
            assert web_models.User.query.filter_by(email=form["email"]).count() == 0

    def test_duplicate_email_rejected(self, global_client, make_user, web_models):
        make_user(email="exists-already@test.local")
        global_client.post(
            "/create_user",
            data={"name": "Dup", "email": "Exists-Already@test.local", "password": "longenough"},
        )
        assert "User already exists" in _session_flashes(global_client)
        assert web_models.User.query.filter_by(email="exists-already@test.local").count() == 1


class TestUpdateUser:
    def test_owner_updates_own_guest(self, owner, owner_client, guest_of, fresh, web_models):
        guest = guest_of(owner)
        resp = owner_client.post(
            "/update_user",
            data={"id": guest, "name": "Guest Renamed", "email": "Guest-Renamed@Test.Local"},
            follow_redirects=False,
        )
        assert resp.headers["Location"].endswith("/manage_guests")
        user = fresh(web_models.User, guest)
        assert user.name == "Guest Renamed"
        assert user.email == "guest-renamed@test.local"

    def test_owner_cannot_update_someone_elses_guest(
        self, owner_client, make_user, guest_of, fresh, web_models
    ):
        other_owner = make_user()
        guest = guest_of(other_owner, name="Untouched")
        owner_client.post("/update_user", data={"id": guest, "name": "Hijack", "email": "hijack@test.local"})
        assert "You don't have permission to update this user" in _session_flashes(owner_client)
        assert fresh(web_models.User, guest).name == "Untouched"

    def test_unknown_user(self, owner_client):
        owner_client.post("/update_user", data={"id": 999999, "name": "X", "email": "x@test.local"})
        assert "User not found" in _session_flashes(owner_client)

    def test_email_collision_rejected(self, owner, owner_client, guest_of, make_user, fresh, web_models):
        make_user(email="collide@test.local")
        guest = guest_of(owner)
        owner_client.post("/update_user", data={"id": guest, "name": "G", "email": "collide@test.local"})
        assert "Email already exists" in _session_flashes(owner_client)
        assert fresh(web_models.User, guest).email != "collide@test.local"

    def test_global_admin_promotes_owner(self, global_client, make_user, fresh, web_models):
        target = make_user(is_active=False)
        global_client.post(
            "/update_user",
            data={"id": target, "name": "Promoted", "email": "promoted@test.local", "role": "global_admin"},
        )
        user = fresh(web_models.User, target)
        assert user.is_global_admin is True
        assert user.admin is True
        assert user.is_active is True  # global admins are always active

    def test_global_admin_demotes_to_admin(self, global_client, make_user, fresh, web_models):
        target = make_user(is_global_admin=True)
        global_client.post(
            "/update_user",
            data={"id": target, "name": "Demoted", "email": "demoted@test.local", "role": "admin"},
        )
        user = fresh(web_models.User, target)
        assert user.is_global_admin is False
        assert user.admin is True

    def test_get_redirects_by_role(self, owner_client, global_client):
        assert owner_client.get("/update_user").headers["Location"].endswith("/manage_guests")
        assert global_client.get("/update_user").headers["Location"].endswith("/global_admin")


class TestActivationAndReview:
    def test_owner_activates_guest_and_notifies(self, owner, owner_client, guest_of, main_module,
                                                monkeypatch, fresh, web_models):
        guest = guest_of(owner, is_active=False)
        notified = []
        monkeypatch.setattr(main_module, "send_account_activation_notification",
                            lambda name, email: notified.append(email))
        owner_client.post(f"/activate_user/{guest}")
        user = fresh(web_models.User, guest)
        assert user.is_active is True
        assert notified == [user.email]

    def test_activation_survives_notification_failure(self, owner, owner_client, guest_of,
                                                      main_module, monkeypatch, fresh, web_models):
        guest = guest_of(owner, is_active=False)

        def _boom(*a):
            raise RuntimeError("smtp down")

        monkeypatch.setattr(main_module, "send_account_activation_notification", _boom)
        owner_client.post(f"/activate_user/{guest}")
        assert fresh(web_models.User, guest).is_active is True

    def test_owner_cannot_activate_unrelated_user(self, owner_client, make_user, fresh, web_models):
        stranger = make_user(is_active=False)
        owner_client.post(f"/activate_user/{stranger}")
        assert fresh(web_models.User, stranger).is_active is False

    def test_owner_deactivates_guest(self, owner, owner_client, guest_of, fresh, web_models):
        guest = guest_of(owner)
        owner_client.post(f"/deactivate_user/{guest}")
        assert fresh(web_models.User, guest).is_active is False

    def test_owner_cannot_deactivate_unrelated_user(self, owner_client, make_user, fresh, web_models):
        stranger = make_user()
        owner_client.post(f"/deactivate_user/{stranger}")
        assert fresh(web_models.User, stranger).is_active is True

    def test_global_admin_cannot_be_deactivated(self, global_client, make_user, fresh, web_models):
        other_admin = make_user(is_global_admin=True)
        global_client.post(f"/deactivate_user/{other_admin}")
        assert fresh(web_models.User, other_admin).is_active is True
        assert any("Cannot deactivate a global admin" in m for m in _session_flashes(global_client))

    def test_global_admin_deactivates_owner(self, global_client, make_user, fresh, web_models):
        target = make_user()
        global_client.post(f"/deactivate_user/{target}")
        assert fresh(web_models.User, target).is_active is False

    def test_toggle_review_user(self, global_client, make_user, fresh, web_models):
        target = make_user(is_active=False)
        global_client.post(f"/toggle_review_user/{target}")
        user = fresh(web_models.User, target)
        assert user.is_review_user is True
        assert user.is_active is True
        global_client.post(f"/toggle_review_user/{target}")
        assert fresh(web_models.User, target).is_review_user is False

    def test_toggle_review_rejects_guests_and_unknown(self, global_client, make_user, guest_of,
                                                      fresh, web_models):
        guest = guest_of(make_user())
        global_client.post(f"/toggle_review_user/{guest}")
        assert not fresh(web_models.User, guest).is_review_user
        global_client.post("/toggle_review_user/999999")
        flashes = _session_flashes(global_client)
        assert "Reviewer flag can only be toggled on account owners" in flashes
        assert "User not found" in flashes

    def test_toggle_review_requires_global_admin(self, owner_client, make_user, fresh, web_models):
        target = make_user()
        owner_client.post(f"/toggle_review_user/{target}")
        assert not fresh(web_models.User, target).is_review_user


class TestDeleteUser:
    def test_owner_deletes_own_guest_and_their_data(self, owner, owner_client, guest_of,
                                                    app_ctx, web_models, fresh):
        guest = guest_of(owner)
        app_ctx.session.add(web_models.PasskeyCredential(
            user_id=guest, credential_id="guest-del-cred", public_key="pk"))
        app_ctx.session.commit()
        resp = owner_client.post(f"/delete_user/{guest}", follow_redirects=False)
        assert resp.headers["Location"].endswith("/manage_guests")
        assert fresh(web_models.User, guest) is None
        assert web_models.PasskeyCredential.query.filter_by(credential_id="guest-del-cred").count() == 0

    def test_owner_cannot_delete_unrelated_user(self, owner_client, make_user, fresh, web_models):
        stranger = make_user()
        owner_client.post(f"/delete_user/{stranger}")
        assert "You don't have permission to delete this user" in _session_flashes(owner_client)
        assert fresh(web_models.User, stranger) is not None

    def test_global_admin_cannot_delete_self(self, global_admin, global_client, fresh, web_models):
        global_client.post(f"/delete_user/{global_admin}")
        assert "You cannot delete your own account" in _session_flashes(global_client)
        assert fresh(web_models.User, global_admin) is not None


class TestDeleteMyAccount:
    def test_owner_deletes_account_guests_and_data(self, make_user, guest_of, login_as,
                                                    app_ctx, web_models, fresh):
        owner = make_user(email="self-delete@test.local", balance="10.00")
        guest = guest_of(owner)
        app_ctx.session.add(web_models.Schedule(user_id=owner, name="Gone", amount="1",
                                                type="Expense", frequency="Monthly"))
        app_ctx.session.commit()
        c = login_as(owner)

        resp = c.post("/delete_my_account",
                      data={"username": "Self-Delete@Test.Local", "password": "testpass123"},
                      follow_redirects=False)
        assert "/login" in resp.headers["Location"]
        assert fresh(web_models.User, owner) is None
        assert fresh(web_models.User, guest) is None
        assert web_models.Schedule.query.filter_by(user_id=owner).count() == 0
        assert web_models.Balance.query.filter_by(user_id=owner).count() == 0
        assert "/login" in c.get("/", follow_redirects=False).headers["Location"]

    @pytest.mark.parametrize(
        "username,password",
        [("wrong@test.local", "testpass123"), ("{own}", "wrong"), ("", "")],
    )
    def test_bad_confirmation_keeps_account(self, make_user, login_as, fresh, web_models,
                                            username, password):
        owner = make_user()
        own_email = fresh(web_models.User, owner).email
        c = login_as(owner)
        c.post("/delete_my_account",
               data={"username": username.replace("{own}", own_email), "password": password})
        assert "Username or password is incorrect" in _session_flashes(c)
        assert fresh(web_models.User, owner) is not None

    def test_guest_cannot_use_self_delete(self, owner, guest_of, login_as, fresh, web_models, app_ctx):
        guest = guest_of(owner)
        email = app_ctx.session.get(web_models.User, guest).email
        c = login_as(guest)
        c.post("/delete_my_account", data={"username": email, "password": "testpass123"})
        assert "Account owner access required" in _session_flashes(c)
        assert fresh(web_models.User, guest) is not None


# ── Guest management by account owners ───────────────────────────────────────


class TestManageGuests:
    def test_lists_only_own_guests(self, owner, owner_client, make_user, guest_of):
        guest_of(owner, name="My Guest Person")
        guest_of(make_user(), name="Other Guest Person")
        resp = owner_client.get("/manage_guests")
        assert resp.status_code == 200
        assert b"My Guest Person" in resp.data
        assert b"Other Guest Person" not in resp.data

    def test_remove_own_guest(self, owner, owner_client, guest_of, fresh, web_models):
        guest = guest_of(owner)
        resp = owner_client.post(f"/remove_guest/{guest}", follow_redirects=True)
        assert _flashed(resp, "Guest user removed successfully")
        assert fresh(web_models.User, guest) is None

    def test_cannot_remove_other_owners_guest(self, owner_client, make_user, guest_of, fresh, web_models):
        guest = guest_of(make_user())
        resp = owner_client.post(f"/remove_guest/{guest}", follow_redirects=True)
        assert _flashed(resp, "Guest user not found")
        assert fresh(web_models.User, guest) is not None

    def test_legacy_guest_password_route_redirects(self, owner_client):
        resp = owner_client.get("/guest_password", follow_redirects=False)
        assert resp.headers["Location"].endswith("/manage_guests")

    @pytest.mark.parametrize(
        "form,message",
        [
            ({"name": "", "email": "g@test.local"}, "Name must be between"),
            ({"name": "G", "email": ""}, "Email must be between"),
        ],
    )
    def test_add_guest_validation(self, owner_client, form, message):
        resp = owner_client.post("/add_guest", data=form, follow_redirects=True)
        assert _flashed(resp, message)

    def test_add_guest_duplicate_email(self, owner_client, make_user):
        make_user(email="guest-dupe@test.local")
        resp = owner_client.post("/add_guest", data={"name": "G", "email": "guest-dupe@test.local"},
                                 follow_redirects=True)
        assert _flashed(resp, "A user with this email already exists")

    def test_add_guest_email_failure_still_creates_guest(self, owner, owner_client, flask_app,
                                                         main_module, monkeypatch, web_models):
        monkeypatch.setitem(flask_app.config, "FRONTEND_BASE_URL", "https://app.example.com")
        monkeypatch.setattr(main_module, "send_password_setup_email", lambda **kw: False)
        resp = owner_client.post("/add_guest", data={"name": "G", "email": "guest-nomail@test.local"},
                                 follow_redirects=True)
        assert _flashed(resp, "setup email could not be sent")
        guest = web_models.User.query.filter_by(email="guest-nomail@test.local").one()
        assert guest.owner_user_id == owner
        assert guest.admin is False

    def test_guest_cannot_manage_guests(self, owner, guest_of, login_as):
        c = login_as(guest_of(owner))
        resp = c.post("/add_guest", data={"name": "G", "email": "nested@test.local"},
                      follow_redirects=False)
        assert resp.headers["Location"].endswith("/")
        assert "Account owner access required" in _session_flashes(c)
