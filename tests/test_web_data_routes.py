"""
Web route tests for the data-management pages in app/main.py.

Covers the server-rendered CRUD flows that the original route tests only
touched lightly: schedule update/delete, holds and skips, scenario
update/delete, balance entry, the transactions table, CSV import/export,
the dashboard for owners and guests, Plaid live-refresh flash messages, and
the public PWA/static assets.

Every test creates its own users through the ``make_user`` fixture so the
assertions don't depend on the shared seeded admin, whose flags other test
modules mutate.
"""

import io
from datetime import date, timedelta

import pytest


def _flashed(resp, keyword):
    return keyword.lower().encode() in resp.data.lower()


def _schedule_form(**overrides):
    form = {
        "name": "Rent",
        "amount": "1200.00",
        "type": "Expense",
        "frequency": "Monthly",
        "startdate": (date.today() + timedelta(days=5)).isoformat(),
    }
    form.update(overrides)
    return form


@pytest.fixture()
def owner(make_user):
    return make_user(balance="5000.00")


@pytest.fixture()
def owner_client(owner, login_as):
    return login_as(owner)


@pytest.fixture()
def add_schedule(app_ctx, web_models):
    def _add(user_id, name="Rent", amount="1200.00", type_="Expense",
             frequency="Monthly", startdate=None):
        startdate = startdate or (date.today() + timedelta(days=5))
        row = web_models.Schedule(
            user_id=user_id, name=name, amount=amount, type=type_,
            frequency=frequency, startdate=startdate, firstdate=startdate,
        )
        app_ctx.session.add(row)
        app_ctx.session.commit()
        return row.id

    return _add


@pytest.fixture()
def add_scenario(app_ctx, web_models):
    def _add(user_id, name="Bonus", amount="500.00", type_="Income",
             frequency="Onetime", startdate=None):
        startdate = startdate or (date.today() + timedelta(days=10))
        row = web_models.Scenario(
            user_id=user_id, name=name, amount=amount, type=type_,
            frequency=frequency, startdate=startdate, firstdate=startdate,
        )
        app_ctx.session.add(row)
        app_ctx.session.commit()
        return row.id

    return _add


# ── Schedules ────────────────────────────────────────────────────────────────


class TestScheduleCreate:
    def test_create_persists_schedule_for_current_user(
        self, owner, owner_client, web_models, app_ctx
    ):
        resp = owner_client.post("/create", data=_schedule_form(), follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/schedule")

        row = web_models.Schedule.query.filter_by(user_id=owner, name="Rent").one()
        assert str(row.amount) == "1200.00"
        assert row.type == "Expense"
        assert row.frequency == "Monthly"
        assert row.startdate == row.firstdate

    def test_create_strips_whitespace_from_name(self, owner, owner_client, web_models):
        owner_client.post("/create", data=_schedule_form(name="  Gym  "))
        assert web_models.Schedule.query.filter_by(user_id=owner, name="Gym").count() == 1

    def test_create_rejects_name_over_max_length(self, owner, owner_client, web_models):
        resp = owner_client.post(
            "/create", data=_schedule_form(name="x" * 101), follow_redirects=True
        )
        assert _flashed(resp, "Name must be between 1 and 100 characters")
        assert web_models.Schedule.query.filter_by(user_id=owner).count() == 0

    def test_same_name_allowed_for_different_users(
        self, owner_client, make_user, login_as, web_models, owner
    ):
        other = make_user(balance="100.00")
        owner_client.post("/create", data=_schedule_form(name="Shared Name"))
        login_as(other).post("/create", data=_schedule_form(name="Shared Name"))
        assert web_models.Schedule.query.filter_by(name="Shared Name", user_id=owner).count() == 1
        assert web_models.Schedule.query.filter_by(name="Shared Name", user_id=other).count() == 1

    def test_get_create_redirects_to_schedule(self, owner_client):
        resp = owner_client.get("/create", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/schedule")


class TestScheduleTable:
    def test_schedule_page_lists_only_own_schedules(
        self, owner, owner_client, make_user, add_schedule
    ):
        other = make_user()
        add_schedule(owner, name="Mine Visible")
        add_schedule(other, name="Theirs Hidden")

        resp = owner_client.get("/schedule")
        assert resp.status_code == 200
        assert b"Mine Visible" in resp.data
        assert b"Theirs Hidden" not in resp.data


class TestScheduleUpdate:
    def test_update_changes_all_fields(
        self, owner, owner_client, add_schedule, fresh, web_models
    ):
        sid = add_schedule(owner, name="Phone")
        new_start = date.today() + timedelta(days=12)
        resp = owner_client.post(
            "/update",
            data={
                "id": sid,
                "name": "Mobile Phone",
                "amount": "85.50",
                "type": "Expense",
                "frequency": "BiWeekly",
                "startdate": new_start.isoformat(),
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert _flashed(resp, "Updated Successfully")

        row = fresh(web_models.Schedule, sid)
        assert row.name == "Mobile Phone"
        assert str(row.amount) == "85.50"
        assert row.frequency == "BiWeekly"
        assert row.startdate == new_start

    def test_update_new_day_of_month_resets_firstdate(
        self, owner, owner_client, add_schedule, fresh, web_models
    ):
        start = date(2030, 1, 10)
        sid = add_schedule(owner, name="Insurance", startdate=start)
        owner_client.post(
            "/update",
            data={"id": sid, "name": "Insurance", "amount": "100", "type": "Expense",
                  "frequency": "Monthly", "startdate": "2030-01-15"},
        )
        row = fresh(web_models.Schedule, sid)
        assert row.startdate == date(2030, 1, 15)
        assert row.firstdate == date(2030, 1, 15)

    def test_update_same_day_of_month_keeps_firstdate(
        self, owner, owner_client, add_schedule, fresh, web_models
    ):
        start = date(2030, 1, 10)
        sid = add_schedule(owner, name="Water", startdate=start)
        owner_client.post(
            "/update",
            data={"id": sid, "name": "Water", "amount": "40", "type": "Expense",
                  "frequency": "Monthly", "startdate": "2030-02-10"},
        )
        row = fresh(web_models.Schedule, sid)
        assert row.startdate == date(2030, 2, 10)
        assert row.firstdate == start

    def test_update_rejects_rename_to_existing_name(
        self, owner, owner_client, add_schedule, fresh, web_models
    ):
        add_schedule(owner, name="Taken")
        sid = add_schedule(owner, name="Original")
        resp = owner_client.post(
            "/update",
            data={"id": sid, "name": "Taken", "amount": "1", "type": "Expense",
                  "frequency": "Monthly", "startdate": "2030-01-01"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Schedule name already exists")
        assert fresh(web_models.Schedule, sid).name == "Original"

    @pytest.mark.parametrize(
        "field,value,message",
        [
            ("name", "", "Name must be between"),
            ("amount", "abc", "Amount must be a number"),
            ("type", "Transfer", "Invalid type"),
            ("frequency", "Daily", "Invalid frequency"),
        ],
    )
    def test_update_validation_errors(
        self, owner, owner_client, add_schedule, fresh, web_models, field, value, message
    ):
        sid = add_schedule(owner, name="Validate Me")
        form = {"id": sid, "name": "Validate Me", "amount": "10", "type": "Expense",
                "frequency": "Monthly", "startdate": "2030-01-01"}
        form[field] = value
        resp = owner_client.post("/update", data=form, follow_redirects=True)
        assert _flashed(resp, message)
        assert str(fresh(web_models.Schedule, sid).amount) == "1200.00"

    def test_update_cannot_modify_another_users_schedule(
        self, owner_client, make_user, add_schedule, fresh, web_models
    ):
        other = make_user()
        sid = add_schedule(other, name="Not Yours")
        resp = owner_client.post(
            "/update",
            data={"id": sid, "name": "Hijacked", "amount": "1", "type": "Expense",
                  "frequency": "Monthly", "startdate": "2030-01-01"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert _flashed(resp, "Schedule not found")
        assert fresh(web_models.Schedule, sid).name == "Not Yours"

    def test_get_update_redirects_to_schedule(self, owner_client):
        resp = owner_client.get("/update", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/schedule")


class TestScheduleDelete:
    def test_delete_removes_own_schedule(self, owner, owner_client, add_schedule, fresh, web_models):
        sid = add_schedule(owner, name="Delete Me")
        resp = owner_client.post(f"/delete/{sid}", follow_redirects=True)
        assert _flashed(resp, "Deleted Successfully")
        assert fresh(web_models.Schedule, sid) is None

    def test_delete_ignores_another_users_schedule(
        self, owner_client, make_user, add_schedule, fresh, web_models
    ):
        other = make_user()
        sid = add_schedule(other, name="Keep Me")
        resp = owner_client.post(f"/delete/{sid}", follow_redirects=False)
        assert resp.status_code == 302
        assert fresh(web_models.Schedule, sid) is not None

    def test_delete_requires_post(self, owner, owner_client, add_schedule):
        sid = add_schedule(owner)
        assert owner_client.get(f"/delete/{sid}").status_code == 405


# ── Holds & skips ────────────────────────────────────────────────────────────


class TestHolds:
    def test_addhold_copies_schedule_fields(self, owner, owner_client, add_schedule, web_models):
        sid = add_schedule(owner, name="Netflix", amount="15.99", type_="Expense")
        resp = owner_client.post(f"/addhold/{sid}", follow_redirects=True)
        assert _flashed(resp, "Added Hold")

        hold = web_models.Hold.query.filter_by(user_id=owner, name="Netflix").one()
        assert str(hold.amount) == "15.99"
        assert hold.type == "Expense"

    def test_addhold_for_another_users_schedule_is_rejected(
        self, owner, owner_client, make_user, add_schedule, web_models
    ):
        other = make_user()
        sid = add_schedule(other, name="Other Hold Target")
        resp = owner_client.post(f"/addhold/{sid}", follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, "Schedule not found")
        assert web_models.Hold.query.filter_by(user_id=owner).count() == 0
        assert web_models.Hold.query.filter_by(user_id=other).count() == 0

    def test_holds_page_lists_holds_and_skips(self, owner, owner_client, app_ctx, web_models):
        app_ctx.session.add(web_models.Hold(user_id=owner, name="Held Item", amount="1", type="Expense"))
        app_ctx.session.add(web_models.Skip(user_id=owner, name="Skipped Item (SKIP)", amount="2",
                                            type="Income", date=date.today()))
        app_ctx.session.commit()
        resp = owner_client.get("/holds")
        assert resp.status_code == 200
        assert b"Held Item" in resp.data
        assert b"Skipped Item (SKIP)" in resp.data

    def test_deletehold_only_removes_own(self, owner, owner_client, make_user, app_ctx, web_models, fresh):
        other = make_user()
        mine = web_models.Hold(user_id=owner, name="Mine", amount="1", type="Expense")
        theirs = web_models.Hold(user_id=other, name="Theirs", amount="1", type="Expense")
        app_ctx.session.add_all([mine, theirs])
        app_ctx.session.commit()
        mine_id, theirs_id = mine.id, theirs.id

        owner_client.post(f"/deletehold/{mine_id}")
        owner_client.post(f"/deletehold/{theirs_id}")
        assert fresh(web_models.Hold, mine_id) is None
        assert fresh(web_models.Hold, theirs_id) is not None

    def test_clearholds_only_clears_own(self, owner, owner_client, make_user, app_ctx, web_models):
        other = make_user()
        app_ctx.session.add_all([
            web_models.Hold(user_id=owner, name="A", amount="1", type="Expense"),
            web_models.Hold(user_id=owner, name="B", amount="1", type="Expense"),
            web_models.Hold(user_id=other, name="C", amount="1", type="Expense"),
        ])
        app_ctx.session.commit()

        resp = owner_client.post("/clearholds", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/holds")
        app_ctx.session.expire_all()
        assert web_models.Hold.query.filter_by(user_id=owner).count() == 0
        assert web_models.Hold.query.filter_by(user_id=other).count() == 1


class TestSkips:
    def test_addskip_records_inverted_transaction(self, owner, owner_client, add_schedule, web_models):
        add_schedule(owner, name="Paycheck", amount="2000.00", type_="Income",
                     frequency="Monthly", startdate=date.today() + timedelta(days=3))
        # Transactions are sorted by date, so index 0 is the first Paycheck.
        page = owner_client.get("/transactions")
        assert page.status_code == 200
        assert b"Paycheck" in page.data

        resp = owner_client.post("/addskip/0", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/transactions")

        skip = web_models.Skip.query.filter_by(user_id=owner).one()
        assert skip.name == "Paycheck (SKIP)"
        assert skip.type == "Expense"  # inverted so the skip offsets the income
        assert str(skip.amount) == "2000.00"
        # The engine may shift weekend dates earlier, so only bound the date.
        assert date.today() < skip.date <= date.today() + timedelta(days=3)

    def test_skip_offset_entry_hidden_from_transactions_table(
        self, owner, owner_client, add_schedule, web_models
    ):
        add_schedule(owner, name="OneOff", amount="50", type_="Expense",
                     frequency="Onetime", startdate=date.today() + timedelta(days=2))
        owner_client.post("/addskip/0")
        assert web_models.Skip.query.filter_by(user_id=owner, name="OneOff (SKIP)").count() == 1
        # The offsetting "(SKIP)" row affects the running balance but is never
        # listed as an upcoming transaction.
        assert b"(SKIP)" not in owner_client.get("/transactions").data

    def test_addskip_unknown_index_is_rejected(self, owner, owner_client, web_models):
        resp = owner_client.post("/addskip/99", follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, "Transaction not found")
        assert web_models.Skip.query.filter_by(user_id=owner).count() == 0

    def test_deleteskip_and_clearskips_scoped_to_user(
        self, owner, owner_client, make_user, app_ctx, web_models, fresh
    ):
        other = make_user()
        rows = [
            web_models.Skip(user_id=owner, name="S1", amount="1", type="Income", date=date.today()),
            web_models.Skip(user_id=owner, name="S2", amount="1", type="Income", date=date.today()),
            web_models.Skip(user_id=other, name="S3", amount="1", type="Income", date=date.today()),
        ]
        app_ctx.session.add_all(rows)
        app_ctx.session.commit()
        s1, s3 = rows[0].id, rows[2].id

        owner_client.post(f"/deleteskip/{s1}")
        owner_client.post(f"/deleteskip/{s3}")
        assert fresh(web_models.Skip, s1) is None
        assert fresh(web_models.Skip, s3) is not None

        owner_client.post("/clearskips")
        app_ctx.session.expire_all()
        assert web_models.Skip.query.filter_by(user_id=owner).count() == 0
        assert web_models.Skip.query.filter_by(user_id=other).count() == 1


class TestTransactions:
    def test_transactions_lists_upcoming_items(self, owner, owner_client, add_schedule):
        add_schedule(owner, name="Electric", frequency="Monthly",
                     startdate=date.today() + timedelta(days=1))
        resp = owner_client.get("/transactions")
        assert resp.status_code == 200
        assert b"Electric" in resp.data

    def test_transactions_without_balance_does_not_crash(self, make_user, login_as):
        uid = make_user()  # no balance row yet
        resp = login_as(uid).get("/transactions")
        assert resp.status_code == 200


# ── Scenarios ────────────────────────────────────────────────────────────────


class TestScenarios:
    def test_create_scenario_persists(self, owner, owner_client, web_models):
        owner_client.post("/create_scenario", data=_schedule_form(name="Vacation", type="Expense"))
        assert web_models.Scenario.query.filter_by(user_id=owner, name="Vacation").count() == 1

    def test_create_duplicate_scenario_rejected(self, owner, owner_client, add_scenario, web_models):
        add_scenario(owner, name="Dup")
        resp = owner_client.post("/create_scenario", data=_schedule_form(name="Dup"),
                                 follow_redirects=True)
        assert _flashed(resp, "Scenario already exists")
        assert web_models.Scenario.query.filter_by(user_id=owner, name="Dup").count() == 1

    @pytest.mark.parametrize(
        "field,value,message",
        [("amount", "x", "Amount must be a number"), ("frequency", "Hourly", "Invalid frequency")],
    )
    def test_create_scenario_validation(self, owner, owner_client, web_models, field, value, message):
        resp = owner_client.post("/create_scenario", data=_schedule_form(**{field: value}),
                                 follow_redirects=True)
        assert _flashed(resp, message)
        assert web_models.Scenario.query.filter_by(user_id=owner).count() == 0

    def test_scenarios_page_lists_only_own(self, owner, owner_client, make_user, add_scenario):
        other = make_user()
        add_scenario(owner, name="My Scenario")
        add_scenario(other, name="Their Scenario")
        resp = owner_client.get("/scenarios")
        assert b"My Scenario" in resp.data
        assert b"Their Scenario" not in resp.data

    def test_update_scenario(self, owner, owner_client, add_scenario, fresh, web_models):
        scid = add_scenario(owner, name="Raise")
        resp = owner_client.post(
            "/update_scenario",
            data={"id": scid, "name": "Big Raise", "amount": "750", "type": "Income",
                  "frequency": "Monthly", "startdate": "2030-03-01"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Updated Successfully")
        row = fresh(web_models.Scenario, scid)
        assert row.name == "Big Raise"
        assert str(row.amount) == "750.00"
        assert row.frequency == "Monthly"

    def test_update_scenario_rejects_existing_name(self, owner, owner_client, add_scenario, fresh, web_models):
        add_scenario(owner, name="Existing")
        scid = add_scenario(owner, name="Renamed")
        resp = owner_client.post(
            "/update_scenario",
            data={"id": scid, "name": "Existing", "amount": "1", "type": "Income",
                  "frequency": "Monthly", "startdate": "2030-03-01"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Scenario name already exists")
        assert fresh(web_models.Scenario, scid).name == "Renamed"

    def test_update_scenario_of_other_user_not_found(
        self, owner_client, make_user, add_scenario, fresh, web_models
    ):
        other = make_user()
        scid = add_scenario(other, name="Private Scenario")
        resp = owner_client.post(
            "/update_scenario",
            data={"id": scid, "name": "Stolen", "amount": "1", "type": "Income",
                  "frequency": "Monthly", "startdate": "2030-03-01"},
            follow_redirects=True,
        )
        assert _flashed(resp, "Scenario not found")
        assert fresh(web_models.Scenario, scid).name == "Private Scenario"

    def test_delete_scenario_scoped_to_user(
        self, owner, owner_client, make_user, add_scenario, fresh, web_models
    ):
        other = make_user()
        mine = add_scenario(owner, name="Drop")
        theirs = add_scenario(other, name="Stay")
        owner_client.post(f"/delete_scenario/{mine}")
        owner_client.post(f"/delete_scenario/{theirs}")
        assert fresh(web_models.Scenario, mine) is None
        assert fresh(web_models.Scenario, theirs) is not None

    def test_scenario_get_endpoints_redirect(self, owner_client):
        for path in ("/create_scenario", "/update_scenario"):
            resp = owner_client.get(path, follow_redirects=False)
            assert resp.status_code == 302
            assert resp.headers["Location"].endswith("/scenarios")


# ── Balance ──────────────────────────────────────────────────────────────────


class TestBalance:
    def test_post_balance_for_new_date_adds_row(self, owner, owner_client, web_models):
        yesterday = date.today() - timedelta(days=1)
        resp = owner_client.post(
            "/balance", data={"amount": "4321.00", "date": yesterday.isoformat()},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        rows = web_models.Balance.query.filter_by(user_id=owner).all()
        assert {r.date for r in rows} == {date.today(), yesterday}

    def test_latest_balance_drives_dashboard(self, owner, owner_client):
        owner_client.post("/balance", data={"amount": "7777.77", "date": date.today().isoformat()})
        resp = owner_client.get("/")
        assert resp.status_code == 200
        assert b"7777.77" in resp.data or b"7,777.77" in resp.data

    def test_get_balance_redirects_to_dashboard(self, owner_client):
        resp = owner_client.get("/balance", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")


# ── Dashboard ────────────────────────────────────────────────────────────────


class TestDashboard:
    def test_dashboard_creates_zero_balance_for_new_user(self, make_user, login_as, web_models):
        uid = make_user()
        resp = login_as(uid).get("/")
        assert resp.status_code == 200
        balance = web_models.Balance.query.filter_by(user_id=uid).one()
        assert float(balance.amount) == 0.0

    def test_dashboard_renders_with_schedules_and_scenarios(
        self, owner, owner_client, add_schedule, add_scenario
    ):
        add_schedule(owner, name="Salary", amount="3000", type_="Income")
        add_schedule(owner, name="Mortgage", amount="1500", type_="Expense")
        add_scenario(owner, name="New Car", amount="400", type_="Expense", frequency="Monthly")
        resp = owner_client.get("/")
        assert resp.status_code == 200
        assert b"plotly" in resp.data.lower()

    def test_dashboard_shows_cached_ai_insights(
        self, owner, owner_client, app_ctx, web_models, monkeypatch
    ):
        monkeypatch.delenv("DO_AI_BASE_URL", raising=False)
        monkeypatch.delenv("DO_AI_API_KEY", raising=False)
        app_ctx.session.add(web_models.AISettings(
            user_id=owner,
            api_key="encrypted-placeholder",
            last_insights='{"insights": [{"type": "cash_risk", "severity": "low", '
                          '"title": "Cached Insight Title", "description": "desc"}]}',
        ))
        app_ctx.session.commit()
        resp = owner_client.get("/")
        assert resp.status_code == 200
        assert b"Cached Insight Title" in resp.data

    def test_dashboard_tolerates_corrupt_ai_cache(self, owner, owner_client, app_ctx, web_models):
        app_ctx.session.add(web_models.AISettings(user_id=owner, last_insights="{not json"))
        app_ctx.session.commit()
        assert owner_client.get("/").status_code == 200

    def test_guest_dashboard_shows_owner_balance(self, make_user, login_as):
        owner_id = make_user(balance="2468.00")
        guest_id = make_user(admin=False, owner_id=owner_id)
        resp = login_as(guest_id).get("/")
        assert resp.status_code == 200
        assert b"2468" in resp.data or b"2,468" in resp.data


# ── Guest (view-only) restrictions ───────────────────────────────────────────


class TestGuestRestrictions:
    @pytest.fixture()
    def guest_client(self, make_user, login_as):
        owner_id = make_user(balance="1000.00")
        guest_id = make_user(admin=False, owner_id=owner_id)
        self.owner_id = owner_id
        return login_as(guest_id)

    @pytest.mark.parametrize(
        "path",
        ["/schedule", "/holds", "/scenarios", "/transactions", "/export", "/manage_guests",
         "/global_admin"],
    )
    def test_guest_cannot_view_admin_pages(self, guest_client, path):
        resp = guest_client.get(path, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"].endswith("/")

    def test_guest_cannot_create_schedule(self, guest_client, web_models):
        resp = guest_client.post("/create", data=_schedule_form(name="Guest Write"),
                                 follow_redirects=False)
        assert resp.status_code == 302
        assert web_models.Schedule.query.filter_by(name="Guest Write").count() == 0

    def test_guest_cannot_post_balance(self, guest_client, web_models):
        guest_client.post("/balance", data={"amount": "1.00", "date": "2030-01-01"})
        assert web_models.Balance.query.filter_by(user_id=self.owner_id,
                                                  date=date(2030, 1, 1)).count() == 0

    def test_guest_cannot_delete_owner_schedule(self, guest_client, add_schedule, fresh, web_models):
        sid = add_schedule(self.owner_id, name="Owner Item")
        guest_client.post(f"/delete/{sid}")
        assert fresh(web_models.Schedule, sid) is not None

    def test_guest_settings_page_renders_guest_template(self, guest_client):
        resp = guest_client.get("/settings")
        assert resp.status_code == 200
        # The admin-only AI settings form is not part of the guest template.
        assert b'action="/ai_settings"' not in resp.data


# ── CSV export / import ──────────────────────────────────────────────────────


class TestExportImport:
    def test_export_returns_csv_of_own_schedules(self, owner, owner_client, make_user, add_schedule):
        other = make_user()
        add_schedule(owner, name="Export Me", amount="10.00")
        add_schedule(other, name="Not Exported")
        resp = owner_client.get("/export")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"
        assert "attachment" in resp.headers["Content-Disposition"]
        body = resp.data.decode()
        assert body.splitlines()[0] == "Name,Amount,Type,Frequency,Next Date,First Date"
        assert "Export Me" in body
        assert "Not Exported" not in body

    def test_export_neutralises_formula_injection(self, owner, owner_client, add_schedule):
        add_schedule(owner, name="=HYPERLINK(evil)")
        body = owner_client.get("/export").data.decode()
        assert "'=HYPERLINK(evil)" in body

    def test_import_creates_schedules(self, owner, owner_client, web_models):
        csv_bytes = (
            "Name,Amount,Type,Frequency,Next Date,First Date\n"
            "Imported Rent,900,Expense,Monthly,2030-01-01,2030-01-01\n"
            "Imported Pay,2500,Income,BiWeekly,2030-01-05,2030-01-05\n"
        ).encode()
        resp = owner_client.post(
            "/import",
            data={"file": (io.BytesIO(csv_bytes), "schedules.csv", "text/csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert _flashed(resp, "Import successful: 2 row(s) imported")
        names = {s.name for s in web_models.Schedule.query.filter_by(user_id=owner)}
        assert {"Imported Rent", "Imported Pay"} <= names

    def test_import_reports_skipped_rows(self, owner, owner_client):
        csv_bytes = (
            b"Name,Amount,Type,Frequency,Next Date,First Date\n"
            b"Good Row,10,Expense,Monthly,2030-01-01,2030-01-01\n"
            b"Bad Row,abc,Expense,Monthly,2030-01-01,2030-01-01\n"
        )
        resp = owner_client.post(
            "/import",
            data={"file": (io.BytesIO(csv_bytes), "mixed.csv", "text/csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert _flashed(resp, "1 row(s) imported, 1 row(s) skipped")

    def test_import_without_file_flashes_error(self, owner_client):
        resp = owner_client.post("/import", data={}, follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, "No file selected")

    def test_export_then_import_round_trip(self, owner, owner_client, make_user, login_as,
                                           add_schedule, web_models):
        add_schedule(owner, name="Round Trip", amount="321.00", type_="Income", frequency="Yearly")
        exported = owner_client.get("/export").data

        target = make_user()
        resp = login_as(target).post(
            "/import",
            data={"file": (io.BytesIO(exported), "export.csv", "text/csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        row = web_models.Schedule.query.filter_by(user_id=target, name="Round Trip").one()
        assert str(row.amount) == "321.00"
        assert row.frequency == "Yearly"


# ── Plaid live balance refresh (flash messaging) ─────────────────────────────


class TestRealtimeBalanceRefresh:
    @pytest.mark.parametrize(
        "result,message",
        [
            ({"status": "ok"}, "Live balance refreshed."),
            ({"status": "rate_limited", "retry_after_seconds": 7200}, "Try again in about 2 hour(s)"),
            ({"status": "skipped", "reason": "no_connection"}, "Connect a Plaid account"),
            ({"status": "skipped", "reason": "not_configured"}, "Live refresh is unavailable"),
            ({"status": "skipped", "reason": "no_balance_value"}, "did not return a balance"),
            ({"status": "error"}, "Live refresh is unavailable"),
        ],
    )
    def test_flash_message_per_status(self, owner_client, main_module, monkeypatch, result, message):
        monkeypatch.setattr(main_module, "realtime_update_plaid_balance_for_user", lambda _u: result)
        resp = owner_client.post("/refresh_realtime_balance", follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, message)

    def test_exception_is_reported_not_raised(self, owner_client, main_module, monkeypatch):
        def _boom(_u):
            raise RuntimeError("plaid down")

        monkeypatch.setattr(main_module, "realtime_update_plaid_balance_for_user", _boom)
        resp = owner_client.post("/refresh_realtime_balance", follow_redirects=True)
        assert resp.status_code == 200
        assert _flashed(resp, "Could not refresh balance from Plaid")


# ── Public assets ────────────────────────────────────────────────────────────


class TestPublicAssets:
    @pytest.mark.parametrize(
        "path,mimetype",
        [
            ("/favicon", "image/vnd.microsoft.icon"),
            ("/appleicon", "image/png"),
            ("/manifest.json", "application/manifest+json"),
            ("/sw.js", "application/javascript"),
            ("/offline.html", "text/html"),
        ],
    )
    def test_asset_served_without_login(self, client, path, mimetype):
        resp = client.get(path)
        assert resp.status_code == 200
        assert resp.mimetype == mimetype
        resp.close()
