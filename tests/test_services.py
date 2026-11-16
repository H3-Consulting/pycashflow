"""Tests for the shared service layer (app/services) used by REST and MCP."""

from datetime import date, timedelta
from decimal import Decimal

import pytest

# Module-level imports capture the real modules before any test stubs.
from app import db as _db
from app.models import Hold, Schedule, Skip, Scenario
from app.services import projections, records
from app.services.errors import ClarificationRequired, Conflict, NotFound, ValidationFailed
from app.services.validation import (
    parse_amount_strict,
    parse_date_strict,
    parse_name_strict,
    validate_balance_amount,
    validate_item_payload,
)
from app.api.auth_utils import create_token_for_user
from app.models import User


def _schedule(user_id, name="Rent", amount="1200.00", type_="Expense", frequency="Monthly", start=None):
    start = start or (date.today() + timedelta(days=10))
    row = Schedule(
        user_id=user_id, name=name, amount=amount, type=type_,
        frequency=frequency, startdate=start, firstdate=start,
    )
    _db.session.add(row)
    _db.session.commit()
    return row


# ── Validation ───────────────────────────────────────────────────────────────


class TestRestPayloadValidation:
    def _body(self, **overrides):
        body = {
            "name": "Rent", "amount": "100.00", "type": "Expense",
            "frequency": "Monthly", "start_date": date.today().isoformat(),
        }
        body.update(overrides)
        return body

    def test_valid_payload_has_no_errors(self):
        assert validate_item_payload(self._body()) == {}

    @pytest.mark.parametrize("amount", ["NaN", "nan", "Infinity", "-inf", "1e308", 1e300, True, "100000000"])
    def test_non_finite_or_out_of_range_amount_rejected(self, amount):
        assert "amount" in validate_item_payload(self._body(amount=amount))

    @pytest.mark.parametrize("amount", ["12.5", 12, "-40.00", "99999999.99"])
    def test_legacy_amounts_still_accepted(self, amount):
        # Negative amounts were historically accepted by REST and remain so.
        assert validate_item_payload(self._body(amount=amount)) == {}

    def test_original_messages_preserved(self):
        errors = validate_item_payload({"amount": "x"})
        assert errors["name"] == "Name must be between 1 and 100 characters"
        assert errors["amount"] == "Amount must be a number"
        assert errors["type"] == "Invalid type"
        assert errors["frequency"] == "Invalid frequency"
        assert errors["start_date"] == "start_date is required"

    def test_balance_amount_rejects_nan(self):
        assert validate_balance_amount("NaN") is not None
        assert validate_balance_amount("250.10") is None


class TestRestRejectsNonFiniteAmounts:
    def test_create_schedule_with_nan_returns_422(self, client, make_user, app_ctx):
        uid = make_user()
        token, _ = create_token_for_user(_db.session.get(User, uid))
        resp = client.post(
            "/api/v1/schedules",
            json={"name": "Bad", "amount": "NaN", "type": "Expense",
                  "frequency": "Monthly", "start_date": date.today().isoformat()},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422
        assert "amount" in resp.get_json()["fields"]
        assert Schedule.query.filter_by(user_id=uid).count() == 0

    def test_set_balance_with_infinity_returns_422(self, client, make_user, app_ctx):
        uid = make_user()
        token, _ = create_token_for_user(_db.session.get(User, uid))
        resp = client.post(
            "/api/v1/balance", json={"amount": "Infinity"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422


class TestStrictParsers:
    @pytest.mark.parametrize("value,expected", [
        ("125.50", Decimal("125.50")), (125.5, Decimal("125.50")), (40, Decimal("40.00")),
        ("$1,250.00", Decimal("1250.00")), ("99999999.99", Decimal("99999999.99")),
    ])
    def test_amount_accepts(self, value, expected):
        assert parse_amount_strict(value) == expected

    @pytest.mark.parametrize("value", [
        "NaN", "inf", float("nan"), float("inf"), "-5", 0, "0.00", "1.005", "100000000",
        True, None, [], {}, "1e3x", "9" * 40,
    ])
    def test_amount_rejects(self, value):
        with pytest.raises(ValidationFailed):
            parse_amount_strict(value)

    @pytest.mark.parametrize("value", [
        "", "   ", "x" * 101, "Rent\x00", "Line\nbreak", "Spoof‮", "Rent (SKIP)", "rent (skip) 2", 12,
    ])
    def test_name_rejects(self, value):
        with pytest.raises(ValidationFailed):
            parse_name_strict(value)

    def test_name_strips_and_accepts_unicode(self):
        assert parse_name_strict("  Café rent 🏠 ") == "Café rent 🏠"

    @pytest.mark.parametrize("value", ["2026-13-01", "26-01-01", "2026/01/01", 20260101, None, "9999-12-31", "0001-01-01"])
    def test_date_rejects(self, value):
        with pytest.raises(ValidationFailed):
            parse_date_strict(value, "start_date")

    def test_date_accepts_today(self):
        assert parse_date_strict(date.today().isoformat(), "d") == date.today()


# ── Projection pipeline ──────────────────────────────────────────────────────


class TestRunProjection:
    def test_maintenance_commit_deletes_expired_onetime_and_past_skip(self, make_user, app_ctx, fresh):
        uid = make_user(balance="1000.00")
        expired = _schedule(uid, name="Old one-time", frequency="Onetime",
                            start=date.today() - timedelta(days=3))
        future = _schedule(uid, name="Future one-time", frequency="Onetime",
                           start=date.today() + timedelta(days=3))
        past_skip = Skip(user_id=uid, name="X (SKIP)", type="Income", amount="1.00",
                         date=date.today() - timedelta(days=2))
        _db.session.add(past_skip)
        _db.session.commit()
        expired_id, future_id, skip_id = expired.id, future.id, past_skip.id

        result = projections.run_projection(uid)

        # The maintenance commit is persisted, not just staged.
        _db.session.rollback()
        assert fresh(Schedule, expired_id) is None
        assert fresh(Schedule, future_id) is not None
        assert fresh(Skip, skip_id) is None
        assert result.balance_amount == 1000.0

    def test_maintenance_advances_elapsed_weekly_start(self, make_user, app_ctx, fresh):
        uid = make_user(balance="500.00")
        start = date.today() - timedelta(days=14)
        row = _schedule(uid, name="Weekly", frequency="Weekly", start=start)
        projections.run_projection(uid)
        _db.session.rollback()
        stored = fresh(Schedule, row.id).startdate
        if date.today().weekday() < 5:
            assert stored > date.today() - timedelta(days=1)
        else:
            # The engine only advances dates on weekdays.
            assert stored == start

    def test_projection_only_touches_own_account(self, make_user, app_ctx, fresh):
        mine = make_user(balance="100.00")
        other = make_user(balance="100.00")
        theirs = _schedule(other, name="Their expired", frequency="Onetime",
                           start=date.today() - timedelta(days=5))
        projections.run_projection(mine)
        _db.session.rollback()
        assert fresh(Schedule, theirs.id) is not None

    def test_retries_once_after_concurrent_maintenance_race(self, make_user, app_ctx, monkeypatch):
        from sqlalchemy.orm.exc import StaleDataError

        uid = make_user(balance="10.00")
        real = projections.update_cash
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise StaleDataError("simulated concurrent delete")
            return real(*args, **kwargs)

        monkeypatch.setattr(projections, "update_cash", flaky)
        result = projections.run_projection(uid)
        assert calls["n"] == 2
        assert result.balance_amount == 10.0

    def test_second_race_propagates(self, make_user, app_ctx, monkeypatch):
        from sqlalchemy.orm.exc import StaleDataError

        uid = make_user()

        def always(*_a, **_k):
            raise StaleDataError("boom")

        monkeypatch.setattr(projections, "update_cash", always)
        with pytest.raises(StaleDataError):
            projections.run_projection(uid)

    def test_upcoming_occurrences_match_engine_transactions(self, make_user, app_ctx):
        uid = make_user(balance="3000.00")
        rent = _schedule(uid, name="Rent", amount="1200.00", start=date.today() + timedelta(days=5))
        _schedule(uid, name="Pay", amount="2000.00", type_="Income", frequency="BiWeekly",
                  start=date.today() + timedelta(days=3))
        _db.session.add(Hold(user_id=uid, name="Rent", type="Expense", amount="1200.00"))
        _db.session.commit()

        result = projections.run_projection(uid)
        schedules, holds, skips, _ = projections.load_inputs(uid)
        items = projections.upcoming_occurrences(schedules, holds, skips)

        engine = sorted(
            (r.name, r.date, f"{Decimal(str(r.amount)):.2f}") for r in result.trans.itertuples(index=False)
        )
        labelled = sorted((i["name"], i["date"], f"{Decimal(str(i['amount'])):.2f}") for i in items)
        assert labelled == engine
        assert any(i["source"] == "hold" and i["schedule_id"] == rent.id for i in items)

    def test_daily_balances_carry_forward(self):
        import pandas as pd

        today = date.today()
        run = pd.DataFrame([
            {"amount": 100.0, "date": today},
            {"amount": 40.0, "date": today + timedelta(days=2)},
        ])
        series = projections.daily_balances(run, today, today + timedelta(days=3))
        assert [v for _d, v in series] == [100.0, 100.0, 40.0, 40.0]
        stats = projections.series_stats(series)
        assert stats["minimum_balance"] == 40.0
        assert stats["minimum_balance_date"] == today + timedelta(days=2)
        periods = projections.shortfall_periods([(today, 5.0), (today + timedelta(days=1), -1.0)])
        assert periods[0]["days"] == 1


# ── Records ──────────────────────────────────────────────────────────────────


class TestItemRecords:
    def _fields(self, **overrides):
        fields = {"name": "Gym", "amount": "45.00", "type": "Expense",
                  "frequency": "Monthly", "start_date": (date.today() + timedelta(days=4)).isoformat()}
        fields.update(overrides)
        return fields

    def test_create_and_duplicate_conflict(self, make_user, app_ctx):
        uid = make_user()
        rec = records.create_item(records.SCHEDULE, uid, self._fields())
        assert rec.firstdate == rec.startdate
        with pytest.raises(Conflict) as exc:
            records.create_item(records.SCHEDULE, uid, self._fields())
        assert exc.value.details["existing_id"] == rec.id

    def test_other_account_ids_are_not_found(self, make_user, app_ctx):
        owner = make_user()
        attacker = make_user()
        rec = records.create_item(records.SCHEDULE, owner, self._fields())
        with pytest.raises(NotFound):
            records.get_item(records.SCHEDULE, attacker, rec.id)
        with pytest.raises(NotFound):
            records.update_item(records.SCHEDULE, attacker, rec.id, {"amount": "1.00"})
        with pytest.raises(NotFound):
            records.delete_item(records.SCHEDULE, attacker, rec.id)
        with pytest.raises(NotFound):
            records.create_hold(attacker, rec.id)

    def test_partial_update_preserves_unspecified_fields(self, make_user, app_ctx):
        uid = make_user()
        rec = records.create_item(records.SCHEDULE, uid, self._fields())
        before = (rec.name, rec.type, rec.frequency, rec.startdate)
        records.update_item(records.SCHEDULE, uid, rec.id, {"amount": "50.25"})
        _db.session.expire_all()
        rec = _db.session.get(Schedule, rec.id)
        assert rec.amount == Decimal("50.25")
        assert (rec.name, rec.type, rec.frequency, rec.startdate) == before

    def test_update_day_change_resets_firstdate_like_rest(self, make_user, app_ctx):
        uid = make_user()
        rec = records.create_item(records.SCHEDULE, uid, self._fields())
        new_start = rec.startdate + timedelta(days=1)
        records.update_item(records.SCHEDULE, uid, rec.id, {"start_date": new_start.isoformat()})
        assert rec.startdate == new_start and rec.firstdate == new_start

    def test_etag_conflict(self, make_user, app_ctx):
        uid = make_user()
        rec = records.create_item(records.SCHEDULE, uid, self._fields())
        stale = records.item_etag(rec)
        records.update_item(records.SCHEDULE, uid, rec.id, {"amount": "46.00"})
        with pytest.raises(Conflict):
            records.update_item(records.SCHEDULE, uid, rec.id, {"amount": "47.00"}, expected_etag=stale)
        with pytest.raises(Conflict):
            records.delete_item(records.SCHEDULE, uid, rec.id, expected_etag=stale)
        records.delete_item(records.SCHEDULE, uid, rec.id, expected_etag=records.item_etag(rec))

    def test_rename_to_existing_name_conflicts(self, make_user, app_ctx):
        uid = make_user()
        records.create_item(records.SCENARIO, uid, self._fields(name="A"))
        b = records.create_item(records.SCENARIO, uid, self._fields(name="B"))
        with pytest.raises(Conflict):
            records.update_item(records.SCENARIO, uid, b.id, {"name": "A"})

    def test_update_rejects_unknown_and_empty_changes(self, make_user, app_ctx):
        uid = make_user()
        rec = records.create_item(records.SCHEDULE, uid, self._fields())
        with pytest.raises(ValidationFailed):
            records.update_item(records.SCHEDULE, uid, rec.id, {"user_id": 999})
        with pytest.raises(ValidationFailed):
            records.update_item(records.SCHEDULE, uid, rec.id, {})


class TestHoldsAndSkips:
    def test_hold_duplicate_and_remove_keeps_schedule(self, make_user, app_ctx, fresh):
        uid = make_user()
        sched = _schedule(uid)
        hold = records.create_hold(uid, sched.id)
        assert (hold.name, hold.type, hold.amount) == (sched.name, sched.type, sched.amount)
        with pytest.raises(Conflict):
            records.create_hold(uid, sched.id)
        records.remove_hold(uid, hold.id)
        assert fresh(Hold, hold.id) is None
        assert fresh(Schedule, sched.id) is not None

    def test_skip_requires_explicit_valid_occurrence(self, make_user, app_ctx, fresh):
        uid = make_user(balance="100.00")
        sched = _schedule(uid, name="Phone", amount="80.00", frequency="Monthly",
                          start=date.today() + timedelta(days=6))
        projections.run_projection(uid)
        with pytest.raises(ClarificationRequired) as missing:
            records.create_skip(uid, sched.id, None)
        options = missing.value.details["upcoming_occurrence_dates"]
        assert options
        not_an_occurrence = (date.fromisoformat(options[0]) + timedelta(days=1)).isoformat()
        assert not_an_occurrence not in options
        with pytest.raises(ClarificationRequired):
            records.create_skip(uid, sched.id, not_an_occurrence)

        skip = records.create_skip(uid, sched.id, options[0])
        assert skip.name == "Phone (SKIP)" and skip.type == "Income"
        assert skip.date.isoformat() == options[0]
        with pytest.raises(Conflict):
            records.create_skip(uid, sched.id, options[0])

        records.remove_skip(uid, skip.id)
        assert fresh(Skip, skip.id) is None
        assert fresh(Schedule, sched.id) is not None

    def test_skip_other_account_not_found(self, make_user, app_ctx):
        owner = make_user()
        attacker = make_user()
        sched = _schedule(owner)
        with pytest.raises(NotFound):
            records.create_skip(attacker, sched.id, date.today().isoformat())
        skip = Skip(user_id=owner, name="Rent (SKIP)", type="Income", amount="1.00",
                    date=date.today() + timedelta(days=3))
        _db.session.add(skip)
        _db.session.commit()
        with pytest.raises(NotFound):
            records.remove_skip(attacker, skip.id)


def test_scenario_model_is_used_for_scenarios(make_user, app_ctx):
    uid = make_user()
    rec = records.create_item(records.SCENARIO, uid, {
        "name": "Raise", "amount": "300.00", "type": "Income", "frequency": "Monthly",
        "start_date": date.today().isoformat(),
    })
    assert isinstance(rec, Scenario)
    assert Schedule.query.filter_by(user_id=uid).count() == 0
