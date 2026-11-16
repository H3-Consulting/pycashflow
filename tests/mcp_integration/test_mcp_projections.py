"""Projection correctness, persistence (commit=True) and isolation through MCP."""

from datetime import date, timedelta
from decimal import Decimal

import pytest

from app import db as _db
from app.api.auth_utils import create_token_for_user
from app.models import Schedule, Skip, User
from app.services import projections as projection_service

from mcp_integration.mcp_helpers import error_code, schedule_id

TODAY = date.today()


def _rest_token(uid):
    raw, _ = create_token_for_user(_db.session.get(User, uid))
    return {"Authorization": f"Bearer {raw}"}


class TestPersistence:
    def test_projection_tools_use_commit_true_pipeline(self, mcp, owner, issue_token, monkeypatch):
        seen = []
        real = projection_service.update_cash

        def spy(*args, **kwargs):
            seen.append(kwargs.get("commit"))
            return real(*args, **kwargs)

        monkeypatch.setattr(projection_service, "update_cash", spy)
        token = issue_token(owner)
        for tool in ("get_cashflow_projection", "get_projection_summary", "list_upcoming_transactions"):
            seen.clear()
            assert not mcp.call(token, tool).is_error
            assert True in seen, tool  # at least one persistent pipeline run per call

    def test_maintenance_commit_is_persisted(self, mcp, owner, issue_token, fresh, app_ctx):
        expired = Schedule(user_id=owner, name="Old bill", amount="10.00", type="Expense", frequency="Onetime",
                           startdate=TODAY - timedelta(days=3), firstdate=TODAY - timedelta(days=3))
        past_skip = Skip(user_id=owner, name="Rent (SKIP)", type="Income", amount="1800.00",
                         date=TODAY - timedelta(days=1))
        _db.session.add_all([expired, past_skip])
        _db.session.commit()
        expired_id, skip_id = expired.id, past_skip.id
        result = mcp.call(issue_token(owner, scopes="projections:read"), "get_projection_summary")
        assert "maintenance" in result.structured_content["maintenance_performed"].lower()
        assert fresh(Schedule, expired_id) is None
        assert fresh(Skip, skip_id) is None

    def test_maintenance_never_touches_other_accounts(self, mcp, owner, make_user, issue_token, fresh, app_ctx):
        other = make_user()
        theirs = Schedule(user_id=other, name="Theirs", amount="10.00", type="Expense", frequency="Onetime",
                          startdate=TODAY - timedelta(days=3), firstdate=TODAY - timedelta(days=3))
        _db.session.add(theirs)
        _db.session.commit()
        mcp.call(issue_token(owner), "get_projection_summary")
        assert fresh(Schedule, theirs.id) is not None

    def test_repeated_requests_reflect_latest_changes(self, mcp, owner, issue_token, client, app_ctx):
        token = issue_token(owner)
        first = mcp.call(token, "get_projection_summary").structured_content
        # Change data through a different path (REST) between MCP calls.
        resp = client.post("/api/v1/schedules", headers=_rest_token(owner), json={
            "name": "Car", "amount": "300.00", "type": "Expense", "frequency": "Monthly",
            "start_date": (TODAY + timedelta(days=3)).isoformat()})
        assert resp.status_code == 201
        second = mcp.call(token, "get_projection_summary").structured_content
        assert Decimal(second["ending_balance"]) < Decimal(first["ending_balance"])
        client.post("/api/v1/balance", headers=_rest_token(owner), json={"amount": "9999.00"})
        third = mcp.call(token, "get_projection_summary").structured_content
        assert third["current_balance"] == "9999.00"


class TestParityWithRest:
    def test_projection_matches_rest_projections(self, mcp, owner, issue_token, client):
        rest = client.get("/api/v1/projections", headers=_rest_token(owner)).get_json()["data"]["schedule"]
        result = mcp.call(issue_token(owner), "get_cashflow_projection", {
            "end_date": (TODAY + timedelta(days=200)).isoformat()}).structured_content
        daily = {p["date"]: p["balance"] for p in result["baseline"]["daily_balances"]}
        for point in rest:
            if point["date"] in daily:
                assert daily[point["date"]] == point["amount"], point["date"]

    def test_summary_matches_dashboard(self, mcp, owner, issue_token, client):
        dashboard = client.get("/api/v1/dashboard", headers=_rest_token(owner)).get_json()["data"]
        summary = mcp.call(issue_token(owner), "get_projection_summary").structured_content
        assert summary["lowest_balance"] == dashboard["min_balance"]
        assert summary["current_balance"] == dashboard["balance"]
        assert summary["risk"]["score"] == dashboard["risk_v2"]["score"]

    def test_upcoming_matches_rest_transactions(self, mcp, owner, issue_token, client):
        rest = client.get("/api/v1/transactions", headers=_rest_token(owner)).get_json()["data"]
        result = mcp.call(issue_token(owner), "list_upcoming_transactions", {"days": 89}).structured_content
        assert sorted((t["name"], t["date"], t["amount"]) for t in rest) == \
            sorted((t["name"], t["date"], t["amount"]) for t in result["items"])

    def test_web_dashboard_still_renders(self, owner, login_as):
        assert login_as(owner).get("/").status_code == 200


class TestWindows:
    def test_default_window_is_90_days(self, mcp, owner, issue_token):
        result = mcp.call(issue_token(owner), "get_cashflow_projection").structured_content
        assert result["window"]["start_date"] == TODAY.isoformat()
        assert result["window"]["days"] == 91
        assert len(result["baseline"]["daily_balances"]) == 91
        assert result["scenario"] is None

    @pytest.mark.parametrize("args,field", [
        ({"start_date": (TODAY - timedelta(days=1)).isoformat()}, "start_date"),
        ({"end_date": (TODAY + timedelta(days=400)).isoformat()}, "end_date"),
        ({"start_date": (TODAY + timedelta(days=10)).isoformat(),
          "end_date": (TODAY + timedelta(days=5)).isoformat()}, "end_date"),
        ({"start_date": "2026-02-31"}, "start_date"),
    ])
    def test_invalid_windows(self, mcp, owner, issue_token, args, field):
        result = mcp.call(issue_token(owner), "get_cashflow_projection", args)
        assert error_code(result) == "validation_error"
        assert field in result.structured_content["error"]["details"]["fields"]

    def test_shortfall_detection(self, mcp, make_user, issue_token, app_ctx):
        uid = make_user(balance="100.00")
        _db.session.add(Schedule(user_id=uid, name="Big bill", amount="500.00", type="Expense",
                                 frequency="Onetime", startdate=TODAY + timedelta(days=4),
                                 firstdate=TODAY + timedelta(days=4)))
        _db.session.commit()
        summary = mcp.call(issue_token(uid), "get_projection_summary").structured_content
        assert summary["first_negative_date"] is not None
        assert summary["shortfalls"] and summary["shortfalls"][0]["lowest_balance"] == "-400.00"
        assert summary["major_outflows"][0]["name"] == "Big bill"

    def test_stale_balance_noted(self, mcp, make_user, issue_token, balance_model, app_ctx):
        uid = make_user()
        _db.session.add(balance_model(user_id=uid, amount="50.00", date=TODAY - timedelta(days=10)))
        _db.session.commit()
        result = mcp.call(issue_token(uid), "get_cashflow_projection").structured_content
        assert result["starting_balance_age_days"] == 10
        assert any("days old" in note for note in result["notes"])

    def test_empty_account(self, mcp, make_user, issue_token):
        summary = mcp.call(issue_token(make_user()), "get_projection_summary").structured_content
        assert summary["current_balance"] == "0.00" and summary["shortfalls"] == []


def test_schedule_ids_on_upcoming_transactions(mcp, owner, issue_token):
    items = mcp.call(issue_token(owner), "list_upcoming_transactions", {"days": 30}).structured_content["items"]
    rent = schedule_id(owner, "Rent")
    assert any(i["schedule_id"] == rent and i["source"] == "schedule" for i in items)
