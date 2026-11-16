"""Concurrency, retry and transaction-integrity tests.

On PostgreSQL these exercise real row locks (SELECT ... FOR UPDATE) and
concurrent transactions; on SQLite (single shared in-memory connection) they
still verify that nothing raises unexpectedly and no state is corrupted.
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta

import pytest

from app import db as _db
from app.models import Hold, Schedule
from app.services import projections, records
from app.services.errors import Conflict, ServiceError

from mcp_integration.mcp_helpers import schedule_id

TODAY = date.today()


def _is_postgres(flask_app):
    return flask_app.config["SQLALCHEMY_DATABASE_URI"].startswith("postgresql")


def _run_parallel(flask_app, fn, n):
    barrier = threading.Barrier(n)

    def worker(i):
        with flask_app.app_context():
            barrier.wait(timeout=10)
            try:
                return ("ok", fn(i))
            except ServiceError as exc:
                _db.session.rollback()
                return ("err", exc.code)
            except Exception as exc:  # surfaced to the assertion below
                _db.session.rollback()
                return ("exc", repr(exc))

    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(worker, range(n)))


@pytest.fixture()
def postgres_only(flask_app):
    if not _is_postgres(flask_app):
        pytest.skip("needs a real multi-connection database (TEST_DATABASE_URL=postgresql://...)")


def test_concurrent_projections_converge(flask_app, owner, app_ctx, fresh, postgres_only):
    expired = Schedule(user_id=owner, name="Expired", amount="5.00", type="Expense", frequency="Onetime",
                       startdate=TODAY - timedelta(days=2), firstdate=TODAY - timedelta(days=2))
    _db.session.add(expired)
    _db.session.commit()
    expired_id = expired.id
    results = _run_parallel(flask_app, lambda _i: projections.run_projection(owner).balance_amount, 6)
    assert all(kind == "ok" for kind, _ in results), results
    assert fresh(Schedule, expired_id) is None
    assert {value for _k, value in results} == {2500.0}


def test_concurrent_identical_creates_yield_one_record(flask_app, owner, app_ctx, postgres_only):
    fields = {"name": "Insurance", "amount": "99.00", "type": "Expense", "frequency": "Monthly",
              "start_date": (TODAY + timedelta(days=7)).isoformat()}
    results = _run_parallel(flask_app, lambda _i: records.create_item(records.SCHEDULE, owner, fields).id, 5)
    assert [k for k, _ in results].count("ok") == 1, results
    assert all(v == "conflict" for k, v in results if k == "err"), results
    assert Schedule.query.filter_by(user_id=owner, name="Insurance").count() == 1


def test_concurrent_holds_on_same_schedule(flask_app, owner, app_ctx, postgres_only):
    sid = schedule_id(owner, "Rent")
    results = _run_parallel(flask_app, lambda _i: records.create_hold(owner, sid).id, 5)
    assert [k for k, _ in results].count("ok") == 1, results
    assert Hold.query.filter_by(user_id=owner).count() == 1


def test_concurrent_updates_with_same_etag_one_wins(flask_app, owner, app_ctx, fresh, postgres_only):
    sid = schedule_id(owner, "Rent")
    etag = records.item_etag(fresh(Schedule, sid))
    results = _run_parallel(
        flask_app,
        lambda i: records.update_item(records.SCHEDULE, owner, sid, {"amount": f"{1000 + i}.00"},
                                      expected_etag=etag).id,
        4,
    )
    assert [k for k, _ in results].count("ok") == 1, results
    assert all(v == "conflict" for k, v in results if k == "err"), results


def test_concurrent_deletes_delete_once(flask_app, owner, app_ctx, fresh, postgres_only):
    sid = schedule_id(owner, "Rent")
    results = _run_parallel(flask_app, lambda _i: records.delete_item(records.SCHEDULE, owner, sid)["id"], 4)
    assert [k for k, _ in results].count("ok") == 1, results
    assert all(v == "not_found" for k, v in results if k == "err"), results
    assert fresh(Schedule, sid) is None
    assert fresh(Schedule, schedule_id(owner, "Pay")) is not None


def test_concurrent_idempotent_tool_calls(flask_app, mcp, owner, issue_token, app_ctx, postgres_only):
    token = issue_token(owner)
    args = {"name": "Gym", "amount": "45.00", "type": "Expense", "frequency": "Monthly",
            "start_date": (TODAY + timedelta(days=4)).isoformat(), "idempotency_key": "parallel-key-01"}
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _i: mcp.call(token, "create_schedule", args), range(3)))
    successes = [r for r in results if not r.is_error]
    assert successes, [r.structured_content for r in results]
    for r in results:
        if r.is_error:
            assert r.structured_content["error"]["code"] == "conflict"
    assert Schedule.query.filter_by(user_id=owner, name="Gym").count() == 1


def test_sequential_retry_and_rollback_on_sqlite_and_postgres(mcp, owner, issue_token, app_ctx, monkeypatch):
    """A failure after a partial write must not leave a half-applied change."""
    token = issue_token(owner)
    sid = schedule_id(owner, "Rent")
    real_commit = records._commit_or_conflict

    def failing_commit(message):
        raise Conflict("simulated commit failure")

    monkeypatch.setattr(records, "_commit_or_conflict", failing_commit)
    result = mcp.call(token, "update_schedule", {"schedule_id": sid, "amount": "1.00", "name": "Renamed"})
    assert result.is_error
    monkeypatch.setattr(records, "_commit_or_conflict", real_commit)
    _db.session.expire_all()
    row = _db.session.get(Schedule, sid)
    assert row.name == "Rent" and str(row.amount) == "1800.00"
