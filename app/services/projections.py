"""Projection pipeline shared by REST and MCP.

``run_projection`` is the only entry point external callers use to obtain a
projection. It always calls :func:`app.cashflow.update_cash` with
``commit=True`` — exactly like ``GET /api/v1/projections`` and the web
dashboard — so projection maintenance (advancing elapsed recurring dates,
removing expired one-time schedules and past skips) is persisted before results
are returned. Inputs are always queried by the caller's effective user id, so the
maintenance commit can only touch that account's rows.

The remaining helpers are pure functions over the resulting DataFrames, plus a
preview helper that evaluates *proposed* changes on detached in-memory copies
with ``commit=False`` so nothing user-directed is persisted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import desc
from sqlalchemy.orm.exc import ObjectDeletedError, StaleDataError

from app import db
from app.models import Balance, Hold, Scenario, Schedule, Skip
from app.cashflow import calc_schedule, calculate_cash_risk_score, update_cash

logger = logging.getLogger(__name__)

# The dashboard, risk score and upcoming-transaction views use 90 days.
DEFAULT_WINDOW_DAYS = 90
# Longest window every frequency is guaranteed to cover: the engine expands
# quarterly items 4 times from their next date (≈9 months); monthly/weekly/
# bi-weekly cover ≈12 months and yearly 2 years. Beyond this, quarterly
# occurrences can be silently missing, so external callers are capped here.
MAX_WINDOW_DAYS = 270

_MAINTENANCE_RACE_ERRORS = (StaleDataError, ObjectDeletedError)


@dataclass
class ProjectionResult:
    """Outcome of one persistent projection run for an account."""

    user_id: int
    balance: Balance | None
    balance_amount: float
    balance_date: date
    trans: object  # pandas.DataFrame of upcoming transactions (90 days)
    run: object  # pandas.DataFrame of running balance (schedules only)
    run_scenario: object | None  # pandas.DataFrame or None when no scenarios
    has_scenarios: bool = False
    extras: dict = field(default_factory=dict)


def latest_balance(user_id: int) -> Balance | None:
    return (
        Balance.query.filter_by(user_id=user_id)
        .order_by(desc(Balance.date), desc(Balance.id))
        .first()
    )


def load_inputs(user_id: int):
    """Return ``(schedules, holds, skips, scenarios)`` for one account."""
    schedules = Schedule.query.filter_by(user_id=user_id).all()
    holds = Hold.query.filter_by(user_id=user_id).all()
    skips = Skip.query.filter_by(user_id=user_id).all()
    scenarios = Scenario.query.filter_by(user_id=user_id).all()
    return schedules, holds, skips, scenarios


def _balance_amount(balance) -> float:
    try:
        return float(balance.amount)
    except (ValueError, TypeError, AttributeError):
        return 0.0


def run_projection(user_id: int) -> ProjectionResult:
    """Run the persistent projection pipeline for *user_id*.

    Calls ``update_cash(..., commit=True)``. If a concurrent projection for the
    same account already removed an expired row (``StaleDataError``), the
    session is rolled back and the pipeline re-runs once on fresh rows; the
    maintenance it performs is deterministic, so the retry converges.
    """
    attempts = 2
    for attempt in range(1, attempts + 1):
        try:
            balance = latest_balance(user_id)
            balance_amount = _balance_amount(balance)
            schedules, holds, skips, scenarios = load_inputs(user_id)
            trans, run, run_scenario = update_cash(
                balance_amount, schedules, holds, skips, scenarios, commit=True
            )
            balance_date = balance.date if balance is not None else date.today()
            return ProjectionResult(
                user_id=user_id,
                balance=balance,
                balance_amount=balance_amount,
                balance_date=balance_date,
                trans=trans,
                run=run,
                run_scenario=run_scenario,
                has_scenarios=bool(scenarios),
            )
        except _MAINTENANCE_RACE_ERRORS:
            db.session.rollback()
            if attempt == attempts:
                raise
            logger.info("Projection maintenance race for account %s; retrying", user_id)
    raise RuntimeError("unreachable")  # pragma: no cover


# ── Detached snapshots (for previews; never attached to the session) ────────


def snapshot_item(obj) -> SimpleNamespace:
    return SimpleNamespace(
        id=obj.id,
        name=obj.name,
        amount=obj.amount,
        frequency=obj.frequency,
        startdate=obj.startdate,
        firstdate=obj.firstdate,
        type=obj.type,
    )


def snapshot_hold(obj) -> SimpleNamespace:
    return SimpleNamespace(id=obj.id, name=obj.name, amount=obj.amount, type=obj.type)


def snapshot_skip(obj) -> SimpleNamespace:
    return SimpleNamespace(
        id=obj.id, name=obj.name, date=obj.date, amount=obj.amount, type=obj.type
    )


def snapshot_inputs(user_id: int):
    """Detached copies of the account's current (post-maintenance) inputs."""
    schedules, holds, skips, scenarios = load_inputs(user_id)
    return (
        [snapshot_item(s) for s in schedules],
        [snapshot_hold(h) for h in holds],
        [snapshot_skip(s) for s in skips],
        [snapshot_item(s) for s in scenarios],
    )


def project_detached(balance_amount: float, schedules, holds, skips, scenarios=None):
    """Evaluate the engine on detached copies without persisting anything."""
    return update_cash(balance_amount, schedules, holds, skips, scenarios or None, commit=False)


# ── Pure analysis helpers ─────────────────────────────────────────────────────


def _as_date(value) -> date:
    # datetime and pandas.Timestamp are date subclasses; normalise them first.
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def daily_balances(run_df, start: date, end: date, today: date | None = None) -> list[tuple[date, float]]:
    """Expand a running-balance DataFrame into one balance per calendar day.

    The engine emits a row for today (starting balance) and one row per date
    with transactions; balances carry forward between those dates.
    """
    today = today or date.today()
    points: dict[date, float] = {}
    if run_df is not None and not run_df.empty:
        for row in run_df.itertuples(index=False):
            points[_as_date(row.date)] = float(row.amount)
    current = points.get(today, 0.0)
    out: list[tuple[date, float]] = []
    day = today
    while day <= end:
        if day in points:
            current = points[day]
        if day >= start:
            out.append((day, current))
        day += timedelta(days=1)
    return out


def series_stats(series: list[tuple[date, float]]) -> dict:
    if not series:
        return {
            "start_balance": None,
            "ending_balance": None,
            "minimum_balance": None,
            "minimum_balance_date": None,
            "maximum_balance": None,
            "first_negative_date": None,
            "days_below_zero": 0,
        }
    min_day, min_val = min(series, key=lambda item: (item[1], item[0]))
    max_val = max(val for _day, val in series)
    first_negative = next((day for day, val in series if val < 0), None)
    return {
        "start_balance": series[0][1],
        "ending_balance": series[-1][1],
        "minimum_balance": min_val,
        "minimum_balance_date": min_day,
        "maximum_balance": max_val,
        "first_negative_date": first_negative,
        "days_below_zero": sum(1 for _day, val in series if val < 0),
    }


def shortfall_periods(series: list[tuple[date, float]], threshold: float = 0.0) -> list[dict]:
    """Return contiguous periods where the balance is below *threshold*."""
    periods: list[dict] = []
    current: dict | None = None
    for day, val in series:
        if val < threshold:
            if current is None:
                current = {"start_date": day, "end_date": day, "lowest_balance": val, "lowest_date": day}
            else:
                current["end_date"] = day
                if val < current["lowest_balance"]:
                    current["lowest_balance"] = val
                    current["lowest_date"] = day
        elif current is not None:
            periods.append(current)
            current = None
    if current is not None:
        periods.append(current)
    for period in periods:
        period["days"] = (period["end_date"] - period["start_date"]).days + 1
    return periods


def upcoming_occurrences(schedules, holds, skips, days: int = DEFAULT_WINDOW_DAYS, today: date | None = None) -> list[dict]:
    """Label each upcoming transaction with its source record.

    Mirrors the engine's own upcoming-transaction window (strictly after today
    and before ``today + days``). Schedule occurrences come from the engine's
    expansion of the given schedules (``commit=False``) and carry the schedule
    id; holds land tomorrow, as in ``calc_schedule``; an occurrence is flagged
    ``skipped`` when a skip record offsets it.
    """
    today = today or date.today()
    horizon = today + timedelta(days=days)
    by_name = {s.name: s for s in schedules}
    total, _total_scenario = calc_schedule(
        [snapshot_item(s) for s in schedules], [], [], [], commit=False
    )
    remaining_skips: dict[tuple[str, date], int] = {}
    for skip in skips:
        key = (skip.name, _as_date(skip.date))
        remaining_skips[key] = remaining_skips.get(key, 0) + 1

    items: list[dict] = []
    if total is not None and not total.empty:
        for row in total.itertuples(index=False):
            occ_date = _as_date(row.date)
            if not (today < occ_date < horizon):
                continue
            schedule = by_name.get(row.name)
            skip_key = (f"{row.name} (SKIP)", occ_date)
            skipped = remaining_skips.get(skip_key, 0) > 0
            if skipped:
                remaining_skips[skip_key] -= 1
            items.append({
                "source": "schedule",
                "schedule_id": schedule.id if schedule is not None else None,
                "hold_id": None,
                "name": row.name,
                "type": row.type,
                "amount": row.amount,
                "date": occ_date,
                "skipped": skipped,
            })
    tomorrow = today + timedelta(days=1)
    if tomorrow < horizon:
        for hold in holds:
            items.append({
                "source": "hold",
                "schedule_id": by_name[hold.name].id if hold.name in by_name else None,
                "hold_id": hold.id,
                "name": hold.name,
                "type": hold.type,
                "amount": hold.amount,
                "date": tomorrow,
                "skipped": False,
            })
    items.sort(key=lambda item: (item["date"], item["source"] != "hold", item["name"]))
    return items


def schedule_occurrence_dates(schedule, today: date | None = None, days: int = MAX_WINDOW_DAYS) -> list[date]:
    """Future occurrence dates of a single schedule (engine expansion, no commit)."""
    today = today or date.today()
    horizon = today + timedelta(days=days)
    total, _ = calc_schedule([snapshot_item(schedule)], [], [], [], commit=False)
    dates = []
    if total is not None and not total.empty:
        for row in total.itertuples(index=False):
            occ = _as_date(row.date)
            if today < occ <= horizon:
                dates.append(occ)
    return sorted(dates)


def risk_score(result: ProjectionResult) -> dict:
    return calculate_cash_risk_score(result.balance_amount, result.run)
