"""Helpers shared by MCP tool modules."""

from __future__ import annotations

import logging
from datetime import date, timedelta
from decimal import Decimal

from mcp_types import ToolAnnotations

from app.oauth.scopes import PROJECTIONS_READ
from app.services import projections, records

from ..schemas import (
    HoldOut,
    ItemOut,
    ProjectionAfterChange,
    SeriesStats,
    SkipOut,
    UpcomingTransaction,
)

MAINTENANCE_NOTE = (
    "Projection maintenance ran (same as opening the PyCashFlow dashboard): recurring items "
    "whose dates have passed were moved to their next date, and expired one-time schedules and "
    "past skips were removed. Amounts, names and balances were not changed."
)

UNTRUSTED_NAMES_NOTE = "Record names are free text entered by the account owner."


def money(value) -> str:
    if value is None:
        return None
    return f"{Decimal(str(value)).quantize(Decimal('0.01')):.2f}"


def iso(value) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def security_meta(scopes: list[str]) -> dict:
    """Per-tool auth requirements (ChatGPT ``securitySchemes``)."""
    return {"securitySchemes": [{"type": "oauth2", "scopes": list(scopes)}]}


def read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, read_only_hint=True, destructive_hint=False,
        idempotent_hint=True, open_world_hint=False,
    )


def projecting(title: str) -> ToolAnnotations:
    """Annotations for tools that run the persistent projection pipeline.

    Not read-only: computing a projection commits maintenance changes,
    including deleting expired one-time schedules and past skips.
    """
    return ToolAnnotations(
        title=title, read_only_hint=False, destructive_hint=True,
        idempotent_hint=True, open_world_hint=False,
    )


def mutating(title: str, *, idempotent: bool) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, read_only_hint=False, destructive_hint=True,
        idempotent_hint=idempotent, open_world_hint=False,
    )


def item_out(record) -> ItemOut:
    return ItemOut(
        id=record.id,
        name=record.name,
        amount=money(record.amount),
        type=record.type,
        frequency=record.frequency,
        start_date=iso(record.startdate),
        first_date=iso(record.firstdate),
        etag=records.item_etag(record),
    )


def schedule_ids_by_name(user_id: int) -> dict[str, int]:
    from app.models import Schedule

    return {name: sid for sid, name in Schedule.query.with_entities(Schedule.id, Schedule.name)
            .filter_by(user_id=user_id).all()}


def hold_out(hold, schedule_ids: dict[str, int], today: date | None = None) -> HoldOut:
    today = today or date.today()
    return HoldOut(
        id=hold.id, name=hold.name, amount=money(hold.amount), type=hold.type,
        schedule_id=schedule_ids.get(hold.name),
        applies_on=(today + timedelta(days=1)).isoformat(),
    )


def skip_out(skip, schedule_ids: dict[str, int]) -> SkipOut:
    base_name = skip.name[:-len(" (SKIP)")] if skip.name and skip.name.endswith(" (SKIP)") else skip.name
    return SkipOut(
        id=skip.id, name=skip.name, date=iso(skip.date), amount=money(skip.amount),
        type=skip.type, schedule_id=schedule_ids.get(base_name),
    )


def upcoming_out(item: dict) -> UpcomingTransaction:
    return UpcomingTransaction(
        date=item["date"].isoformat(), name=item["name"], type=item["type"],
        amount=money(item["amount"]), source=item["source"],
        schedule_id=item["schedule_id"], hold_id=item["hold_id"], skipped=item["skipped"],
    )


def stats_out(stats: dict) -> SeriesStats:
    return SeriesStats(
        start_balance=money(stats["start_balance"]),
        ending_balance=money(stats["ending_balance"]),
        minimum_balance=money(stats["minimum_balance"]),
        minimum_balance_date=iso(stats["minimum_balance_date"]),
        maximum_balance=money(stats["maximum_balance"]),
        first_negative_date=iso(stats["first_negative_date"]),
        days_below_zero=stats["days_below_zero"],
    )


def projection_after_change(principal, horizon_days: int = projections.DEFAULT_WINDOW_DAYS):
    """Re-run the persistent pipeline after a write and summarise it.

    Returns ``None`` when the connection lacks ``projections:read``.
    """
    if not principal.has_scope(PROJECTIONS_READ):
        return None
    try:
        return _summarise_after_change(principal, horizon_days)
    except Exception:
        # The requested change is already committed; never report it as
        # failed because the follow-up summary could not be computed.
        from app import db

        db.session.rollback()
        logging.getLogger(__name__).exception("Post-change projection summary failed")
        return None


def _summarise_after_change(principal, horizon_days: int):
    result = projections.run_projection(principal.effective_user_id, settle=True)
    today = date.today()
    end, _complete = projections.capped_window_end(principal.effective_user_id,
                                                   today + timedelta(days=horizon_days))
    series = projections.daily_balances(result.run, today, end)
    stats = projections.series_stats(series)
    return ProjectionAfterChange(
        horizon_days=max(0, (end - today).days),
        lowest_balance=money(stats["minimum_balance"]),
        lowest_balance_date=iso(stats["minimum_balance_date"]),
        ending_balance=money(stats["ending_balance"]),
        first_negative_date=iso(stats["first_negative_date"]),
    )
