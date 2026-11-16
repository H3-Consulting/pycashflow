"""Ownership-scoped record operations for schedules, scenarios, holds, skips.

Every function takes the caller's *effective user id* and filters every query
by it, so a record id belonging to another account behaves exactly like a
missing record (``NotFound``) — no existence oracle across accounts.

Writes run in a single transaction: rows are locked (``SELECT ... FOR UPDATE``
on PostgreSQL), optimistic-concurrency tokens (``etag``) are compared, and any
integrity failure rolls the session back before a ``Conflict`` is raised.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from sqlalchemy.exc import IntegrityError

from app import db
from app.models import Hold, Scenario, Schedule, Skip

from . import projections
from .errors import ClarificationRequired, Conflict, NotFound, ValidationFailed
from .validation import (
    VALID_FREQUENCIES,
    VALID_TYPES,
    parse_amount_strict,
    parse_choice_strict,
    parse_date_strict,
    parse_name_strict,
)


@dataclass(frozen=True)
class ItemKind:
    model: type
    label: str  # "Schedule" / "Scenario"


SCHEDULE = ItemKind(Schedule, "Schedule")
SCENARIO = ItemKind(Scenario, "Scenario")

_EDITABLE_FIELDS = ("name", "amount", "type", "frequency", "start_date")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _amount_text(value) -> str:
    return f"{Decimal(str(value)):.2f}" if value is not None else ""


def item_etag(record) -> str:
    """Return a short content hash used for optimistic concurrency checks.

    Projection maintenance can advance ``startdate``; that intentionally changes
    the etag so a stale preview cannot be committed over newer state.
    """
    raw = "|".join([
        str(record.id),
        record.name or "",
        _amount_text(record.amount),
        record.type or "",
        record.frequency or "",
        record.startdate.isoformat() if record.startdate else "",
        record.firstdate.isoformat() if record.firstdate else "",
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def apply_start_date(record, new_start: date) -> None:
    """Apply the REST/web start-date rule (resets ``firstdate`` on a day change)."""
    current = record.startdate
    if current is None or (new_start != current and new_start.day != current.day):
        record.firstdate = new_start
    record.startdate = new_start


def _check_etag(record, expected_etag: str | None) -> None:
    if expected_etag is None:
        return
    current = item_etag(record)
    if expected_etag != current:
        raise Conflict(
            "The record changed since it was read; re-read it and confirm the change again",
            details={"current_etag": current},
        )


def _commit_or_conflict(message: str) -> None:
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise Conflict(message)


# ── Schedules & scenarios ───────────────────────────────────────────────────


def list_items(kind: ItemKind, user_id: int, *, limit: int | None = None, offset: int = 0):
    query = kind.model.query.filter_by(user_id=user_id).order_by(kind.model.id.asc())
    total = query.count()
    if limit is not None:
        query = query.limit(limit).offset(offset)
    return query.all(), total


def get_item(kind: ItemKind, user_id: int, item_id: int, *, for_update: bool = False):
    if not isinstance(item_id, int) or isinstance(item_id, bool):
        raise NotFound(f"{kind.label} not found")
    query = kind.model.query.filter_by(user_id=user_id, id=item_id)
    if for_update:
        query = query.with_for_update()
    record = query.first()
    if record is None:
        raise NotFound(f"{kind.label} not found")
    return record


def validate_new_item(fields: dict) -> dict:
    """Strictly validate a complete set of item fields; return parsed values."""
    errors: dict[str, str] = {}
    parsed: dict = {}
    for key, parser in (
        ("name", lambda v: parse_name_strict(v)),
        ("amount", lambda v: parse_amount_strict(v)),
        ("type", lambda v: parse_choice_strict(v, VALID_TYPES, "type")),
        ("frequency", lambda v: parse_choice_strict(v, VALID_FREQUENCIES, "frequency")),
        ("start_date", lambda v: parse_date_strict(v, "start_date")),
    ):
        if fields.get(key) is None:
            errors[key] = f"{key} is required"
            continue
        try:
            parsed[key] = parser(fields[key])
        except ValidationFailed as exc:
            errors.update(exc.fields)
    if errors:
        raise ValidationFailed(errors)
    return parsed


def parse_item_changes(changes: dict) -> dict:
    """Strictly validate a partial update and return only the supplied fields.

    Only keys present in *changes* with a non-``None`` value are returned, so
    :func:`apply_item_changes` merges them over the stored record and
    unspecified fields keep their current values (never reset).
    """
    unknown = set(changes) - set(_EDITABLE_FIELDS)
    if unknown:
        raise ValidationFailed({k: "Unknown field" for k in sorted(unknown)})
    supplied = {k: v for k, v in changes.items() if v is not None}
    if not supplied:
        raise ValidationFailed({"changes": "Provide at least one field to change"})
    parsed: dict = {}
    errors: dict[str, str] = {}
    parsers = {
        "name": lambda v: parse_name_strict(v),
        "amount": lambda v: parse_amount_strict(v),
        "type": lambda v: parse_choice_strict(v, VALID_TYPES, "type"),
        "frequency": lambda v: parse_choice_strict(v, VALID_FREQUENCIES, "frequency"),
        "start_date": lambda v: parse_date_strict(v, "start_date"),
    }
    for key, value in supplied.items():
        try:
            parsed[key] = parsers[key](value)
        except ValidationFailed as exc:
            errors.update(exc.fields)
    if errors:
        raise ValidationFailed(errors)
    return parsed


def apply_item_changes(record, parsed: dict) -> None:
    """Apply parsed changes to a record-like object (ORM row or snapshot)."""
    if "name" in parsed:
        record.name = parsed["name"]
    if "amount" in parsed:
        record.amount = parsed["amount"]
    if "type" in parsed:
        record.type = parsed["type"]
    if "frequency" in parsed:
        record.frequency = parsed["frequency"]
    if "start_date" in parsed:
        apply_start_date(record, parsed["start_date"])


def create_item(kind: ItemKind, user_id: int, fields: dict):
    parsed = validate_new_item(fields)
    existing = kind.model.query.filter_by(user_id=user_id, name=parsed["name"]).first()
    if existing is not None:
        raise Conflict(
            f"{kind.label} already exists",
            details={"existing_id": existing.id, "field": "name"},
        )
    record = kind.model(
        user_id=user_id,
        name=parsed["name"],
        amount=parsed["amount"],
        type=parsed["type"],
        frequency=parsed["frequency"],
        startdate=parsed["start_date"],
        firstdate=parsed["start_date"],
    )
    db.session.add(record)
    _commit_or_conflict(f"{kind.label} already exists")
    return record


def update_item(kind: ItemKind, user_id: int, item_id: int, changes: dict, *, expected_etag: str | None = None):
    parsed = parse_item_changes(changes)  # validate before locking
    record = get_item(kind, user_id, item_id, for_update=True)
    _check_etag(record, expected_etag)
    if "name" in parsed and parsed["name"] != record.name:
        clash = kind.model.query.filter_by(user_id=user_id, name=parsed["name"]).first()
        if clash is not None and clash.id != record.id:
            db.session.rollback()
            raise Conflict(f"{kind.label} name already exists", details={"field": "name"})
    apply_item_changes(record, parsed)
    _commit_or_conflict(f"{kind.label} name already exists")
    return record


def delete_item(kind: ItemKind, user_id: int, item_id: int, *, expected_etag: str | None = None) -> dict:
    record = get_item(kind, user_id, item_id, for_update=True)
    _check_etag(record, expected_etag)
    snapshot = {
        "id": record.id,
        "name": record.name,
        "amount": record.amount,
        "type": record.type,
        "frequency": record.frequency,
        "startdate": record.startdate,
        "firstdate": record.firstdate,
    }
    db.session.delete(record)
    db.session.commit()
    return snapshot


# ── Holds ─────────────────────────────────────────────────────────────────────


def list_holds(user_id: int):
    return Hold.query.filter_by(user_id=user_id).order_by(Hold.id.asc()).all()


def get_hold(user_id: int, hold_id: int, *, for_update: bool = False) -> Hold:
    if not isinstance(hold_id, int) or isinstance(hold_id, bool):
        raise NotFound("Hold not found")
    query = Hold.query.filter_by(user_id=user_id, id=hold_id)
    if for_update:
        query = query.with_for_update()
    hold = query.first()
    if hold is None:
        raise NotFound("Hold not found")
    return hold


def find_duplicate_hold(user_id: int, schedule) -> Hold | None:
    return Hold.query.filter_by(
        user_id=user_id, name=schedule.name, type=schedule.type
    ).first()


def create_hold(user_id: int, schedule_id: int) -> Hold:
    schedule = get_item(SCHEDULE, user_id, schedule_id, for_update=True)
    duplicate = find_duplicate_hold(user_id, schedule)
    if duplicate is not None:
        db.session.rollback()
        raise Conflict(
            "A hold for this schedule already exists",
            details={"existing_hold_id": duplicate.id},
        )
    hold = Hold(name=schedule.name, type=schedule.type, amount=schedule.amount, user_id=user_id)
    db.session.add(hold)
    db.session.commit()
    return hold


def remove_hold(user_id: int, hold_id: int) -> dict:
    hold = get_hold(user_id, hold_id, for_update=True)
    snapshot = {"id": hold.id, "name": hold.name, "amount": hold.amount, "type": hold.type}
    db.session.delete(hold)
    db.session.commit()
    return snapshot


# ── Skips ─────────────────────────────────────────────────────────────────────


def list_skips(user_id: int):
    return Skip.query.filter_by(user_id=user_id).order_by(Skip.id.asc()).all()


def get_skip(user_id: int, skip_id: int, *, for_update: bool = False) -> Skip:
    if not isinstance(skip_id, int) or isinstance(skip_id, bool):
        raise NotFound("Skip not found")
    query = Skip.query.filter_by(user_id=user_id, id=skip_id)
    if for_update:
        query = query.with_for_update()
    skip = query.first()
    if skip is None:
        raise NotFound("Skip not found")
    return skip


def resolve_skip_occurrence(user_id: int, schedule_id: int, occurrence_date) -> tuple:
    """Validate that *occurrence_date* is a real future occurrence of a schedule.

    Returns ``(schedule, occurrence_date)``. Never guesses: a missing or
    non-matching date raises ``ClarificationRequired`` listing valid dates.
    Must be called after the projection pipeline has run so the schedule's
    persisted next date is current.
    """
    schedule = get_item(SCHEDULE, user_id, schedule_id)
    upcoming = projections.schedule_occurrence_dates(schedule)
    options = [d.isoformat() for d in upcoming[:12]]
    if occurrence_date is None:
        raise ClarificationRequired(
            "Specify which occurrence to skip by its date",
            details={"schedule_id": schedule.id, "upcoming_occurrence_dates": options},
        )
    parsed = parse_date_strict(occurrence_date, "occurrence_date")
    if parsed not in upcoming:
        raise ClarificationRequired(
            "That date is not an upcoming occurrence of this schedule",
            details={"schedule_id": schedule.id, "upcoming_occurrence_dates": options},
        )
    return schedule, parsed


def skip_name_for(schedule) -> str:
    return f"{schedule.name} (SKIP)"


def find_duplicate_skip(user_id: int, schedule, occurrence: date) -> Skip | None:
    return Skip.query.filter_by(
        user_id=user_id, name=skip_name_for(schedule), date=occurrence
    ).first()


def build_skip(user_id: int, schedule, occurrence: date) -> Skip:
    """Build (not persist) the offsetting skip row the engine expects.

    Matches ``POST /api/v1/skips``: same amount, opposite type, dated on the
    occurrence, name suffixed with ``(SKIP)``.
    """
    opposite = "Income" if schedule.type == "Expense" else "Expense"
    return Skip(
        name=skip_name_for(schedule),
        type=opposite,
        amount=schedule.amount,
        date=occurrence,
        user_id=user_id,
    )


def create_skip(user_id: int, schedule_id: int, occurrence_date) -> Skip:
    schedule, occurrence = resolve_skip_occurrence(user_id, schedule_id, occurrence_date)
    duplicate = find_duplicate_skip(user_id, schedule, occurrence)
    if duplicate is not None:
        raise Conflict(
            "That occurrence is already skipped",
            details={"existing_skip_id": duplicate.id},
        )
    skip = build_skip(user_id, schedule, occurrence)
    db.session.add(skip)
    db.session.commit()
    return skip


def remove_skip(user_id: int, skip_id: int) -> dict:
    skip = get_skip(user_id, skip_id, for_update=True)
    snapshot = {
        "id": skip.id, "name": skip.name, "date": skip.date,
        "amount": skip.amount, "type": skip.type,
    }
    db.session.delete(skip)
    db.session.commit()
    return snapshot
