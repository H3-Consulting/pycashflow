"""preview_change: what-if impact of a proposed change, never persisted."""

from datetime import date, timedelta
from types import SimpleNamespace
from typing import Annotated, Literal

from mcp.server.mcpserver import Context
from mcp_types import CallToolResult
from pydantic import Field

from app.oauth import scopes as S
from app.services import projections, records
from app.services.errors import Conflict, NotFound, ValidationFailed

from ..schemas import ImpactStats, PreviewOut
from .common import MAINTENANCE_NOTE, item_out, money, projecting, security_meta
from .items import FrequencyParam, TypeParam, _reject_past_onetime

ChangeType = Literal[
    "create_schedule", "update_schedule", "delete_schedule",
    "create_hold", "remove_hold", "create_skip", "remove_skip",
]

# Read scopes for the records a preview reveals (create_hold/create_skip also
# return the referenced schedule).
_READ_SCOPES = {
    "create_schedule": [S.SCHEDULES_READ], "update_schedule": [S.SCHEDULES_READ],
    "delete_schedule": [S.SCHEDULES_READ], "create_hold": [S.HOLDS_READ, S.SCHEDULES_READ],
    "remove_hold": [S.HOLDS_READ], "create_skip": [S.SKIPS_READ, S.SCHEDULES_READ],
    "remove_skip": [S.SKIPS_READ],
}
_WRITE_SCOPE = {
    "create_schedule": S.SCHEDULES_WRITE, "update_schedule": S.SCHEDULES_WRITE,
    "delete_schedule": S.SCHEDULES_WRITE, "create_hold": S.HOLDS_WRITE, "remove_hold": S.HOLDS_WRITE,
    "create_skip": S.SKIPS_WRITE, "remove_skip": S.SKIPS_WRITE,
}


def _impact(series) -> tuple[ImpactStats, dict]:
    stats = projections.series_stats(series)
    return ImpactStats(
        ending_balance=money(stats["ending_balance"]),
        minimum_balance=money(stats["minimum_balance"]),
        minimum_balance_date=stats["minimum_balance_date"].isoformat(),
        first_negative_date=stats["first_negative_date"].isoformat() if stats["first_negative_date"] else None,
        days_below_zero=stats["days_below_zero"],
    ), stats


def _require(value, field: str):
    if value is None:
        raise ValidationFailed({field: f"{field} is required for this change_type"})
    return value


def _find(rows, row_id, label):
    for row in rows:
        if row.id == row_id:
            return row
    raise NotFound(f"{label} not found")


def apply_proposed_change(principal, change: dict, schedules, holds, skips):
    """Apply *change* to detached copies; return (target, apply_with)."""
    kind = change["change_type"]
    user_id = principal.effective_user_id
    names = {s.name for s in schedules}
    if kind == "create_schedule":
        fields = {k: change.get(k) for k in ("name", "amount", "type", "frequency", "start_date")}
        parsed = records.validate_new_item(fields)
        _reject_past_onetime(parsed["frequency"], parsed["start_date"])
        if parsed["name"] in names:
            raise Conflict("Schedule already exists", details={"field": "name"})
        schedules.append(SimpleNamespace(
            id=None, name=parsed["name"], amount=parsed["amount"], type=parsed["type"],
            frequency=parsed["frequency"], startdate=parsed["start_date"], firstdate=parsed["start_date"],
        ))
        return None, {"tool": "create_schedule", "arguments": {k: str(v) if k == "amount" else v
                                                              for k, v in fields.items()}}
    if kind in ("update_schedule", "delete_schedule"):
        schedule_id = _require(change.get("schedule_id"), "schedule_id")
        live = records.get_item(records.SCHEDULE, user_id, schedule_id)  # ownership check
        target = item_out(live).model_dump(mode="json")
        snapshot = _find(schedules, schedule_id, "Schedule")
        if kind == "delete_schedule":
            schedules.remove(snapshot)
            return target, {"tool": "delete_schedule", "arguments": {
                "schedule_id": schedule_id, "confirm": True, "expected_etag": target["etag"]}}
        changes = {k: change.get(k) for k in ("name", "amount", "type", "frequency", "start_date")}
        changes = {k: (str(v) if k == "amount" and v is not None else v) for k, v in changes.items()}
        parsed = records.parse_item_changes(changes)
        if "name" in parsed and parsed["name"] != snapshot.name and parsed["name"] in names:
            raise Conflict("Schedule name already exists", details={"field": "name"})
        records.apply_item_changes(snapshot, parsed)
        if snapshot.frequency == "Onetime" and snapshot.startdate < date.today():
            raise ValidationFailed({"start_date": "A one-time item must be dated today or later"})
        arguments = {"schedule_id": schedule_id, "expected_etag": target["etag"]}
        arguments.update({k: v for k, v in changes.items() if v is not None})
        return target, {"tool": "update_schedule", "arguments": arguments}
    if kind == "create_hold":
        schedule_id = _require(change.get("schedule_id"), "schedule_id")
        live = records.get_item(records.SCHEDULE, user_id, schedule_id)
        if records.find_duplicate_hold(user_id, live) is not None:
            raise Conflict("A hold for this schedule already exists")
        holds.append(SimpleNamespace(id=None, name=live.name, amount=live.amount, type=live.type))
        return item_out(live).model_dump(mode="json"), {
            "tool": "create_hold", "arguments": {"schedule_id": schedule_id}}
    if kind == "remove_hold":
        hold_id = _require(change.get("hold_id"), "hold_id")
        live = records.get_hold(user_id, hold_id)
        holds.remove(_find(holds, hold_id, "Hold"))
        return {"id": live.id, "name": live.name, "amount": money(live.amount), "type": live.type}, {
            "tool": "remove_hold", "arguments": {"hold_id": hold_id}}
    if kind == "create_skip":
        schedule_id = _require(change.get("schedule_id"), "schedule_id")
        schedule, occurrence = records.resolve_skip_occurrence(user_id, schedule_id, change.get("occurrence_date"))
        if records.find_duplicate_skip(user_id, schedule, occurrence) is not None:
            raise Conflict("That occurrence is already skipped")
        new_skip = records.build_skip(user_id, schedule, occurrence)
        skips.append(SimpleNamespace(id=None, name=new_skip.name, date=new_skip.date,
                                     amount=new_skip.amount, type=new_skip.type))
        return item_out(schedule).model_dump(mode="json"), {
            "tool": "create_skip",
            "arguments": {"schedule_id": schedule_id, "occurrence_date": occurrence.isoformat()}}
    if kind == "remove_skip":
        skip_id = _require(change.get("skip_id"), "skip_id")
        live = records.get_skip(user_id, skip_id)
        skips.remove(_find(skips, skip_id, "Skip"))
        return {"id": live.id, "name": live.name, "date": live.date.isoformat(),
                "amount": money(live.amount), "type": live.type}, {
            "tool": "remove_skip", "arguments": {"skip_id": skip_id}}
    raise ValidationFailed({"change_type": "Unsupported change_type"})  # pragma: no cover


def register(mcp, runner) -> None:
    async def preview_change(
        ctx: Context,
        change_type: Annotated[ChangeType, Field(description="The kind of change to evaluate")],
        schedule_id: Annotated[int | None, Field(default=None, ge=1, le=2_147_483_647)] = None,
        hold_id: Annotated[int | None, Field(default=None, ge=1, le=2_147_483_647)] = None,
        skip_id: Annotated[int | None, Field(default=None, ge=1, le=2_147_483_647)] = None,
        occurrence_date: Annotated[str | None, Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
        name: Annotated[str | None, Field(default=None, min_length=1, max_length=100)] = None,
        amount: Annotated[str | float | int | None, Field(default=None)] = None,
        type: TypeParam | None = None,
        frequency: FrequencyParam | None = None,
        start_date: Annotated[str | None, Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
        horizon_days: Annotated[int, Field(ge=7, le=projections.MAX_WINDOW_DAYS)] = 90,
    ) -> Annotated[CallToolResult, PreviewOut]:
        change = {
            "change_type": change_type, "schedule_id": schedule_id, "hold_id": hold_id,
            "skip_id": skip_id, "occurrence_date": occurrence_date, "name": name, "amount": amount,
            "type": type, "frequency": frequency, "start_date": start_date,
        }

        def body(principal, _cid):
            today = date.today()
            end = today + timedelta(days=horizon_days)
            # Establish the current baseline with the normal persistent pipeline.
            result = projections.run_projection(principal.effective_user_id)
            schedules, holds, skips, _scen = projections.snapshot_inputs(principal.effective_user_id)
            _t, run_before, _rs = projections.project_detached(result.balance_amount, list(schedules),
                                                              list(holds), list(skips))
            target, apply_with = apply_proposed_change(principal, change, schedules, holds, skips)
            _t, run_after, _rs = projections.project_detached(result.balance_amount, schedules, holds, skips)
            before_series = projections.daily_balances(run_before, today, end)
            after_series = projections.daily_balances(run_after, today, end)
            before, before_stats = _impact(before_series)
            after, after_stats = _impact(after_series)
            changed = [d.isoformat() for (d, b), (_d2, a) in zip(before_series, after_series)
                       if round(a - b, 2) != 0][:10]
            return PreviewOut(
                change_type=change_type,
                persisted=False,
                horizon_days=horizon_days,
                before=before,
                after=after,
                ending_balance_change=money(after_stats["ending_balance"] - before_stats["ending_balance"]),
                minimum_balance_change=money(after_stats["minimum_balance"] - before_stats["minimum_balance"]),
                first_changed_dates=changed,
                target=target,
                apply_with=apply_with,
                can_apply=principal.can_write and principal.has_scope(_WRITE_SCOPE[change_type]),
                maintenance_performed=MAINTENANCE_NOTE,
            )

        scopes = [S.PROJECTIONS_READ, *_READ_SCOPES[change_type]]
        return await runner.run(ctx, tool="preview_change", scopes=scopes, fn=body)

    mcp.add_tool(
        preview_change,
        name="preview_change",
        title="Preview a change",
        description=(
            "Calculate how a proposed change would affect projected balances WITHOUT saving it. Supports "
            "creating/updating/deleting a schedule, creating/removing a hold, and creating/removing a skip. "
            "Returns before/after lowest and ending balances, the first dates that change, the current "
            "record (with etag) and an apply_with tool call to run only after the user confirms. Example: "
            "to move a bill to the 20th, call with change_type=update_schedule, schedule_id and the new "
            "start_date. The proposed change is never persisted; establishing the current baseline runs "
            "the same projection maintenance as opening the dashboard (moving elapsed recurring dates and "
            "deleting expired one-time schedules and past skips). Requires projections:read plus read "
            "access to the affected record type."
        ),
        annotations=projecting("Preview a change"),
        meta=security_meta([S.PROJECTIONS_READ, S.SCHEDULES_READ, S.HOLDS_READ, S.SKIPS_READ]),
    )
