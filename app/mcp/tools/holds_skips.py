"""Hold and skip tools."""

from typing import Annotated

from mcp.server.mcpserver import Context
from mcp_types import CallToolResult
from pydantic import Field

from app.oauth import scopes as S
from app.services import projections, records

from ..schemas import HoldList, HoldWriteOut, SkipList, SkipWriteOut
from .common import (
    UNTRUSTED_NAMES_NOTE,
    hold_out,
    mutating,
    projection_after_change,
    read_only,
    schedule_ids_by_name,
    security_meta,
    skip_out,
)

IdParam = Annotated[int, Field(ge=1, le=2_147_483_647)]
IdempotencyParam = Annotated[
    str | None,
    Field(default=None, min_length=8, max_length=128,
          description="Optional client-generated key; retries with the same key return the original result"),
]

HOLD_SEMANTICS = (
    "A hold records a pending payment or deposit for an existing schedule that has not cleared the "
    "bank yet: the projection applies the schedule's amount once more on the next day. Holds copy the "
    "schedule's name, amount and type; they never modify or delete the schedule."
)
SKIP_SEMANTICS = (
    "A skip cancels one future occurrence of a schedule (for example, one rent payment) by adding an "
    "offsetting entry on that date; the schedule itself is unchanged and later occurrences still apply."
)


def register(mcp, runner) -> None:
    async def list_holds(ctx: Context) -> Annotated[CallToolResult, HoldList]:
        def body(principal, _cid):
            ids = schedule_ids_by_name(principal.effective_user_id)
            rows = records.list_holds(principal.effective_user_id)
            return HoldList(items=[hold_out(h, ids) for h in rows], total=len(rows))

        return await runner.run(ctx, tool="list_holds", scopes=[S.HOLDS_READ], fn=body)

    mcp.add_tool(list_holds, name="list_holds", title="List holds",
                 description=f"List active holds. {HOLD_SEMANTICS} Read-only. Requires holds:read. "
                             f"{UNTRUSTED_NAMES_NOTE}",
                 annotations=read_only("List holds"), meta=security_meta([S.HOLDS_READ]))

    async def create_hold(ctx: Context, schedule_id: IdParam,
                          idempotency_key: IdempotencyParam = None) -> Annotated[CallToolResult, HoldWriteOut]:
        payload = {"schedule_id": schedule_id}

        def body(principal, cid):
            hold = records.create_hold(principal.effective_user_id, schedule_id)
            ids = schedule_ids_by_name(principal.effective_user_id)
            created = hold_out(hold, ids)
            return HoldWriteOut(action="created", hold=created, removed=None,
                                projection_after_change=projection_after_change(principal))

        # schedules:read too: the result reveals the referenced schedule.
        return await runner.run(ctx, tool="create_hold", scopes=[S.HOLDS_WRITE, S.SCHEDULES_READ], fn=body,
                                write=True,
                                resource_type="hold", idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    mcp.add_tool(create_hold, name="create_hold", title="Create hold",
                 description=(f"Create a hold from an existing schedule (schedule_id). {HOLD_SEMANTICS} "
                              "Refused if that schedule already has a hold. "
                              "Saving also runs projection maintenance. Requires holds:write and schedules:read."),
                 annotations=mutating("Create hold", idempotent=False),
                 meta=security_meta([S.HOLDS_WRITE, S.SCHEDULES_READ]))

    async def remove_hold(ctx: Context, hold_id: IdParam,
                          idempotency_key: IdempotencyParam = None) -> Annotated[CallToolResult, HoldWriteOut]:
        payload = {"hold_id": hold_id}

        def body(principal, cid):
            removed = records.remove_hold(principal.effective_user_id, hold_id)
            removed["amount"] = f"{removed['amount']:.2f}" if removed.get("amount") is not None else None
            return HoldWriteOut(action="removed", hold=None, removed=removed,
                                projection_after_change=projection_after_change(principal))

        return await runner.run(ctx, tool="remove_hold", scopes=[S.HOLDS_WRITE], fn=body, write=True,
                                resource_type="hold", idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    mcp.add_tool(remove_hold, name="remove_hold", title="Remove hold",
                 description=("Remove one hold (hold_id). The underlying schedule is not deleted or changed. "
                              "Saving also runs projection maintenance. Requires holds:write."),
                 annotations=mutating("Remove hold", idempotent=True), meta=security_meta([S.HOLDS_WRITE]))

    async def list_skips(ctx: Context) -> Annotated[CallToolResult, SkipList]:
        def body(principal, _cid):
            ids = schedule_ids_by_name(principal.effective_user_id)
            rows = records.list_skips(principal.effective_user_id)
            return SkipList(items=[skip_out(s, ids) for s in rows], total=len(rows))

        return await runner.run(ctx, tool="list_skips", scopes=[S.SKIPS_READ], fn=body)

    mcp.add_tool(list_skips, name="list_skips", title="List skips",
                 description=f"List skipped occurrences. {SKIP_SEMANTICS} Read-only. Requires skips:read. "
                             f"{UNTRUSTED_NAMES_NOTE}",
                 annotations=read_only("List skips"), meta=security_meta([S.SKIPS_READ]))

    async def create_skip(
        ctx: Context,
        schedule_id: IdParam,
        occurrence_date: Annotated[str | None, Field(
            default=None, pattern=r"^\d{4}-\d{2}-\d{2}$",
            description="Exact date of the occurrence to skip, as returned by list_upcoming_transactions",
        )] = None,
        idempotency_key: IdempotencyParam = None,
    ) -> Annotated[CallToolResult, SkipWriteOut]:
        payload = {"schedule_id": schedule_id, "occurrence_date": occurrence_date}

        def body(principal, cid):
            # Bring the schedule's stored next date up to date first, exactly
            # like POST /api/v1/skips does, then validate the occurrence.
            projections.run_projection(principal.effective_user_id)
            skip = records.create_skip(principal.effective_user_id, schedule_id, occurrence_date)
            ids = schedule_ids_by_name(principal.effective_user_id)
            created = skip_out(skip, ids)
            return SkipWriteOut(action="created", skip=created, removed=None,
                                projection_after_change=projection_after_change(principal))

        # Resolving occurrences runs the projection and reveals schedule dates.
        return await runner.run(ctx, tool="create_skip",
                                scopes=[S.SKIPS_WRITE, S.SCHEDULES_READ, S.PROJECTIONS_READ], fn=body, write=True,
                                resource_type="skip", idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    mcp.add_tool(create_skip, name="create_skip", title="Skip one occurrence",
                 description=(f"Skip one specific future occurrence of a schedule. {SKIP_SEMANTICS} Identify "
                              "the occurrence by schedule_id and occurrence_date (from list_upcoming_transactions). "
                              "If occurrence_date is missing or does not match a real upcoming occurrence, nothing "
                              "is saved and a clarification_required error lists the valid upcoming dates. "
                              "Already-skipped occurrences are refused. Also runs "
                              "projection maintenance. Requires skips:write, schedules:read and projections:read."),
                 annotations=mutating("Skip one occurrence", idempotent=False),
                 meta=security_meta([S.SKIPS_WRITE, S.SCHEDULES_READ, S.PROJECTIONS_READ]))

    async def remove_skip(ctx: Context, skip_id: IdParam,
                          idempotency_key: IdempotencyParam = None) -> Annotated[CallToolResult, SkipWriteOut]:
        payload = {"skip_id": skip_id}

        def body(principal, cid):
            removed = records.remove_skip(principal.effective_user_id, skip_id)
            removed = {
                "id": removed["id"], "name": removed["name"],
                "date": removed["date"].isoformat() if removed.get("date") else None,
                "amount": f"{removed['amount']:.2f}" if removed.get("amount") is not None else None,
                "type": removed["type"],
            }
            return SkipWriteOut(action="removed", skip=None, removed=removed,
                                projection_after_change=projection_after_change(principal))

        return await runner.run(ctx, tool="remove_skip", scopes=[S.SKIPS_WRITE], fn=body, write=True,
                                resource_type="skip", idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    mcp.add_tool(remove_skip, name="remove_skip", title="Remove skip",
                 description=("Remove one skip (skip_id) so that occurrence counts again. The schedule is not "
                              "deleted or changed. Also runs projection maintenance. Requires skips:write."),
                 annotations=mutating("Remove skip", idempotent=True), meta=security_meta([S.SKIPS_WRITE]))
