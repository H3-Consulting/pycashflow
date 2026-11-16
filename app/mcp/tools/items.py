"""Schedule and scenario tools (identical shape, different tables/scopes)."""

from datetime import date
from typing import Annotated, Literal

from mcp.server.mcpserver import Context
from mcp_types import CallToolResult
from pydantic import Field

from app.oauth import scopes as S
from app.services import records
from app.services.errors import ValidationFailed

from ..schemas import ItemList, ItemOut, ItemWriteOut
from .common import (
    UNTRUSTED_NAMES_NOTE,
    item_out,
    money,
    mutating,
    projection_after_change,
    read_only,
    security_meta,
)

TypeParam = Literal["Income", "Expense"]
FrequencyParam = Literal["Monthly", "Quarterly", "Yearly", "Weekly", "BiWeekly", "Onetime"]
AmountParam = Annotated[
    str | float | int,
    Field(description="Positive amount with up to 2 decimals, e.g. 125.50. Direction comes from type."),
]
NameParam = Annotated[str, Field(min_length=1, max_length=100, description="Unique label")]
DateParam = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$", description="ISO date YYYY-MM-DD")]
IdParam = Annotated[int, Field(ge=1, le=2_147_483_647)]
EtagParam = Annotated[
    str | None,
    Field(default=None, pattern=r"^[0-9a-f]{16}$",
          description="etag from a previous read/preview; the change is refused if the record changed since"),
]
IdempotencyParam = Annotated[
    str | None,
    Field(default=None, min_length=8, max_length=128,
          description="Optional client-generated key; retries with the same key return the original result"),
]

_FREQ_HELP = (
    "Frequencies: Monthly, Quarterly, Yearly, Weekly, BiWeekly (every two weeks) or Onetime. "
    "Monthly income dated on a weekend or holiday is moved to the previous business day; expenses "
    "to the next business day."
)


def _reject_past_onetime(frequency, start: date) -> None:
    if frequency == "Onetime" and start < date.today():
        raise ValidationFailed(
            {"start_date": "A one-time item must be dated today or later (past one-time items are removed)"}
        )


def _check_onetime_after_update(record) -> None:
    if record.frequency == "Onetime" and record.startdate and record.startdate < date.today():
        raise ValidationFailed(
            {"start_date": "A one-time item must be dated today or later (past one-time items are removed)"}
        )


def _register_kind(mcp, runner, *, kind, noun: str, plural: str, read_scope: str, write_scope: str,
                   semantics: str) -> None:
    singular_title = noun.capitalize()

    @mcp.tool(
        name=f"list_{plural}",
        title=f"List {plural}",
        description=f"List all {plural} in the PyCashFlow account. {semantics} Read-only. "
                    f"Requires {read_scope}. {UNTRUSTED_NAMES_NOTE}",
        annotations=read_only(f"List {plural}"),
        meta=security_meta([read_scope]),
    )
    async def list_items(ctx: Context) -> Annotated[CallToolResult, ItemList]:
        def body(principal, _cid):
            rows, total = records.list_items(kind, principal.effective_user_id)
            return ItemList(items=[item_out(r) for r in rows], total=total)

        return await runner.run(ctx, tool=f"list_{plural}", scopes=[read_scope], fn=body)

    async def get_item_impl(ctx: Context, item_id: IdParam) -> Annotated[CallToolResult, ItemOut]:
        def body(principal, _cid):
            return item_out(records.get_item(kind, principal.effective_user_id, item_id))

        return await runner.run(ctx, tool=f"get_{noun}", scopes=[read_scope], fn=body)

    _add(mcp, get_item_impl, name=f"get_{noun}", title=f"Get {noun}",
         description=f"Get one {noun} by id ({noun}_id), including its etag for safe updates. Read-only. "
                     f"Requires {read_scope}. {UNTRUSTED_NAMES_NOTE}",
         annotations=read_only(f"Get {noun}"), scopes=[read_scope], rename={"item_id": f"{noun}_id"})

    async def create_impl(
        ctx: Context,
        name: NameParam,
        amount: AmountParam,
        type: TypeParam,
        frequency: FrequencyParam,
        start_date: DateParam,
        idempotency_key: IdempotencyParam = None,
    ) -> Annotated[CallToolResult, ItemWriteOut]:
        payload = {"name": name, "amount": str(amount), "type": type, "frequency": frequency,
                   "start_date": start_date}

        def body(principal, cid):
            fields = dict(payload)
            parsed = records.validate_new_item(fields)
            _reject_past_onetime(parsed["frequency"], parsed["start_date"])
            record = records.create_item(kind, principal.effective_user_id, fields)
            created = item_out(record)
            return ItemWriteOut(action="created", item=created, deleted=None,
                                projection_after_change=projection_after_change(principal),
                                correlation_id=cid)

        return await runner.run(ctx, tool=f"create_{noun}", scopes=[write_scope], fn=body, write=True,
                                resource_type=noun, idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    _add(mcp, create_impl, name=f"create_{noun}", title=f"Create {noun}",
         description=(f"Create a new {noun}. {semantics} {_FREQ_HELP} Names must be unique within the "
                      f"account. Returns the saved {noun} and the updated projection summary. Ask the user "
                      f"to confirm the details before calling. Saving also runs projection maintenance. "
                      f"Requires {write_scope}."),
         annotations=mutating(f"Create {noun}", idempotent=False), scopes=[write_scope])

    async def update_impl(
        ctx: Context,
        item_id: IdParam,
        name: Annotated[str | None, Field(default=None, min_length=1, max_length=100)] = None,
        amount: Annotated[str | float | int | None, Field(default=None, description="New positive amount")] = None,
        type: TypeParam | None = None,
        frequency: FrequencyParam | None = None,
        start_date: Annotated[str | None, Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
        expected_etag: EtagParam = None,
        idempotency_key: IdempotencyParam = None,
    ) -> Annotated[CallToolResult, ItemWriteOut]:
        changes = {"name": name, "amount": None if amount is None else str(amount), "type": type,
                   "frequency": frequency, "start_date": start_date}
        payload = {"id": item_id, "changes": changes, "expected_etag": expected_etag}

        def body(principal, cid):
            record = records.update_item(kind, principal.effective_user_id, item_id, changes,
                                         expected_etag=expected_etag)
            try:
                _check_onetime_after_update(record)
            except ValidationFailed:
                from app import db
                db.session.rollback()
                raise
            return ItemWriteOut(action="updated", item=item_out(record), deleted=None,
                                projection_after_change=projection_after_change(principal),
                                correlation_id=cid)

        return await runner.run(ctx, tool=f"update_{noun}", scopes=[write_scope], fn=body, write=True,
                                resource_type=noun, idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    _add(mcp, update_impl, name=f"update_{noun}", title=f"Update {noun}",
         description=(f"Change fields of an existing {noun} ({noun}_id). Only the fields you pass are changed; "
                      f"all others keep their current values. Changing start_date to a different day of the "
                      f"month also resets the day-of-month anchor, exactly like the web app. Pass expected_etag "
                      f"from get_{noun} or preview_change so the update is refused if the {noun} changed in the "
                      f"meantime. Consider preview_change first and confirm with the user. Saving also runs "
                      f"projection maintenance. Requires {write_scope}."),
         annotations=mutating(f"Update {noun}", idempotent=True), scopes=[write_scope],
         rename={"item_id": f"{noun}_id"})

    async def delete_impl(
        ctx: Context,
        item_id: IdParam,
        confirm: Annotated[Literal[True], Field(description="Must be true; set only after the user confirmed")],
        expected_etag: EtagParam = None,
        idempotency_key: IdempotencyParam = None,
    ) -> Annotated[CallToolResult, ItemWriteOut]:
        payload = {"id": item_id, "expected_etag": expected_etag}

        def body(principal, cid):
            snapshot = records.delete_item(kind, principal.effective_user_id, item_id,
                                           expected_etag=expected_etag)
            deleted = {
                "id": snapshot["id"], "name": snapshot["name"], "amount": money(snapshot["amount"]),
                "type": snapshot["type"], "frequency": snapshot["frequency"],
                "start_date": snapshot["startdate"].isoformat() if snapshot["startdate"] else None,
            }
            return ItemWriteOut(action="deleted", item=None, deleted=deleted,
                                projection_after_change=projection_after_change(principal),
                                correlation_id=cid)

        return await runner.run(ctx, tool=f"delete_{noun}", scopes=[write_scope], fn=body, write=True,
                                resource_type=noun, idempotency_key=idempotency_key,
                                idempotency_payload=payload)

    _add(mcp, delete_impl, name=f"delete_{noun}", title=f"Delete {noun}",
         description=(f"Permanently delete one {noun} ({noun}_id). Only that {noun} is removed. This cannot be "
                      f"undone: confirm with the user first and pass confirm=true. Pass expected_etag to make "
                      f"sure you delete the version the user saw. Saving also runs projection maintenance. "
                      f"Requires {write_scope}."),
         annotations=mutating(f"Delete {noun}", idempotent=True), scopes=[write_scope],
         rename={"item_id": f"{noun}_id"})


def _add(mcp, fn, *, name, title, description, annotations, scopes, rename=None):
    """Register *fn* as a tool, optionally renaming parameters for clarity."""
    if rename:
        fn = _renamed(fn, rename)
    mcp.add_tool(fn, name=name, title=title, description=description, annotations=annotations,
                 meta=security_meta(scopes))


def _renamed(fn, rename: dict):
    """Wrap *fn* so tool arguments use public names (e.g. schedule_id)."""
    import functools
    import inspect

    sig = inspect.signature(fn)
    params = []
    for p in sig.parameters.values():
        params.append(p.replace(name=rename.get(p.name, p.name)))
    reverse = {v: k for k, v in rename.items()}

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await fn(*args, **{reverse.get(k, k): v for k, v in kwargs.items()})

    wrapper.__signature__ = sig.replace(parameters=params)
    annotations = dict(getattr(fn, "__annotations__", {}))
    for old, new in rename.items():
        if old in annotations:
            annotations[new] = annotations.pop(old)
    wrapper.__annotations__ = annotations
    return wrapper


def register(mcp, runner) -> None:
    _register_kind(
        mcp, runner, kind=records.SCHEDULE, noun="schedule", plural="schedules",
        read_scope=S.SCHEDULES_READ, write_scope=S.SCHEDULES_WRITE,
        semantics=("Schedules are the real recurring income and expenses that drive the baseline "
                   "cash-flow projection."),
    )
    _register_kind(
        mcp, runner, kind=records.SCENARIO, noun="scenario", plural="scenarios",
        read_scope=S.SCENARIOS_READ, write_scope=S.SCENARIOS_WRITE,
        semantics=("Scenarios are hypothetical what-if items; they only affect the 'with scenarios' "
                   "projection and are never converted into real schedules."),
    )


__all__ = ["register"]
