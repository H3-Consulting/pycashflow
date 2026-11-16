# MCP tool catalog

Server name `pycashflow`, endpoint `https://<host>/mcp` (Streamable HTTP,
stateless, JSON responses). 20 tools. The table is generated from the live tool
definitions; every tool also sets `openWorldHint: false`, a `title`, an
`outputSchema`, and `_meta.securitySchemes = [{"type": "oauth2", "scopes": [...]}]`.

| Tool | Scopes (all required) | readOnly | destructive | idempotent | Inputs (required*) |
|---|---|---|---|---|---|
| `get_cashflow_projection` | projections:read (+ scenarios:read when `include_scenarios`) | false | true | true | start_date, end_date, include_scenarios |
| `get_projection_summary` | projections:read (+ scenarios:read when `include_scenarios`) | false | true | true | horizon_days, include_scenarios |
| `list_upcoming_transactions` | projections:read | false | true | true | days |
| `list_schedules` | schedules:read | true | false | true | — |
| `get_schedule` | schedules:read | true | false | true | schedule_id* |
| `create_schedule` | schedules:write | false | true | false | name*, amount*, type*, frequency*, start_date*, idempotency_key |
| `update_schedule` | schedules:write | false | true | true | schedule_id*, name, amount, type, frequency, start_date, expected_etag, idempotency_key |
| `delete_schedule` | schedules:write | false | true | true | schedule_id*, confirm*, expected_etag, idempotency_key |
| `list_scenarios` | scenarios:read | true | false | true | — |
| `get_scenario` | scenarios:read | true | false | true | scenario_id* |
| `create_scenario` | scenarios:write | false | true | false | name*, amount*, type*, frequency*, start_date*, idempotency_key |
| `update_scenario` | scenarios:write | false | true | true | scenario_id*, name, amount, type, frequency, start_date, expected_etag, idempotency_key |
| `delete_scenario` | scenarios:write | false | true | true | scenario_id*, confirm*, expected_etag, idempotency_key |
| `list_holds` | holds:read | true | false | true | — |
| `create_hold` | holds:write, schedules:read | false | true | false | schedule_id*, idempotency_key |
| `remove_hold` | holds:write | false | true | true | hold_id*, idempotency_key |
| `list_skips` | skips:read | true | false | true | — |
| `create_skip` | skips:write, schedules:read, projections:read | false | true | false | schedule_id*, occurrence_date, idempotency_key |
| `remove_skip` | skips:write | false | true | true | skip_id*, idempotency_key |
| `preview_change` | projections:read + read scope(s) of the affected record (see below) | false | true | true | change_type*, schedule_id, hold_id, skip_id, occurrence_date, name, amount, type, frequency, start_date, horizon_days |

Write tools (all `create_*`, `update_*`, `delete_*`, `remove_*`) are also
refused for guest accounts regardless of token scopes.

## Why projection tools are not read-only

`update_cash(..., commit=True)` persists projection maintenance: elapsed
recurring dates move forward, expired one-time schedules and past skips are
deleted. This is the same upkeep the web dashboard performs on every load, and
it is required to keep projections current, so the projection and preview
tools are honestly annotated `readOnlyHint: false, destructiveHint: true` and
say so in their descriptions and in a `maintenance_performed` field. Hosts may
therefore ask the user to approve these calls. Write tools also re-run the
projection afterwards (when the token has `projections:read`) to return an
updated summary, so they carry the same annotation.

## Conventions

- Money: decimal strings with two places (`"1500.00"`); negative values only
  for projected overdrawn balances. Inputs accept `125.50`, `"125.50"` or
  `"$1,250.00"`; must be > 0, ≤ 99,999,999.99, ≤ 2 decimals, finite.
- Dates: `YYYY-MM-DD`. Start dates must lie within −5/+10 years; a one-time
  item must be dated today or later.
- Names: 1–100 characters, no control/format characters, may not contain the
  engine's reserved `(SKIP)` marker; unique per account within schedules (and
  separately within scenarios).
- Frequencies: `Monthly`, `Quarterly`, `Yearly`, `Weekly`, `BiWeekly`, `Onetime`.
  Types: `Income`, `Expense`.
- Forecast horizon: default 90 days, maximum 270 days (the engine expands
  quarterly items four times from their next date, ≈ 9 months).

## Tools in detail

### Projections

- **`get_cashflow_projection`** — Daily balances for a window (default today
  → +90 days) from the latest recorded balance. Returns `starting_balance`,
  `starting_balance_date`/`age_days`, `baseline` (`stats` + `daily_balances`),
  optional `scenario` and `scenario_comparison`, `baseline_cash_flow`
  (income/expense totals), notes (e.g. stale balance).
- **`get_projection_summary`** — Current balance, lowest balance and date,
  ending balance, first negative date, shortfall periods, top 5 inflows and
  outflows, the PyCashFlow risk score (same values as `/api/v1/dashboard`),
  optional scenario comparison.
- **`list_upcoming_transactions`** — Individual transactions in the next
  1–90 days with `schedule_id`/`hold_id`, `source` and `skipped` flag.

### Schedules and scenarios

- `list_*`, `get_*` return records with an `etag` (16 hex chars).
- `create_*` validates strictly, rejects duplicate names (`conflict` with
  `existing_id`), stores `firstdate = start_date`, returns the record and
  `projection_after_change`.
- `update_*` changes only supplied fields; unspecified fields are never reset.
  Changing `start_date` to a different day of month resets the day anchor
  (`firstdate`), exactly like the web app and REST API. `expected_etag`
  refuses the change if the record changed (`conflict` with `current_etag`).
- `delete_*` requires `confirm: true` (schema-enforced) and deletes exactly one
  record; `expected_etag` optional.
- Scenarios are never converted into schedules.

### Holds

A hold copies a schedule's name, amount and type and is applied by the engine
as a one-off transaction **tomorrow** (a pending payment that has not cleared).
It never changes or deletes the schedule. `create_hold` refuses a second hold
for the same schedule. `remove_hold` deletes only the hold.

### Skips

A skip cancels one future occurrence by adding an offsetting entry
(`"<name> (SKIP)"`, opposite type, same amount) on that date.
`create_skip` takes `schedule_id` + `occurrence_date`; the date must be an
actual upcoming occurrence computed by the engine (after the persistent
pipeline refreshed the schedule's next date). Missing or non-matching dates
return `clarification_required` with up to 12 valid dates — nothing is saved
and nothing is guessed. Duplicate skips return `conflict`. `remove_skip`
deletes only the skip.

### `preview_change`

`change_type` ∈ `create_schedule`, `update_schedule`, `delete_schedule`,
`create_hold`, `remove_hold`, `create_skip`, `remove_skip`. Runs the normal
persistent projection to establish today's baseline, then evaluates "before"
and "after" on detached in-memory copies with `commit=False`. Returns
`persisted: false`, before/after lowest/ending balances, deltas, the first
changed dates, the `target` record (with `etag`), `apply_with` (tool + arguments
including `expected_etag`) and `can_apply` for this connection. Read scopes:
schedule changes need `schedules:read`; holds need `holds:read`
(+ `schedules:read` for create); skips need `skips:read` (+ `schedules:read`
for create).

## Safeguards on writes

- Scope check, guest check, then strict validation before any DB access.
- Account isolation: every query filters by the token's effective account; an
  id from another account behaves exactly like a missing id (`not_found`).
- Row locks (`SELECT … FOR UPDATE` on PostgreSQL) plus a per-account write
  lock per worker (covers SQLite); etag conflict detection.
- Optional `idempotency_key` (8–128 chars): replays return the original result
  with `replayed: true`; reuse with different arguments → `conflict`; keys are
  scoped per user + client and expire after 24 h.
- Any failure rolls back the tool's transaction; audit event per write attempt
  (success, error, denied).
- No bulk-delete, clear-all, transfer, payment, billing, Plaid, account or
  admin tools.

## Errors

Errors are `isError: true` results with `structuredContent`:

```json
{"error": {"code": "not_found", "message": "Schedule not found", "details": {}}}
```

| `code` | Meaning |
|---|---|
| `validation_error` | `details.fields` maps field → reason |
| `not_found` | Record does not exist in this account |
| `conflict` | Duplicate, stale etag, or idempotency-key reuse |
| `clarification_required` | Ambiguous request; `details` lists the valid options |
| `insufficient_scope` | `details.required_scopes`; `_meta["mcp/www_authenticate"]` carries an RFC 6750 challenge |
| `forbidden` | Guest (view-only) account attempted a write |
| `internal_error` | Unexpected failure; the tool's transaction was rolled back |

Schema violations (wrong types, missing required arguments, `confirm` not
`true`) are rejected by the SDK before the tool runs. Unknown arguments are
ignored and can never select another account.
