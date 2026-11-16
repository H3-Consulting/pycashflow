"""Projection tools. All of them run the persistent projection pipeline."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Annotated

from mcp.server.mcpserver import Context
from mcp_types import CallToolResult
from pydantic import Field

from app.oauth.scopes import PROJECTIONS_READ, SCENARIOS_READ
from app.services import projections
from app.services.errors import ValidationFailed

from ..schemas import (
    CashFlowTotals,
    CashflowProjectionOut,
    ProjectionSummaryOut,
    RiskIndicators,
    ScenarioComparison,
    Series,
    Shortfall,
    UpcomingTransactionsOut,
    Window,
    BalancePoint,
)
from .common import (
    MAINTENANCE_NOTE,
    UNTRUSTED_NAMES_NOTE,
    iso,
    money,
    projecting,
    security_meta,
    stats_out,
    upcoming_out,
)

DateParam = Annotated[
    str | None,
    Field(default=None, description="ISO date YYYY-MM-DD", pattern=r"^\d{4}-\d{2}-\d{2}$"),
]

_MAINTENANCE_DISCLOSURE = (
    " Side effects: like opening the PyCashFlow dashboard, this runs projection maintenance and "
    "saves it — recurring items whose dates have passed move to their next date, and expired "
    "one-time schedules and past skip records are deleted. It never changes amounts, names, "
    "frequencies or balances."
)


def _parse_window(start_date, end_date, today: date) -> tuple[date, date]:
    limit = today + timedelta(days=projections.MAX_WINDOW_DAYS)
    errors = {}
    try:
        start = date.fromisoformat(start_date) if start_date else today
    except ValueError:
        errors["start_date"] = "start_date must be a valid YYYY-MM-DD date"
        start = today
    try:
        end = date.fromisoformat(end_date) if end_date else min(
            start + timedelta(days=projections.DEFAULT_WINDOW_DAYS), limit
        )
    except ValueError:
        errors["end_date"] = "end_date must be a valid YYYY-MM-DD date"
        end = today
    if not errors:
        if start < today:
            errors["start_date"] = "Projections start today; start_date cannot be in the past"
        elif start > limit:
            errors["start_date"] = f"start_date must be on or before {limit.isoformat()}"
        if end < start:
            errors["end_date"] = "end_date must be on or after start_date"
        elif end > limit:
            errors["end_date"] = (
                f"The supported forecast horizon ends {limit.isoformat()} "
                f"({projections.MAX_WINDOW_DAYS} days); quarterly items are not projected further"
            )
    if errors:
        raise ValidationFailed(errors)
    return start, end


def _series(run_df, start, end) -> tuple[Series, dict]:
    points = projections.daily_balances(run_df, start, end)
    stats = projections.series_stats(points)
    return Series(
        stats=stats_out(stats),
        daily_balances=[BalancePoint(date=d.isoformat(), balance=money(v)) for d, v in points],
    ), stats


def _comparison(base: dict, scen: dict) -> ScenarioComparison:
    return ScenarioComparison(
        ending_balance_difference=money(scen["ending_balance"] - base["ending_balance"]),
        minimum_balance_difference=money(scen["minimum_balance"] - base["minimum_balance"]),
    )


def _cash_flow_totals(items, start: date, end: date) -> CashFlowTotals:
    from decimal import Decimal

    income = Decimal("0")
    expenses = Decimal("0")
    count = 0
    for item in items:
        if item["skipped"] or not (start <= item["date"] <= end):
            continue
        amount = Decimal(str(item["amount"]))
        if item["type"] == "Income":
            income += amount
        else:
            expenses += amount
        count += 1
    return CashFlowTotals(
        total_income=money(income), total_expenses=money(expenses),
        net=money(income - expenses), transaction_count=count,
    )


def register(mcp, runner) -> None:
    get_projection_scopes = [PROJECTIONS_READ]

    @mcp.tool(
        name="get_cashflow_projection",
        title="Get cash-flow projection",
        description=(
            "Return the projected daily bank balance for a date window (default: today through 90 days; "
            f"maximum {projections.MAX_WINDOW_DAYS} days ahead), starting from the latest recorded balance. "
            "Includes the baseline projection (real schedules, holds and skips) and, when "
            "include_scenarios is true, the projection with what-if scenarios added plus a comparison. "
            "Use get_projection_summary for a compact overview." + _MAINTENANCE_DISCLOSURE
            + " Requires projections:read (and scenarios:read for scenarios). " + UNTRUSTED_NAMES_NOTE
        ),
        annotations=projecting("Get cash-flow projection"),
        meta=security_meta(get_projection_scopes),
    )
    async def get_cashflow_projection(
        ctx: Context,
        start_date: DateParam = None,
        end_date: DateParam = None,
        include_scenarios: Annotated[bool, Field(description="Also project with what-if scenarios")] = False,
    ) -> Annotated[CallToolResult, CashflowProjectionOut]:
        scopes = [PROJECTIONS_READ] + ([SCENARIOS_READ] if include_scenarios else [])

        def body(principal, _cid):
            today = date.today()
            start, end = _parse_window(start_date, end_date, today)
            result = projections.run_projection(principal.effective_user_id)
            baseline, base_stats = _series(result.run, start, end)
            scenario = comparison = None
            notes = []
            if include_scenarios:
                if result.run_scenario is None:
                    notes.append("No what-if scenarios are defined, so only the baseline is shown.")
                else:
                    scenario, scen_stats = _series(result.run_scenario, start, end)
                    comparison = _comparison(base_stats, scen_stats)
            schedules, holds, skips, _scen = projections.load_inputs(principal.effective_user_id)
            items = projections.upcoming_occurrences(schedules, holds, skips, days=(end - today).days + 1)
            age = (today - result.balance_date).days
            if age > 3:
                notes.append(f"The latest recorded balance is {age} days old; projections may be off.")
            return CashflowProjectionOut(
                as_of=today.isoformat(),
                starting_balance=money(result.balance_amount),
                starting_balance_date=result.balance_date.isoformat(),
                starting_balance_age_days=age,
                window=Window(start_date=start.isoformat(), end_date=end.isoformat(),
                              days=(end - start).days + 1),
                baseline=baseline,
                scenario=scenario,
                scenario_comparison=comparison,
                baseline_cash_flow=_cash_flow_totals(items, start, end),
                maintenance_performed=MAINTENANCE_NOTE,
                notes=notes,
            )

        return await runner.run(ctx, tool="get_cashflow_projection", scopes=scopes, fn=body)

    @mcp.tool(
        name="get_projection_summary",
        title="Get projection summary",
        description=(
            "Summarise the cash-flow outlook: current balance, lowest projected balance and its date, "
            "ending balance, periods where the balance goes negative, the largest upcoming inflows and "
            "outflows, and the PyCashFlow risk score. Optionally compares against what-if scenarios. "
            "Best first call for questions like 'will I run short this month?'." + _MAINTENANCE_DISCLOSURE
            + " Requires projections:read (and scenarios:read for scenarios). " + UNTRUSTED_NAMES_NOTE
        ),
        annotations=projecting("Get projection summary"),
        meta=security_meta([PROJECTIONS_READ]),
    )
    async def get_projection_summary(
        ctx: Context,
        horizon_days: Annotated[int, Field(ge=7, le=projections.MAX_WINDOW_DAYS,
                                           description="Days ahead to analyse")] = 90,
        include_scenarios: Annotated[bool, Field(description="Compare with what-if scenarios")] = False,
    ) -> Annotated[CallToolResult, ProjectionSummaryOut]:
        scopes = [PROJECTIONS_READ] + ([SCENARIOS_READ] if include_scenarios else [])

        def body(principal, _cid):
            today = date.today()
            end = today + timedelta(days=horizon_days)
            result = projections.run_projection(principal.effective_user_id)
            points = projections.daily_balances(result.run, today, end)
            stats = projections.series_stats(points)
            schedules, holds, skips, _scen = projections.load_inputs(principal.effective_user_id)
            items = [i for i in projections.upcoming_occurrences(
                schedules, holds, skips, days=horizon_days + 1) if not i["skipped"]]
            inflows = sorted((i for i in items if i["type"] == "Income"), key=lambda i: -float(i["amount"]))[:5]
            outflows = sorted((i for i in items if i["type"] == "Expense"), key=lambda i: -float(i["amount"]))[:5]
            risk = projections.risk_score(result)
            scenario_stats = comparison = None
            if include_scenarios and result.run_scenario is not None:
                scen_points = projections.daily_balances(result.run_scenario, today, end)
                scen = projections.series_stats(scen_points)
                scenario_stats = stats_out(scen)
                comparison = _comparison(stats, scen)
            return ProjectionSummaryOut(
                as_of=today.isoformat(),
                current_balance=money(result.balance_amount),
                current_balance_date=result.balance_date.isoformat(),
                current_balance_age_days=(today - result.balance_date).days,
                horizon_days=horizon_days,
                lowest_balance=money(stats["minimum_balance"]),
                lowest_balance_date=iso(stats["minimum_balance_date"]),
                ending_balance=money(stats["ending_balance"]),
                first_negative_date=iso(stats["first_negative_date"]),
                shortfalls=[
                    Shortfall(
                        start_date=p["start_date"].isoformat(), end_date=p["end_date"].isoformat(),
                        days=p["days"], lowest_balance=money(p["lowest_balance"]),
                        lowest_date=p["lowest_date"].isoformat(),
                    )
                    for p in projections.shortfall_periods(points)[:10]
                ],
                major_inflows=[upcoming_out(i) for i in inflows],
                major_outflows=[upcoming_out(i) for i in outflows],
                risk=RiskIndicators(
                    score=int(risk["score"]),
                    status=str(risk["status"]),
                    runway_days=risk["runway_days"],
                    lowest_balance=money(risk["lowest_balance"]),
                    days_to_lowest=int(risk["days_to_lowest"]),
                    days_below_threshold=int(risk["days_below_threshold"]),
                    near_term_buffer=money(risk["near_term_buffer"]),
                ),
                scenario=scenario_stats,
                scenario_comparison=comparison,
                maintenance_performed=MAINTENANCE_NOTE,
            )

        return await runner.run(ctx, tool="get_projection_summary", scopes=scopes, fn=body)

    @mcp.tool(
        name="list_upcoming_transactions",
        title="List upcoming transactions",
        description=(
            "List the individual projected transactions in the next N days (max 90), each with its "
            "date, amount, type and the schedule_id or hold_id it comes from. Occurrences already offset "
            "by a skip are flagged skipped=true. Use the schedule_id and date from this list with "
            "create_skip to skip a specific occurrence." + _MAINTENANCE_DISCLOSURE
            + " Requires projections:read. " + UNTRUSTED_NAMES_NOTE
        ),
        annotations=projecting("List upcoming transactions"),
        meta=security_meta([PROJECTIONS_READ]),
    )
    async def list_upcoming_transactions(
        ctx: Context,
        days: Annotated[int, Field(ge=1, le=projections.DEFAULT_WINDOW_DAYS, description="Days ahead")] = 30,
    ) -> Annotated[CallToolResult, UpcomingTransactionsOut]:
        def body(principal, _cid):
            today = date.today()
            projections.run_projection(principal.effective_user_id)
            schedules, holds, skips, _scen = projections.load_inputs(principal.effective_user_id)
            items = projections.upcoming_occurrences(schedules, holds, skips, days=days + 1)
            return UpcomingTransactionsOut(
                as_of=today.isoformat(),
                window=Window(
                    start_date=(today + timedelta(days=1)).isoformat(),
                    end_date=(today + timedelta(days=days)).isoformat(),
                    days=days,
                ),
                items=[upcoming_out(i) for i in items],
                maintenance_performed=MAINTENANCE_NOTE,
            )

        return await runner.run(ctx, tool="list_upcoming_transactions", scopes=[PROJECTIONS_READ], fn=body)
