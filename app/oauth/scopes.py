"""OAuth scopes exposed to MCP clients and their user-facing descriptions."""

from __future__ import annotations

PROJECTIONS_READ = "projections:read"
SCHEDULES_READ = "schedules:read"
SCHEDULES_WRITE = "schedules:write"
SCENARIOS_READ = "scenarios:read"
SCENARIOS_WRITE = "scenarios:write"
HOLDS_READ = "holds:read"
HOLDS_WRITE = "holds:write"
SKIPS_READ = "skips:read"
SKIPS_WRITE = "skips:write"

# Ordered for display on the consent screen.
SCOPE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    PROJECTIONS_READ: (
        "View cash-flow projections",
        "Current balance, projected daily balances, risk indicators and upcoming "
        "transactions. Calculating a projection also performs the same routine "
        "upkeep as opening your dashboard: moving recurring items past dates "
        "that have already happened and removing expired one-time items and "
        "past skips.",
    ),
    SCHEDULES_READ: ("View recurring schedules", "Names, amounts, frequencies and dates of your income and expenses."),
    SCHEDULES_WRITE: ("Change recurring schedules", "Create, edit and delete income and expense schedules."),
    SCENARIOS_READ: ("View what-if scenarios", "Hypothetical items you model separately from your real schedule."),
    SCENARIOS_WRITE: ("Change what-if scenarios", "Create, edit and delete scenarios."),
    HOLDS_READ: ("View holds", "Pending payments held against tomorrow's balance."),
    HOLDS_WRITE: ("Change holds", "Add or remove holds created from your schedules."),
    SKIPS_READ: ("View skipped payments", "Individual occurrences you chose to skip."),
    SKIPS_WRITE: ("Change skipped payments", "Skip or un-skip individual occurrences of a schedule."),
}

ALL_SCOPES: tuple[str, ...] = tuple(SCOPE_DESCRIPTIONS)
WRITE_SCOPES: frozenset[str] = frozenset(s for s in ALL_SCOPES if s.endswith(":write"))
READ_SCOPES: frozenset[str] = frozenset(s for s in ALL_SCOPES if s.endswith(":read"))

# Scopes some clients append that carry no permission here (refresh tokens are
# issued to clients registered for the refresh_token grant regardless).
IGNORED_SCOPES = frozenset({"offline_access"})


def split_scope(scope: str | None) -> list[str]:
    """Split a space-delimited scope string into an ordered, de-duplicated list."""
    if not scope:
        return []
    seen: list[str] = []
    for item in scope.split():
        if item not in seen:
            seen.append(item)
    return seen


def join_scope(scopes) -> str:
    """Join scopes in canonical (display) order."""
    wanted = set(scopes)
    return " ".join(s for s in ALL_SCOPES if s in wanted)


def normalize_requested(scope: str | None) -> tuple[list[str], list[str]]:
    """Return ``(known, unknown)`` scopes from a request, ignoring benign extras.

    An empty request means "everything this server offers"; the user still
    chooses on the consent screen.
    """
    requested = [s for s in split_scope(scope) if s not in IGNORED_SCOPES]
    if not requested:
        return list(ALL_SCOPES), []
    known = [s for s in requested if s in SCOPE_DESCRIPTIONS]
    unknown = [s for s in requested if s not in SCOPE_DESCRIPTIONS]
    return known, unknown
