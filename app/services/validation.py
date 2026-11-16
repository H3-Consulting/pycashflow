"""Field validation shared by the REST API and MCP tools.

Two levels are provided:

* :func:`validate_item_payload` keeps the REST API's historical rules and error
  messages (so existing clients see identical responses) while closing gaps
  that let non-finite or out-of-range amounts reach the database.
* The ``parse_*_strict`` helpers implement the stricter rules used by the MCP
  integration, where inputs are produced by a language model and must be
  treated as untrusted: positive two-decimal amounts, bounded ISO dates, and
  names without control characters or the engine's reserved ``(SKIP)`` marker.
"""

from __future__ import annotations

import math
import unicodedata
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation

VALID_TYPES = ("Income", "Expense")
VALID_FREQUENCIES = ("Monthly", "Quarterly", "Yearly", "Weekly", "BiWeekly", "Onetime")
MAX_NAME_LEN = 100

# ``Numeric(10, 2)`` holds at most 8 integer digits.
MAX_AMOUNT = Decimal("99999999.99")

# Bounds for MCP-supplied dates. Recurring items may start in the past (the
# engine fast-forwards them), but extreme years overflow date arithmetic.
STRICT_DATE_PAST_YEARS = 5
STRICT_DATE_FUTURE_YEARS = 10

# The projection engine hides any transaction whose name contains this marker
# from upcoming-transaction lists, so user-named records must not contain it.
SKIP_MARKER = "(SKIP)"

_FORBIDDEN_UNICODE_CATEGORIES = {"Cc", "Cf", "Cs", "Co"}


def _finite_amount_in_range(value) -> bool:
    """Return True when *value* parses as a finite number the DB can store."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(number):
        return False
    try:
        dec = Decimal(str(value).strip()) if isinstance(value, str) else Decimal(str(number))
    except (InvalidOperation, ValueError):
        return False
    return abs(dec) <= MAX_AMOUNT


def validate_item_payload(body: dict) -> dict:
    """Validate a REST schedule/scenario payload; return ``{field: reason}``.

    Messages match the original ``api/routes/data._validate_schedule_payload``.
    """
    errors = {}
    name_raw = body.get("name")
    name = name_raw.strip() if isinstance(name_raw, str) else ""
    if not name or len(name) > MAX_NAME_LEN:
        errors["name"] = f"Name must be between 1 and {MAX_NAME_LEN} characters"

    amount = body.get("amount")
    try:
        float(amount)
    except (TypeError, ValueError):
        errors["amount"] = "Amount must be a number"
    else:
        if isinstance(amount, bool) or not _finite_amount_in_range(amount):
            errors["amount"] = (
                f"Amount must be a finite number no larger than {MAX_AMOUNT} in magnitude"
            )

    if body.get("type") not in VALID_TYPES:
        errors["type"] = "Invalid type"
    if body.get("frequency") not in VALID_FREQUENCIES:
        errors["frequency"] = "Invalid frequency"

    start_date = body.get("start_date")
    if not start_date:
        errors["start_date"] = "start_date is required"
    else:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
        except (TypeError, ValueError):
            errors["start_date"] = "start_date must be YYYY-MM-DD"
    return errors


def validate_balance_amount(value) -> str | None:
    """Return an error message for a REST balance amount, or ``None``."""
    try:
        float(value)
    except (TypeError, ValueError):
        return "Amount must be a number"
    if isinstance(value, bool) or not _finite_amount_in_range(value):
        return f"Amount must be a finite number no larger than {MAX_AMOUNT} in magnitude"
    return None


# ── Strict (MCP) parsing ─────────────────────────────────────────────────────


def parse_amount_strict(value, field: str = "amount") -> Decimal:
    """Parse a positive monetary amount with at most two decimal places.

    Accepts a JSON number or a decimal string. Rejects booleans, NaN/Infinity,
    exponents that lose precision, zero/negative values and anything that would
    overflow ``Numeric(10, 2)``. Direction is carried by the record ``type``.
    """
    from .errors import ValidationFailed

    if isinstance(value, bool) or value is None:
        raise ValidationFailed({field: "Amount must be a positive number such as 125.50"})
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationFailed({field: "Amount must be a finite number"})
        text = repr(value)
    elif isinstance(value, (int, Decimal)):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip().replace(",", "")
        if text.startswith("$"):
            text = text[1:]
    else:
        raise ValidationFailed({field: "Amount must be a positive number such as 125.50"})
    if len(text) > 32:
        raise ValidationFailed({field: "Amount is too long"})
    try:
        amount = Decimal(text)
    except (InvalidOperation, ValueError):
        raise ValidationFailed({field: "Amount must be a positive number such as 125.50"})
    if not amount.is_finite():
        raise ValidationFailed({field: "Amount must be a finite number"})
    if amount <= 0:
        raise ValidationFailed(
            {field: "Amount must be greater than zero; use type Income or Expense for direction"}
        )
    if amount > MAX_AMOUNT:
        raise ValidationFailed({field: f"Amount must not exceed {MAX_AMOUNT}"})
    if amount != amount.quantize(Decimal("0.01")):
        raise ValidationFailed({field: "Amount must have at most two decimal places"})
    return amount.quantize(Decimal("0.01"))


def parse_name_strict(value, field: str = "name") -> str:
    """Validate a user-visible record name supplied by an MCP client."""
    from .errors import ValidationFailed

    if not isinstance(value, str):
        raise ValidationFailed({field: "Name must be a string"})
    name = value.strip()
    if not name or len(name) > MAX_NAME_LEN:
        raise ValidationFailed({field: f"Name must be between 1 and {MAX_NAME_LEN} characters"})
    if any(unicodedata.category(ch) in _FORBIDDEN_UNICODE_CATEGORIES for ch in name):
        raise ValidationFailed({field: "Name must not contain control or formatting characters"})
    if SKIP_MARKER.lower() in name.lower():
        raise ValidationFailed({field: f"Name must not contain the reserved marker {SKIP_MARKER}"})
    return name


def parse_choice_strict(value, choices, field: str) -> str:
    from .errors import ValidationFailed

    if value not in choices:
        raise ValidationFailed({field: f"Must be one of: {', '.join(choices)}"})
    return value


def strict_date_bounds(today: date | None = None) -> tuple[date, date]:
    """Return the inclusive (lower, upper) window accepted for MCP dates."""
    today = today or date.today()
    lower = today - timedelta(days=366 * STRICT_DATE_PAST_YEARS)
    upper = today + timedelta(days=366 * STRICT_DATE_FUTURE_YEARS)
    return lower, upper


def parse_date_strict(value, field: str, *, lower: date | None = None, upper: date | None = None) -> date:
    """Parse an ISO ``YYYY-MM-DD`` date within configured bounds."""
    from .errors import ValidationFailed

    if isinstance(value, date) and not isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value.strip()) == 10:
        try:
            parsed = date.fromisoformat(value.strip())
        except ValueError:
            raise ValidationFailed({field: "Date must be a valid YYYY-MM-DD date"})
    else:
        raise ValidationFailed({field: "Date must be a YYYY-MM-DD string"})
    default_lower, default_upper = strict_date_bounds()
    lower = lower or default_lower
    upper = upper or default_upper
    if parsed < lower or parsed > upper:
        raise ValidationFailed(
            {field: f"Date must be between {lower.isoformat()} and {upper.isoformat()}"}
        )
    return parsed
