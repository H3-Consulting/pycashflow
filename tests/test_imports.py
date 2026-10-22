"""
Tests for CSV import / parsing logic (app/files.py).

Two layers are tested:

1. validate_upload() — pure file-level validation that requires no database.
   Tests file type, MIME type, and size enforcement.

2. upload() CSV parsing — row-level validation of name, amount, type,
   frequency, and dates.  Tests use the ``app_ctx`` fixture from conftest.py
   so that the real SQLAlchemy session handles Schedule creation in the
   in-memory SQLite test database.
"""

import io

import pytest

from app.files import validate_upload, upload


# ── Helpers: mock file objects ────────────────────────────────────────────────

def csv_bytes(*rows) -> bytes:
    """Build a CSV byte string with a standard header + supplied data rows."""
    header = "Name,Amount,Type,Frequency,Next Date,First Date\n"
    return (header + "\n".join(rows)).encode("utf-8")


class _FakeFile(io.BytesIO):
    """
    Minimal stub that looks like a werkzeug FileStorage object.

    Inherits from BytesIO so that TextIOWrapper (used inside upload()) can
    wrap it directly.  Extra attributes ``filename`` and ``mimetype`` are
    added to satisfy validate_upload().
    """

    def __init__(self, filename: str, content: bytes, mimetype: str = "text/csv"):
        super().__init__(content)
        self.filename = filename
        self.mimetype = mimetype


def make_file(filename, content, mimetype="text/csv"):
    return _FakeFile(filename, content, mimetype)


# ── Tests: validate_upload ────────────────────────────────────────────────────


class TestValidateUpload:
    def test_none_file_returns_error(self):
        ok, err = validate_upload(None)
        assert ok is False
        assert err

    def test_empty_filename_returns_error(self):
        f = make_file("", b"")
        ok, err = validate_upload(f)
        assert ok is False
        assert err

    def test_non_csv_extension_returns_error(self):
        f = make_file("data.xlsx", b"", mimetype="application/vnd.ms-excel")
        ok, err = validate_upload(f)
        assert ok is False
        assert "csv" in err.lower()

    def test_wrong_mime_type_returns_error(self):
        # Extension is .csv but MIME type signals something unexpected
        f = make_file("data.csv", b"", mimetype="application/octet-stream")
        ok, err = validate_upload(f)
        assert ok is False

    def test_file_too_large_returns_error(self):
        big = b"x" * (1024 * 1024 + 1)  # 1 MB + 1 byte
        f = make_file("big.csv", big)
        ok, err = validate_upload(f)
        assert ok is False
        # The error message should mention size in some form
        assert any(w in err.lower() for w in ("large", "size", "kb", "mb"))

    def test_valid_csv_file_passes(self):
        content = csv_bytes("Salary,3000,Income,Monthly,2025-01-01,2025-01-01")
        f = make_file("schedules.csv", content)
        ok, err = validate_upload(f)
        assert ok is True
        assert err is None

    def test_valid_csv_with_text_plain_mime_passes(self):
        content = csv_bytes("Rent,1000,Expense,Monthly,2025-01-01,2025-01-01")
        f = make_file("schedules.csv", content, mimetype="text/plain")
        ok, err = validate_upload(f)
        assert ok is True


# ── Tests: CSV row parsing via upload() ──────────────────────────────────────
# upload() calls Schedule.query and db.session — these require a Flask app
# context.  The ``app_ctx`` fixture (from conftest.py) pushes one and provides
# access to the in-memory SQLite test database.
#
# Each test imports into its own freshly created user (``uid`` fixture) so
# rows never collide across tests and the user_id foreign key is satisfied
# on databases that enforce it (PostgreSQL in CI).


@pytest.fixture()
def uid(make_user):
    return make_user()


class TestCSVParsing:
    def test_valid_row_counts_as_success(self, app_ctx, uid):
        f = make_file("t.csv", csv_bytes("Salary,3000.00,Income,Monthly,2025-03-01,2025-03-01"))
        success, errors = upload(f, user_id=uid)
        assert success == 1
        assert errors == 0

    def test_multiple_valid_rows_all_succeed(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes(
                "Salary,3000,Income,Monthly,2025-03-01,2025-03-01",
                "Rent,1200,Expense,Monthly,2025-03-05,2025-03-05",
                "Bonus,5000,Income,Onetime,2025-06-01,2025-06-01",
            ),
        )
        success, errors = upload(f, user_id=uid)
        assert success == 3
        assert errors == 0

    def test_row_with_too_few_columns_counts_as_error(self, app_ctx, uid):
        f = make_file("t.csv", csv_bytes("Salary,3000,Income,Monthly"))  # only 4 cols
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_invalid_type_counts_as_error(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes("Salary,3000,Payment,Monthly,2025-03-01,2025-03-01"),  # 'Payment' is invalid
        )
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_invalid_frequency_counts_as_error(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes("Salary,3000,Income,Fortnightly,2025-03-01,2025-03-01"),
        )
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_non_numeric_amount_counts_as_error(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes("Salary,three_thousand,Income,Monthly,2025-03-01,2025-03-01"),
        )
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_invalid_date_format_counts_as_error(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes("Salary,3000,Income,Monthly,01/03/2025,01/03/2025"),  # wrong format
        )
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_empty_name_counts_as_error(self, app_ctx, uid):
        f = make_file("t.csv", csv_bytes(",3000,Income,Monthly,2025-03-01,2025-03-01"))
        success, errors = upload(f, user_id=uid)
        assert errors == 1
        assert success == 0

    def test_all_valid_frequencies_are_accepted(self, app_ctx, uid):
        """Every documented frequency value must be accepted by the parser."""
        valid_frequencies = [
            "Monthly", "Quarterly", "Yearly", "Weekly", "BiWeekly", "Onetime"
        ]
        for freq in valid_frequencies:
            f = make_file("t.csv", csv_bytes(f"Item{freq},100,Income,{freq},2025-03-01,2025-03-01"))
            success, errors = upload(f, user_id=uid)
            assert success == 1, f"Frequency '{freq}' should be valid but got errors={errors}"
            assert errors == 0

    def test_mixed_valid_and_invalid_rows_counted_separately(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes(
                "Salary,3000,Income,Monthly,2025-03-01,2025-03-01",    # valid
                "Broken,abc,Expense,Monthly,2025-03-01,2025-03-01",    # invalid amount
                "Rent,1000,Expense,Monthly,2025-03-05,2025-03-05",     # valid
                "Bad,100,Income,EverySunday,2025-03-01,2025-03-01",    # invalid frequency
            ),
        )
        success, errors = upload(f, user_id=uid)
        assert success == 2
        assert errors == 2

    def test_both_income_and_expense_types_accepted(self, app_ctx, uid):
        f = make_file(
            "t.csv",
            csv_bytes(
                "Salary,3000,Income,Monthly,2025-03-01,2025-03-01",
                "Rent,1000,Expense,Monthly,2025-03-05,2025-03-05",
            ),
        )
        success, errors = upload(f, user_id=uid)
        assert success == 2
        assert errors == 0

    def test_amount_with_decimal_places_accepted(self, app_ctx, uid):
        f = make_file("t.csv", csv_bytes("Salary,3000.50,Income,Monthly,2025-03-01,2025-03-01"))
        success, errors = upload(f, user_id=uid)
        assert success == 1
        assert errors == 0
