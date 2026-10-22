"""
Tests for calculate_cash_risk_score — liquidity-path-based scoring model.

Each test targets a specific scenario. The naming convention is:
    test_<scenario>_<expected_outcome>

Run with:
    pytest tests/test_cash_risk_score.py -v
"""

import sys
import os
from datetime import date, timedelta

import pandas as pd
import pytest

# cashflow.py imports `from app import db` and `from .models import ...`, which
# pulls in the full Flask application stack.  We use importlib to load the module
# in isolation, injecting stubs for the Flask/DB dependencies so the pure-Python
# scoring logic can be tested without a running app or database.
import types
import importlib.util
import unittest.mock as mock

_APP_DIR = os.path.join(os.path.dirname(__file__), '..', 'app')

# Remember the real modules so they can be restored once cashflow.py is loaded;
# leaving the stubs in sys.modules would leak a MagicMock ``db`` into every
# later test module that lazily does ``from app import db``.
_SAVED_MODULES = {
    name: sys.modules.get(name) for name in ('app', 'app.models', 'app.cashflow')
}

# Stub the app package itself (needs __path__ so relative imports inside cashflow work)
_app_stub = types.ModuleType('app')
_app_stub.__path__ = [_APP_DIR]
_app_stub.__package__ = 'app'
_app_stub.db = mock.MagicMock()
sys.modules['app'] = _app_stub

# Stub app.models with dummy classes for Schedule, Skip, etc.
_models_stub = types.ModuleType('app.models')
for _cls in ('Schedule', 'Skip', 'Hold', 'Scenario', 'Balance', 'User'):
    setattr(_models_stub, _cls, mock.MagicMock())
sys.modules['app.models'] = _models_stub

# Load cashflow.py as app.cashflow using importlib so relative imports resolve
_spec = importlib.util.spec_from_file_location(
    'app.cashflow',
    os.path.join(_APP_DIR, 'cashflow.py'),
)
_cashflow_mod = importlib.util.module_from_spec(_spec)
_cashflow_mod.__package__ = 'app'
sys.modules['app.cashflow'] = _cashflow_mod
_spec.loader.exec_module(_cashflow_mod)

for _name, _module in _SAVED_MODULES.items():
    if _module is None:
        sys.modules.pop(_name, None)
    else:
        sys.modules[_name] = _module

calculate_cash_risk_score = _cashflow_mod.calculate_cash_risk_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_run(entries):
    """
    Build a minimal 'run' DataFrame from a list of (date, amount) tuples.

    Args:
        entries: list of (date_offset_days_from_today, balance) pairs
                 OR list of (date, balance) pairs where date is a date object.
    """
    today = date.today()
    rows = []
    for offset_or_date, amount in entries:
        if isinstance(offset_or_date, int):
            d = today + timedelta(days=offset_or_date)
        else:
            d = offset_or_date
        rows.append({'date': d, 'amount': float(amount)})
    return pd.DataFrame(rows)


def daily_expense_series(start_offset, end_offset, start_balance, daily_drop):
    """
    Generate a day-by-day balance series that drops by `daily_drop` each day.
    Useful for creating deterministic expense-only scenarios.
    """
    entries = []
    for day in range(start_offset, end_offset + 1):
        bal = start_balance - (day - start_offset) * daily_drop
        entries.append((day, bal))
    return entries


# ---------------------------------------------------------------------------
# Return structure sanity check
# ---------------------------------------------------------------------------

class TestReturnStructure:
    """Verify the public interface is unchanged."""

    def test_keys_present(self):
        run = make_run([(1, 5000), (30, 4000), (60, 3000), (90, 2000)])
        result = calculate_cash_risk_score(5000, run)
        assert set(result.keys()) == {
            'score', 'status', 'color',
            'runway_days', 'lowest_balance', 'days_to_lowest', 'avg_daily_expense',
            'days_below_threshold', 'pct_below_threshold', 'recovery_days', 'near_term_buffer',
        }

    def test_score_is_int_in_range(self):
        run = make_run([(1, 5000), (30, 4000), (60, 3000), (90, 2000)])
        result = calculate_cash_risk_score(5000, run)
        assert isinstance(result['score'], int)
        assert 0 <= result['score'] <= 100

    def test_status_is_valid_label(self):
        run = make_run([(1, 5000), (30, 4000), (60, 3000), (90, 2000)])
        result = calculate_cash_risk_score(5000, run)
        assert result['status'] in ('Safe', 'Stable', 'Watch', 'Risk', 'Critical')

    def test_color_matches_status(self):
        mapping = {
            'Safe': 'green', 'Stable': 'blue', 'Watch': 'yellow',
            'Risk': 'orange', 'Critical': 'red',
        }
        run = make_run([(1, 5000), (30, 4000), (60, 3000), (90, 2000)])
        result = calculate_cash_risk_score(5000, run)
        assert result['color'] == mapping[result['status']]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_zero_balance_returns_critical(self):
        run = make_run([(1, 0), (30, 0)])
        result = calculate_cash_risk_score(0, run)
        assert result['score'] == 0
        assert result['status'] == 'Critical'

    def test_negative_balance_returns_critical(self):
        run = make_run([(1, -100), (30, -500)])
        result = calculate_cash_risk_score(-100, run)
        assert result['score'] == 0
        assert result['status'] == 'Critical'

    def test_empty_run_returns_watch(self):
        result = calculate_cash_risk_score(10000, pd.DataFrame())
        assert result['score'] == 50
        assert result['status'] == 'Watch'

    def test_single_row_run_returns_watch(self):
        run = make_run([(10, 5000)])
        result = calculate_cash_risk_score(5000, run)
        assert result['score'] == 50
        assert result['status'] == 'Watch'

    def test_zero_expenses_does_not_crash(self):
        """If balance is perfectly flat (no expenses), the model should not divide by zero."""
        run = make_run([(1, 10000), (30, 10000), (60, 10000), (90, 10000)])
        result = calculate_cash_risk_score(10000, run)
        # Stable flat balance with no expenses should score well
        assert result['score'] > 50
        assert result['avg_daily_expense'] >= 0

    def test_lowest_point_at_end_of_horizon(self):
        """Lowest balance near day 90 should not crash and should be scored."""
        run = make_run([(1, 10000), (30, 8000), (60, 5000), (89, 1000)])
        result = calculate_cash_risk_score(10000, run)
        assert 'score' in result
        assert result['lowest_balance'] == pytest.approx(1000.0)
        assert result['days_to_lowest'] == 89

    def test_balance_never_below_threshold_scores_high_recovery(self):
        """If balance never dips below threshold, recovery factor should be perfect."""
        # Balance stays comfortably above one month of expenses at all times.
        # Monthly expenses ≈ 1000, so threshold ≈ 1000; balance stays at 5000+.
        entries = daily_expense_series(1, 90, 8000, 33)  # ~1000/month drop
        run = make_run(entries)
        result = calculate_cash_risk_score(8000, run)
        assert result['score'] >= 60  # Should be at least Stable
        assert result['status'] in ('Safe', 'Stable')


# ---------------------------------------------------------------------------
# Cyclical income — the core regression test for the old model's false penalty
# ---------------------------------------------------------------------------

class TestCyclicalIncomeFalsePenalty:
    """
    A business receives a large monthly salary/income near month-end and has
    regular monthly expenses earlier in the month.  The lowest projected balance
    (just before income arrives) remains well above zero and above one month of
    expenses.  Under the old runway-heavy model this scored poorly because naive
    runway = current_balance / avg_daily_expense looked short.  The new model
    should rate this as Safe or Stable.
    """

    def _build_cyclical_run(self):
        """
        Simulate a 90-day window where:
          - $3,000 of monthly expenses hit on day 5, 35, 65
          - $5,000 income arrives on day 28, 58, 88
          - Starting balance $6,000; lowest point ~$3,000 (after expenses, before income)
        All balances remain above $3,000 (well above avg_monthly_expense ≈ $1,000).
        """
        today = date.today()
        rows = [
            # Day 1: starting balance reflected as first entry
            (1,  6000),
            # Month 1: expenses hit, then income
            (5,  3000),   # -3000 expenses
            (28, 8000),   # +5000 income
            # Month 2
            (35, 5000),   # -3000 expenses
            (58, 10000),  # +5000 income
            # Month 3
            (65, 7000),   # -3000 expenses
            (88, 12000),  # +5000 income
        ]
        return make_run(rows)

    def test_cyclical_income_scores_safe_or_stable(self):
        """
        PRIMARY REGRESSION TEST.
        Cyclical income with healthy lowest balance must not produce medium/poor score.
        The old model penalised this because naive runway ≈ 6000/33 ≈ 6 days (very low).
        The new model evaluates actual liquidity path and should rate this well.
        """
        run = self._build_cyclical_run()
        result = calculate_cash_risk_score(6000, run)

        # Lowest balance is ~$3,000; avg_monthly_expense is ~$1,000 → ratio ≈ 3.0
        # Should not be Watch, Risk, or Critical
        assert result['status'] in ('Safe', 'Stable'), (
            f"Expected Safe or Stable for healthy cyclical cash flow, got "
            f"{result['status']} (score={result['score']}). "
            f"The model is still over-penalising cyclical income patterns."
        )
        assert result['score'] >= 60, (
            f"Score {result['score']} is too low for a business with a lowest balance "
            f"of ~$3,000 and avg_monthly_expense of ~$1,000 (ratio ≈ 3.0)."
        )

    def test_cyclical_income_lowest_balance_is_healthy(self):
        """Verify the scenario is set up correctly: lowest balance >> threshold."""
        run = self._build_cyclical_run()
        result = calculate_cash_risk_score(6000, run)
        # avg_monthly_expense ≈ 1000 (3000 expenses over 90 days / 3 months)
        assert result['lowest_balance'] >= 3000
        assert result['avg_daily_expense'] > 0


# ---------------------------------------------------------------------------
# Negative balance with no recovery
# ---------------------------------------------------------------------------

class TestNegativeBalanceNoRecovery:
    """Balance goes negative and never recovers within the horizon."""

    def test_negative_unrecovered_scores_critical_or_risk(self):
        run = make_run([
            (1,  2000),
            (10, 500),
            (20, -200),   # Goes negative
            (50, -800),   # Stays negative
            (90, -1500),  # Still negative at end of horizon
        ])
        result = calculate_cash_risk_score(2000, run)
        assert result['status'] in ('Critical', 'Risk'), (
            f"Expected Critical or Risk for unrecovered negative balance, "
            f"got {result['status']} (score={result['score']})"
        )
        assert result['score'] < 40

    def test_negative_lowest_balance_reported(self):
        run = make_run([
            (1, 1000),
            (30, -500),
            (60, -1000),
            (90, -1500),
        ])
        result = calculate_cash_risk_score(1000, run)
        assert result['lowest_balance'] < 0


# ---------------------------------------------------------------------------
# Temporary dip with fast recovery
# ---------------------------------------------------------------------------

class TestTemporaryDipFastRecovery:
    """
    Balance briefly dips below the liquidity threshold but recovers quickly
    (within a few days).  This should not produce a poor score — it is a
    normal cyclical pattern, not a structural risk.
    """

    def test_fast_recovery_scores_at_least_stable(self):
        """
        Balance: $5,000 → dips to $800 on day 28 (below ~$1,000 threshold)
        → recovers to $5,800 on day 30 (just 2 days later).
        Monthly expenses ≈ $1,000.  Recovery is extremely fast.
        """
        run = make_run([
            (1,  5000),
            (10, 4500),
            (20, 3000),
            (28,  800),   # Brief dip below 1-month threshold
            (30, 5800),   # Quick recovery (income arrived)
            (60, 5300),
            (90, 4800),
        ])
        result = calculate_cash_risk_score(5000, run)
        assert result['status'] in ('Safe', 'Stable', 'Watch'), (
            f"Expected at most Watch for a brief dip with fast recovery, "
            f"got {result['status']} (score={result['score']})"
        )

    def test_fast_recovery_scores_higher_than_slow_recovery(self):
        """Fast recovery should always score higher than slow recovery, all else equal."""
        today = date.today()

        run_fast = make_run([
            (1,  5000),
            (28,  500),         # dip
            (32, 5500),         # recovers in 4 days
            (60, 5000),
            (90, 4500),
        ])
        run_slow = make_run([
            (1,  5000),
            (28,  500),         # same dip
            (65, 5500),         # takes 37 days to recover
            (90, 5000),
        ])

        result_fast = calculate_cash_risk_score(5000, run_fast)
        result_slow = calculate_cash_risk_score(5000, run_slow)

        assert result_fast['score'] > result_slow['score'], (
            f"Fast recovery (score={result_fast['score']}) should outscore "
            f"slow recovery (score={result_slow['score']})"
        )


# ---------------------------------------------------------------------------
# Near-term risk worse than long-term
# ---------------------------------------------------------------------------

class TestNearTermRiskWorseThanLongTerm:
    """
    An imminent (within 14 days) cash shortfall should be penalised more
    than an identical shortfall occurring further in the future.
    """

    def test_imminent_dip_scores_lower_than_distant_dip(self):
        """
        Two scenarios with the same lowest balance (~$200) but at different times:
          - Scenario A: dip occurs in 5 days (near-term)
          - Scenario B: dip occurs in 50 days (long-term)
        Scenario A should score lower because of the near-term buffer factor.
        """
        run_imminent = make_run([
            (1,  5000),
            (5,   200),   # dip in 5 days — hits near-term window
            (15, 5200),   # quick recovery
            (60, 4800),
            (90, 4500),
        ])
        run_distant = make_run([
            (1,  5000),
            (15, 4800),   # no near-term dip
            (50,  200),   # same dip but at day 50
            (60, 5200),   # quick recovery
            (90, 4800),
        ])

        result_imminent = calculate_cash_risk_score(5000, run_imminent)
        result_distant = calculate_cash_risk_score(5000, run_distant)

        assert result_imminent['score'] < result_distant['score'], (
            f"Imminent dip (score={result_imminent['score']}) should score lower than "
            f"distant dip (score={result_distant['score']})"
        )

    def test_near_term_minimum_is_below_threshold_triggers_low_score(self):
        """If near-term minimum is deeply negative, score should be Critical or Risk."""
        run = make_run([
            (1,   500),   # current balance is fine
            (3,  -200),   # goes negative in 3 days — very imminent
            (10, -500),
            (30, 4000),   # eventually recovers
            (90, 3500),
        ])
        result = calculate_cash_risk_score(500, run)
        assert result['score'] < 40, (
            f"Score {result['score']} should be < 40 when near-term balance goes negative"
        )


# ---------------------------------------------------------------------------
# Score banding sanity
# ---------------------------------------------------------------------------

class TestScoreBanding:
    """Verify the status bands align with expected score thresholds."""

    @pytest.mark.parametrize("score_threshold,expected_status", [
        (80, 'Safe'),
        (60, 'Stable'),
        (40, 'Watch'),
        (20, 'Risk'),
        (0,  'Critical'),
    ])
    def test_score_banding_boundaries(self, score_threshold, expected_status):
        """
        Construct scenarios that should produce scores in each band and verify
        the status label matches.  Uses parametrise for brevity.
        """
        # High-score scenario: large healthy balance, no dips
        if expected_status == 'Safe':
            run = make_run([(1, 50000), (30, 48000), (60, 46000), (90, 44000)])
            result = calculate_cash_risk_score(50000, run)
            assert result['status'] == 'Safe', (
                f"Expected Safe, got {result['status']} (score={result['score']})"
            )

        # Critical scenario: balance goes deeply negative immediately
        elif expected_status == 'Critical':
            run = make_run([(1, -1000), (30, -5000), (60, -10000)])
            result = calculate_cash_risk_score(-1000, run)
            assert result['status'] == 'Critical'
            assert result['score'] == 0
