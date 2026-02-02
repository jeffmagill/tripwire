"""
Tests for tripwire.

Run: YNAB_TOKEN=x PUSHOVER_API_TOKEN=x PUSHOVER_USER_KEYS=x GITHUB_TOKEN=x GITHUB_REPOSITORY=x python tests.py
Or:  python -m pytest tests.py -v   (if you have pytest installed)
"""

import os
import sys
from datetime import datetime, timezone, timedelta

# Stub env vars before importing alerts (they're read at module level)
for key in ("YNAB_TOKEN", "YNAB_BUDGET_ID", "PUSHOVER_API_TOKEN", "PUSHOVER_USER_KEYS", "GITHUB_TOKEN", "GITHUB_REPOSITORY"):
    os.environ.setdefault(key, "test-stub")

from alerts import (
    # Parsing
    parse_threshold,
    # Low-level evaluators
    evaluate_goal_threshold,
    evaluate_pacing,
    milliunits_to_dollars,
    # Rule-level evaluators
    evaluate_goal_threshold_rule,
    evaluate_pacing_rule,
    # Category-level dispatcher
    evaluate_category,
    # State
    should_alert,
    record_firing,
    prune_old_months,
    current_month_key,
    # Config
    load_config,
    build_final_category_config,
    # Types
    Firing,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ynab_category(budgeted: int | None = 1000000, activity: int = 0, balance: int | None = None, cat_id: str = "cat-1", goal_target: int | None = None) -> dict:
    """Build a minimal YNAB category dict.

    budgeted: amount assigned this month (in milliunits) - used for spending_limit: auto
    activity: transaction activity (negative for spending/outflows, positive for income)
    balance: category balance (defaults to budgeted + activity)
    goal_target: optional YNAB goal (for savings goals, not spending limits)
    """
    if balance is None:
        balance = (budgeted or 0) + activity
    return {
        "id": cat_id,
        "budgeted": budgeted,
        "activity": activity,
        "balance": balance,
        "goal_target": goal_target,
    }


def april(day: int, hour: int = 12) -> datetime:
    """Shorthand for a datetime in April 2026 (30-day month, clean math)."""
    return datetime(2026, 4, day, hour, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 1. Config loading
# ---------------------------------------------------------------------------

def test_config_loads():
    cfg = load_config()
    assert "budget_id" in cfg
    assert "auto_alerts" in cfg
    assert len(cfg["categories"]) >= 2  # At least Groceries and Car Maintenance
    for name, cat in cfg["categories"].items():
        for rule in cat.get("rules", []):
            assert "min_hours_between_alerts" in rule, f"{name}: missing min_hours_between_alerts"
            assert "once_per_trigger" not in rule,     f"{name}: stale once_per_trigger still present"


def test_auto_alerts_disabled():
    """When auto_alerts is disabled, only explicit categories are returned."""
    config = {"categories": {"Groceries": {"rules": []}}, "auto_alerts": {"enabled": False}}
    cat_map = {
        "Groceries": {"budgeted": 100000},
        "Dining Out": {"budgeted": 50000},  # has budgeted but should not be auto-added
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 1
    assert "Groceries" in final
    assert "Dining Out" not in final


def test_auto_alerts_enabled():
    """When auto_alerts is enabled, categories with budgeted amounts are auto-detected."""
    config = {
        "categories": {"Groceries": {"rules": []}},
        "auto_alerts": {
            "enabled": True,
            "spending_limit": "auto",
            "rules": [{"type": "goal_threshold", "min_hours_between_alerts": 744, "triggers": []}],
        },
    }
    cat_map = {
        "Groceries": {"budgeted": 100000},  # explicit, should not be duplicated
        "Dining Out": {"budgeted": 50000},  # has budgeted, should be auto-added
        "Vacation": {"budgeted": None},     # no budgeted, should not be added
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 2
    assert "Groceries" in final
    assert "Dining Out" in final
    assert "Vacation" not in final
    assert final["Dining Out"]["_auto_detected"] is True
    assert final["Dining Out"]["spending_limit"] == "auto"


def test_auto_alerts_exclude_list():
    """Categories in the exclude list are not auto-detected."""
    config = {
        "categories": {},
        "auto_alerts": {
            "enabled": True,
            "exclude": ["Dining Out"],
            "spending_limit": "auto",
            "rules": [{"type": "goal_threshold", "min_hours_between_alerts": 744, "triggers": []}],
        },
    }
    cat_map = {
        "Groceries": {"budgeted": 100000},
        "Dining Out": {"budgeted": 50000},  # excluded
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 1
    assert "Groceries" in final
    assert "Dining Out" not in final


def test_auto_alerts_skips_zero_budgeted():
    """Categories with zero or null budgeted amounts are not auto-detected."""
    config = {
        "categories": {},
        "auto_alerts": {
            "enabled": True,
            "spending_limit": "auto",
            "rules": [{"type": "goal_threshold", "min_hours_between_alerts": 744, "triggers": []}],
        },
    }
    cat_map = {
        "Groceries": {"budgeted": 100000},   # valid budgeted amount
        "Clothing": {"budgeted": 0},         # zero budgeted - should skip
        "Vacation": {"budgeted": None},      # no budgeted - should skip
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 1
    assert "Groceries" in final
    assert "Clothing" not in final  # zero budgeted should be skipped
    assert "Vacation" not in final  # null budgeted should be skipped


# ---------------------------------------------------------------------------
# 2. Threshold parsing
# ---------------------------------------------------------------------------

def test_parse_threshold_percent_spent():
    assert parse_threshold("75%")  == ("percent_spent", 75.0)
    assert parse_threshold("100%") == ("percent_spent", 100.0)
    assert parse_threshold("0%")   == ("percent_spent", 0.0)
    assert parse_threshold("33.5%") == ("percent_spent", 33.5)


def test_parse_threshold_dollars_remaining():
    assert parse_threshold("$200 remaining")     == ("dollars_remaining", 200.0)
    assert parse_threshold("$0 remaining")       == ("dollars_remaining", 0.0)
    assert parse_threshold("$50.50 remaining")   == ("dollars_remaining", 50.50)
    assert parse_threshold("$1000 Remaining")    == ("dollars_remaining", 1000.0)  # case-insensitive


def test_parse_threshold_percent_over():
    assert parse_threshold("5% over")   == ("percent_over", 5.0)
    assert parse_threshold("0% over")   == ("percent_over", 0.0)
    assert parse_threshold("20% over")  == ("percent_over", 20.0)
    assert parse_threshold("12.5% over") == ("percent_over", 12.5)
    assert parse_threshold("10 % over") == ("percent_over", 10.0)  # space before %


def test_parse_threshold_invalid():
    for bad in ("foo", "75", "$200", "over 5%", "remaining $50", ""):
        try:
            parse_threshold(bad)
            assert False, f"Should have raised ValueError for '{bad}'"
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# 3. Low-level: evaluate_goal_threshold
# ---------------------------------------------------------------------------

def test_goal_threshold_percent_spent():
    # $800 spent of $1000 limit = 80%
    # Activity is NEGATIVE for spending (outflows)
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    assert evaluate_goal_threshold(cat, {"at": "75%"}, cat_config)  == True   # 80 >= 75
    assert evaluate_goal_threshold(cat, {"at": "80%"}, cat_config)  == True   # 80 >= 80
    assert evaluate_goal_threshold(cat, {"at": "81%"}, cat_config)  == False  # 80 < 81


def test_goal_threshold_dollars_remaining():
    # $1000 budgeted, $800 spent (negative activity), $200 remaining
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    assert evaluate_goal_threshold(cat, {"at": "$200 remaining"}, cat_config) == True   # 200 <= 200
    assert evaluate_goal_threshold(cat, {"at": "$250 remaining"}, cat_config) == True   # 200 <= 250
    assert evaluate_goal_threshold(cat, {"at": "$150 remaining"}, cat_config) == False  # 200 > 150


def test_goal_threshold_no_spending_limit():
    # No budgeted amount, no spending limit
    cat = make_ynab_category(budgeted=None, activity=-500000)
    cat_config = {"spending_limit": "auto"}
    assert evaluate_goal_threshold(cat, {"at": "50%"}, cat_config) == False


def test_goal_threshold_zero_spending_limit():
    # Zero spending limit is meaningless - treat same as no spending limit
    cat = make_ynab_category(budgeted=0, activity=0)
    cat_config = {"spending_limit": "auto"}
    assert evaluate_goal_threshold(cat, {"at": "50%"}, cat_config) == False
    assert evaluate_goal_threshold(cat, {"at": "75%"}, cat_config) == False
    # Even with activity, zero spending limit should never trigger
    cat_with_activity = make_ynab_category(budgeted=0, activity=-100000)
    assert evaluate_goal_threshold(cat_with_activity, {"at": "50%"}, cat_config) == False


# ---------------------------------------------------------------------------
# 4. Low-level: evaluate_pacing
# ---------------------------------------------------------------------------

def test_pacing_over():
    # April (30 days), day 15, $600 spent (negative activity), limit $1000
    # projected = 600 * 30/15 = $1200 → 20% over
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    now = april(15)

    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, cat_config, now)
    assert fired == True
    assert abs(ctx["percent_over"] - 20.0) < 0.01
    assert ctx["days_in_month"] == 30
    assert ctx["days_elapsed"] == 15

    fired, _ = evaluate_pacing(cat, {"at": "20% over"}, cat_config, now)
    assert fired == True   # exactly 20, >= 20

    fired, _ = evaluate_pacing(cat, {"at": "25% over"}, cat_config, now)
    assert fired == False  # 20 < 25


def test_pacing_on_pace():
    # $500 spent by day 15 of 30 → projected = $1000 → 0% over
    cat = make_ynab_category(budgeted=1000000, activity=-500000)
    cat_config = {"spending_limit": "auto"}
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, cat_config, april(15))
    assert fired == False
    assert abs(ctx["percent_over"] - 0.0) < 0.01


def test_pacing_under_pace():
    # $300 spent by day 15 of 30 → projected = $600 → -40% over (under)
    cat = make_ynab_category(budgeted=1000000, activity=-300000)
    cat_config = {"spending_limit": "auto"}
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, cat_config, april(15))
    assert fired == False
    assert ctx["percent_over"] < 0


def test_pacing_no_spending_limit():
    cat = make_ynab_category(budgeted=None, activity=-500000)
    cat_config = {"spending_limit": "auto"}
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, cat_config, april(15))
    assert fired == False
    assert ctx == {}


def test_pacing_zero_spending_limit():
    cat = make_ynab_category(budgeted=0, activity=-500000)
    cat_config = {"spending_limit": "auto"}
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, cat_config, april(15))
    assert fired == False
    assert ctx == {}


def test_pacing_invalid_trigger_syntax():
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    try:
        evaluate_pacing(cat, {"at": "75%"}, cat_config, april(15))  # wrong syntax for pacing
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# 5. State: should_alert / record_firing / prune
# ---------------------------------------------------------------------------

def test_should_alert_never_fired():
    state = {}
    now = april(15)
    assert should_alert(state, "Groceries", "75%", 24, now) == True


def test_should_alert_cooldown_active():
    now = april(15, 12)
    state = {}
    record_firing(state, "Groceries", "75%", now)
    # Immediately after firing → cooldown active
    assert should_alert(state, "Groceries", "75%", 24, now) == False
    # 23 hours later → still active
    assert should_alert(state, "Groceries", "75%", 24, now + timedelta(hours=23)) == False


def test_should_alert_cooldown_expired():
    now = april(15, 12)
    state = {}
    record_firing(state, "Groceries", "75%", now)
    # 25 hours later → expired
    assert should_alert(state, "Groceries", "75%", 24, now + timedelta(hours=25)) == True


def test_should_alert_different_triggers_independent():
    now = april(15)
    state = {}
    record_firing(state, "Groceries", "75%", now)
    # "90%" on same category is unaffected
    assert should_alert(state, "Groceries", "90%", 24, now) == True


def test_should_alert_different_categories_independent():
    now = april(15)
    state = {}
    record_firing(state, "Groceries", "75%", now)
    # Same trigger key on different category is unaffected
    assert should_alert(state, "Dining Out", "75%", 24, now) == True


def test_prune_old_months():
    state = {
        "fired": {
            "2026-02": {"Groceries:75%": "2026-02-15T12:00:00+00:00"},
            "2026-03": {"Groceries:75%": "2026-03-15T12:00:00+00:00"},
            "2026-04": {"Groceries:75%": "2026-04-15T12:00:00+00:00"},
        }
    }
    prune_old_months(state, april(15))
    assert "2026-02" not in state["fired"]
    assert "2026-03" not in state["fired"]
    assert "2026-04" in state["fired"]  # current month preserved


# ---------------------------------------------------------------------------
# 6. Rule-level: evaluate_goal_threshold_rule
# ---------------------------------------------------------------------------

def test_goal_threshold_rule_fires_matching_triggers():
    # 80% spent. Rule has triggers at 75% (should fire) and 90% (should not).
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [
            {"at": "75%", "severity": "warning"},
            {"at": "90%", "severity": "urgent"},
        ],
    }
    state = {}
    now = april(15)

    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, cat_config, state, now)
    assert len(firings) == 1
    assert firings[0].trigger["at"] == "75%"
    assert firings[0].trigger["severity"] == "warning"
    assert firings[0].category_name == "Groceries"


def test_goal_threshold_rule_respects_cooldown():
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [{"at": "75%", "severity": "warning"}],
    }
    now = april(15)
    state = {}
    record_firing(state, "Groceries", "75%", now)

    # Should not fire again — cooldown active
    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, cat_config, state, now)
    assert len(firings) == 0


def test_goal_threshold_rule_no_spending_limit_returns_empty():
    cat = make_ynab_category(budgeted=None, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [{"at": "75%", "severity": "warning"}],
    }
    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, cat_config, {}, april(15))
    assert len(firings) == 0


def test_goal_threshold_rule_zero_spending_limit_returns_empty():
    """Zero spending limit should be treated like no spending limit - return empty and warn."""
    cat = make_ynab_category(budgeted=0, activity=-100000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [{"at": "75%", "severity": "warning"}],
    }
    firings = evaluate_goal_threshold_rule("Clothing", rule, cat, cat_config, {}, april(15))
    assert len(firings) == 0  # Should not trigger on zero spending limit


# ---------------------------------------------------------------------------
# 7. Rule-level: evaluate_pacing_rule
# ---------------------------------------------------------------------------

def test_pacing_rule_fires_when_over_pace():
    # April day 15, $600 spent of $1000 limit → 20% over
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "pacing",
        "warm_up_hours": 72,
        "min_hours_between_alerts": 24,
        "triggers": [
            {"at": "5% over",  "severity": "warning"},
            {"at": "25% over", "severity": "urgent"},   # 20 < 25, should not fire
        ],
    }
    now = april(15)
    # hours_into_month for april 15 = 14 days * 24 + 12 = 348h, well past warm-up
    hours_into_month = (now - datetime(2026, 4, 1, tzinfo=timezone.utc)).total_seconds() / 3600

    firings = evaluate_pacing_rule("Groceries", rule, cat, cat_config, {}, now, hours_into_month)
    assert len(firings) == 1
    assert firings[0].trigger["at"] == "5% over"
    assert firings[0].pacing_context["percent_over"] == pytest_approx(20.0)


def test_pacing_rule_blocked_by_warm_up():
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "pacing",
        "warm_up_hours": 72,
        "min_hours_between_alerts": 24,
        "triggers": [{"at": "5% over", "severity": "warning"}],
    }
    # Only 48 hours into the month — warm_up_hours is 72
    firings = evaluate_pacing_rule("Groceries", rule, cat, cat_config, {}, april(2, 0), hours_into_month=48.0)
    assert len(firings) == 0


def test_pacing_rule_respects_cooldown():
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "pacing",
        "warm_up_hours": 72,
        "min_hours_between_alerts": 24,
        "triggers": [{"at": "5% over", "severity": "warning"}],
    }
    now = april(15)
    hours_into_month = (now - datetime(2026, 4, 1, tzinfo=timezone.utc)).total_seconds() / 3600
    state = {}
    record_firing(state, "Groceries", "5% over", now)

    firings = evaluate_pacing_rule("Groceries", rule, cat, cat_config, state, now, hours_into_month)
    assert len(firings) == 0


def test_pacing_rule_re_alerts_after_cooldown():
    cat = make_ynab_category(budgeted=1000000, activity=-600000)
    cat_config = {"spending_limit": "auto"}
    rule = {
        "type": "pacing",
        "warm_up_hours": 72,
        "min_hours_between_alerts": 24,
        "triggers": [{"at": "5% over", "severity": "warning"}],
    }
    now = april(15)
    hours_into_month = (now - datetime(2026, 4, 1, tzinfo=timezone.utc)).total_seconds() / 3600
    state = {}
    # Fired 25 hours ago → cooldown expired
    record_firing(state, "Groceries", "5% over", now - timedelta(hours=25))

    firings = evaluate_pacing_rule("Groceries", rule, cat, cat_config, state, now, hours_into_month)
    assert len(firings) == 1


# ---------------------------------------------------------------------------
# 8. Category-level: evaluate_category
# ---------------------------------------------------------------------------

def test_evaluate_category_disabled():
    cat_config = {
        "spending_limit": "auto",
        "enabled": False,
        "rules": [
            {"type": "goal_threshold", "min_hours_between_alerts": 744,
             "triggers": [{"at": "75%", "severity": "warning"}]},
        ],
    }
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 0


def test_evaluate_category_unknown_rule_type():
    cat_config = {
        "spending_limit": "auto",
        "enabled": True,
        "rules": [
            {"type": "unknown_future_type", "triggers": [{"at": "75%", "severity": "warning"}]},
        ],
    }
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    # Should not crash, just skip
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 0


def test_evaluate_category_multiple_rules():
    # 80% spent, day 15 of April. Goal threshold at 75% should fire.
    # Pacing: 800k spent on day 15 of 30 → projected = 1600k → 60% over. "5% over" should fire.
    cat_config = {
        "spending_limit": "auto",
        "enabled": True,
        "rules": [
            {
                "type": "goal_threshold",
                "min_hours_between_alerts": 744,
                "triggers": [
                    {"at": "75%", "severity": "warning"},
                    {"at": "90%", "severity": "urgent"},  # 80 < 90, won't fire
                ],
            },
            {
                "type": "pacing",
                "warm_up_hours": 72,
                "min_hours_between_alerts": 24,
                "triggers": [
                    {"at": "5% over",  "severity": "warning"},
                    {"at": "70% over", "severity": "urgent"},  # 60 < 70, won't fire
                ],
            },
        ],
    }
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))

    assert len(firings) == 2
    triggers_fired = {f.trigger["at"] for f in firings}
    assert "75%" in triggers_fired
    assert "5% over" in triggers_fired


def test_evaluate_category_enabled_defaults_true():
    # No "enabled" key at all — should still evaluate
    cat_config = {
        "spending_limit": "auto",
        "rules": [
            {"type": "goal_threshold", "min_hours_between_alerts": 744,
             "triggers": [{"at": "75%", "severity": "warning"}]},
        ],
    }
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 1


# ---------------------------------------------------------------------------
# 9. spending_limit: auto vs explicit
# ---------------------------------------------------------------------------

def test_spending_limit_auto_uses_budgeted():
    """spending_limit: auto should use the budgeted amount from YNAB."""
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": "auto"}
    # 80% of budgeted amount
    assert evaluate_goal_threshold(cat, {"at": "75%"}, cat_config) == True
    assert evaluate_goal_threshold(cat, {"at": "90%"}, cat_config) == False


def test_spending_limit_explicit_overrides_budgeted():
    """Explicit spending_limit should override YNAB budgeted amount."""
    # Budgeted is $1000, but explicit limit is $500
    cat = make_ynab_category(budgeted=1000000, activity=-400000)
    cat_config = {"spending_limit": 500}  # $500 explicit limit
    # $400 spent of $500 limit = 80%
    assert evaluate_goal_threshold(cat, {"at": "75%"}, cat_config) == True
    assert evaluate_goal_threshold(cat, {"at": "90%"}, cat_config) == False


def test_spending_limit_explicit_in_pacing():
    """Explicit spending_limit should work with pacing rules."""
    # Budgeted is $1000, but explicit limit is $500
    # Day 15 of April (30 days), $400 spent
    # Projected: 400 * 30/15 = $800, which is 60% over $500 limit
    cat = make_ynab_category(budgeted=1000000, activity=-400000)
    cat_config = {"spending_limit": 500}
    now = april(15)

    fired, ctx = evaluate_pacing(cat, {"at": "50% over"}, cat_config, now)
    assert fired == True
    assert abs(ctx["percent_over"] - 60.0) < 0.01


def test_spending_limit_zero_explicit_returns_false():
    """Explicit spending_limit of 0 should be treated as no limit."""
    cat = make_ynab_category(budgeted=1000000, activity=-800000)
    cat_config = {"spending_limit": 0}
    assert evaluate_goal_threshold(cat, {"at": "75%"}, cat_config) == False


def test_spending_limit_missing_with_no_budgeted():
    """If spending_limit is auto and budgeted is None/0, should not trigger."""
    cat_no_budgeted = make_ynab_category(budgeted=None, activity=-500000)
    cat_config = {"spending_limit": "auto"}
    assert evaluate_goal_threshold(cat_no_budgeted, {"at": "50%"}, cat_config) == False

    cat_zero_budgeted = make_ynab_category(budgeted=0, activity=-500000)
    assert evaluate_goal_threshold(cat_zero_budgeted, {"at": "50%"}, cat_config) == False


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def pytest_approx(expected, rel=1e-3):
    """Minimal approx helper if pytest isn't available."""
    class _Approx:
        def __eq__(self, other):
            return abs(other - expected) <= abs(expected * rel)
        def __repr__(self):
            return f"≈{expected}"
    return _Approx()


def run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1

    print()
    if failed:
        print(f"{passed} passed, {failed} FAILED")
        sys.exit(1)
    else:
        print(f"All {passed} tests passed.")


if __name__ == "__main__":
    run_all()
