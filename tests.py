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

def make_ynab_category(goal_target: int | None = 1000000, activity: int = 0, balance: int | None = None, cat_id: str = "cat-1") -> dict:
    """Build a minimal YNAB category dict. balance defaults to goal_target - activity."""
    if balance is None:
        balance = (goal_target or 0) - activity
    return {
        "id": cat_id,
        "goal_target": goal_target,
        "activity": activity,
        "balance": balance,
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
        "Groceries": {"goal_target": 100000},
        "Dining Out": {"goal_target": 50000},  # has goal but should not be auto-added
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 1
    assert "Groceries" in final
    assert "Dining Out" not in final


def test_auto_alerts_enabled():
    """When auto_alerts is enabled, categories with goals are auto-detected."""
    config = {
        "categories": {"Groceries": {"rules": []}},
        "auto_alerts": {
            "enabled": True,
            "rules": [{"type": "goal_threshold", "min_hours_between_alerts": 744, "triggers": []}],
        },
    }
    cat_map = {
        "Groceries": {"goal_target": 100000},  # explicit, should not be duplicated
        "Dining Out": {"goal_target": 50000},  # has goal, should be auto-added
        "Vacation": {"goal_target": None},     # no goal, should not be added
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 2
    assert "Groceries" in final
    assert "Dining Out" in final
    assert "Vacation" not in final
    assert final["Dining Out"]["_auto_detected"] is True


def test_auto_alerts_exclude_list():
    """Categories in the exclude list are not auto-detected."""
    config = {
        "categories": {},
        "auto_alerts": {
            "enabled": True,
            "exclude": ["Dining Out"],
            "rules": [{"type": "goal_threshold", "min_hours_between_alerts": 744, "triggers": []}],
        },
    }
    cat_map = {
        "Groceries": {"goal_target": 100000},
        "Dining Out": {"goal_target": 50000},  # excluded
    }
    final = build_final_category_config(config, cat_map)
    assert len(final) == 1
    assert "Groceries" in final
    assert "Dining Out" not in final


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
    # 800 of 1000 spent = 80%
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    assert evaluate_goal_threshold(cat, {"at": "75%"})  == True   # 80 >= 75
    assert evaluate_goal_threshold(cat, {"at": "80%"})  == True   # 80 >= 80
    assert evaluate_goal_threshold(cat, {"at": "81%"})  == False  # 80 < 81


def test_goal_threshold_dollars_remaining():
    # balance = $200 (200,000 milliunits)
    cat = make_ynab_category(goal_target=1000000, activity=800000, balance=200000)
    assert evaluate_goal_threshold(cat, {"at": "$200 remaining"}) == True   # 200 <= 200
    assert evaluate_goal_threshold(cat, {"at": "$250 remaining"}) == True   # 200 <= 250
    assert evaluate_goal_threshold(cat, {"at": "$150 remaining"}) == False  # 200 > 150


def test_goal_threshold_no_goal():
    cat = make_ynab_category(goal_target=None, activity=500000, balance=0)
    assert evaluate_goal_threshold(cat, {"at": "50%"}) == False


def test_goal_threshold_zero_goal():
    # Zero goal_target: percent_spent should be 100% (clamped), not a division error
    cat = make_ynab_category(goal_target=0, activity=0, balance=0)
    assert evaluate_goal_threshold(cat, {"at": "50%"}) == True


# ---------------------------------------------------------------------------
# 4. Low-level: evaluate_pacing
# ---------------------------------------------------------------------------

def test_pacing_over():
    # April (30 days), day 15, $600 spent, goal $1000
    # projected = 600 * 30/15 = $1200 → 20% over
    cat = make_ynab_category(goal_target=1000000, activity=600000)
    now = april(15)

    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, now)
    assert fired == True
    assert abs(ctx["percent_over"] - 20.0) < 0.01
    assert ctx["days_in_month"] == 30
    assert ctx["days_elapsed"] == 15

    fired, _ = evaluate_pacing(cat, {"at": "20% over"}, now)
    assert fired == True   # exactly 20, >= 20

    fired, _ = evaluate_pacing(cat, {"at": "25% over"}, now)
    assert fired == False  # 20 < 25


def test_pacing_on_pace():
    # $500 by day 15 of 30 → projected = $1000 → 0% over
    cat = make_ynab_category(goal_target=1000000, activity=500000)
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, april(15))
    assert fired == False
    assert abs(ctx["percent_over"] - 0.0) < 0.01


def test_pacing_under_pace():
    # $300 by day 15 of 30 → projected = $600 → -40% over (under)
    cat = make_ynab_category(goal_target=1000000, activity=300000)
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, april(15))
    assert fired == False
    assert ctx["percent_over"] < 0


def test_pacing_no_goal():
    cat = make_ynab_category(goal_target=None, activity=500000)
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, april(15))
    assert fired == False
    assert ctx == {}


def test_pacing_zero_goal():
    cat = make_ynab_category(goal_target=0, activity=500000)
    fired, ctx = evaluate_pacing(cat, {"at": "5% over"}, april(15))
    assert fired == False
    assert ctx == {}


def test_pacing_invalid_trigger_syntax():
    cat = make_ynab_category(goal_target=1000000, activity=600000)
    try:
        evaluate_pacing(cat, {"at": "75%"}, april(15))  # wrong syntax for pacing
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
    cat = make_ynab_category(goal_target=1000000, activity=800000)
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

    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, state, now)
    assert len(firings) == 1
    assert firings[0].trigger["at"] == "75%"
    assert firings[0].trigger["severity"] == "warning"
    assert firings[0].category_name == "Groceries"


def test_goal_threshold_rule_respects_cooldown():
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [{"at": "75%", "severity": "warning"}],
    }
    now = april(15)
    state = {}
    record_firing(state, "Groceries", "75%", now)

    # Should not fire again — cooldown active
    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, state, now)
    assert len(firings) == 0


def test_goal_threshold_rule_no_goal_returns_empty():
    cat = make_ynab_category(goal_target=None, activity=800000, balance=0)
    rule = {
        "type": "goal_threshold",
        "min_hours_between_alerts": 744,
        "triggers": [{"at": "75%", "severity": "warning"}],
    }
    firings = evaluate_goal_threshold_rule("Groceries", rule, cat, {}, april(15))
    assert len(firings) == 0


# ---------------------------------------------------------------------------
# 7. Rule-level: evaluate_pacing_rule
# ---------------------------------------------------------------------------

def test_pacing_rule_fires_when_over_pace():
    # April day 15, $600 of $1000 spent → 20% over
    cat = make_ynab_category(goal_target=1000000, activity=600000)
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

    firings = evaluate_pacing_rule("Groceries", rule, cat, {}, now, hours_into_month)
    assert len(firings) == 1
    assert firings[0].trigger["at"] == "5% over"
    assert firings[0].pacing_context["percent_over"] == pytest_approx(20.0)


def test_pacing_rule_blocked_by_warm_up():
    cat = make_ynab_category(goal_target=1000000, activity=600000)
    rule = {
        "type": "pacing",
        "warm_up_hours": 72,
        "min_hours_between_alerts": 24,
        "triggers": [{"at": "5% over", "severity": "warning"}],
    }
    # Only 48 hours into the month — warm_up_hours is 72
    firings = evaluate_pacing_rule("Groceries", rule, cat, {}, april(2, 0), hours_into_month=48.0)
    assert len(firings) == 0


def test_pacing_rule_respects_cooldown():
    cat = make_ynab_category(goal_target=1000000, activity=600000)
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

    firings = evaluate_pacing_rule("Groceries", rule, cat, state, now, hours_into_month)
    assert len(firings) == 0


def test_pacing_rule_re_alerts_after_cooldown():
    cat = make_ynab_category(goal_target=1000000, activity=600000)
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

    firings = evaluate_pacing_rule("Groceries", rule, cat, state, now, hours_into_month)
    assert len(firings) == 1


# ---------------------------------------------------------------------------
# 8. Category-level: evaluate_category
# ---------------------------------------------------------------------------

def test_evaluate_category_disabled():
    cat_config = {"goal_id": "cat-1", "enabled": False, "rules": [
        {"type": "goal_threshold", "min_hours_between_alerts": 744,
         "triggers": [{"at": "75%", "severity": "warning"}]},
    ]}
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 0


def test_evaluate_category_unknown_rule_type():
    cat_config = {"goal_id": "cat-1", "enabled": True, "rules": [
        {"type": "unknown_future_type", "triggers": [{"at": "75%", "severity": "warning"}]},
    ]}
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    # Should not crash, just skip
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 0


def test_evaluate_category_multiple_rules():
    # 80% spent, day 15 of April. Goal threshold at 75% should fire.
    # Pacing: 800k activity on day 15 of 30 → projected = 1600k → 60% over. "5% over" should fire.
    cat_config = {
        "goal_id": "cat-1",
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
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))

    assert len(firings) == 2
    triggers_fired = {f.trigger["at"] for f in firings}
    assert "75%" in triggers_fired
    assert "5% over" in triggers_fired


def test_evaluate_category_enabled_defaults_true():
    # No "enabled" key at all — should still evaluate
    cat_config = {"goal_id": "cat-1", "rules": [
        {"type": "goal_threshold", "min_hours_between_alerts": 744,
         "triggers": [{"at": "75%", "severity": "warning"}]},
    ]}
    cat = make_ynab_category(goal_target=1000000, activity=800000)
    firings = evaluate_category("Groceries", cat_config, cat, {}, april(15))
    assert len(firings) == 1


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
