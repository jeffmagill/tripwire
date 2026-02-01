import os
import re
import json
import calendar
from datetime import datetime, timezone, timedelta
from typing import Any

import requests
import yaml


# ---------------------------------------------------------------------------
# Config & env
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


YNAB_TOKEN = os.environ["YNAB_TOKEN"]
PUSHOVER_API_TOKEN = os.environ["PUSHOVER_API_TOKEN"]
PUSHOVER_USER_KEYS = [k.strip() for k in os.environ["PUSHOVER_USER_KEYS"].split(",")]

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]          # Actions automatic token
GITHUB_REPO = os.environ["GITHUB_REPOSITORY"]      # e.g. "yourusername/tripwire"
STATE_BRANCH = "state"
STATE_FILE = "state.json"

YNAB_BASE = "https://api.ynab.com/v1"


# ---------------------------------------------------------------------------
# State management (reads/writes state.json on the state branch via GitHub API)
#
# State shape:
# {
#   "fired": {
#     "2026-01": {
#       "Groceries:75%":          "2026-01-15T12:00:00+00:00",
#       "Groceries:5% over":      "2026-01-20T08:00:00+00:00",
#       ...
#     }
#   }
# }
#
# Each trigger key maps to the ISO timestamp of its most recent firing.
# ---------------------------------------------------------------------------

def _github_headers() -> dict:
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }


def load_state() -> dict:
    """Read state.json from the state branch. Returns empty dict if missing."""
    import base64
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STATE_FILE}?ref={STATE_BRANCH}"
    r = requests.get(url, headers=_github_headers())
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    raw = base64.b64decode(r.json()["content"]).decode()
    return json.loads(raw)


def save_state(state: dict, old_sha: str | None) -> None:
    """Write state.json to the state branch. Creates file if it doesn't exist."""
    import base64
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STATE_FILE}"
    payload: dict[str, Any] = {
        "message": "chore: update tripwire state",
        "content": base64.b64encode(json.dumps(state, indent=2).encode()).decode(),
        "branch": STATE_BRANCH,
    }
    if old_sha:
        payload["sha"] = old_sha
        r = requests.put(url, headers=_github_headers(), json=payload)
    else:
        r = requests.post(url, headers=_github_headers(), json=payload)
    r.raise_for_status()


def get_state_sha() -> str | None:
    """Get the SHA of state.json on the state branch (needed for updates)."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STATE_FILE}?ref={STATE_BRANCH}"
    r = requests.get(url, headers=_github_headers())
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["sha"]


def current_month_key() -> str:
    """e.g. '2026-01'"""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def should_alert(state: dict, category_name: str, trigger_key: str, min_hours: int) -> bool:
    """
    Returns True if enough time has passed since the last firing of this trigger
    to warrant a new alert. Also returns True if the trigger has never fired.
    """
    month = current_month_key()
    last_fired_str = state.get("fired", {}).get(month, {}).get(f"{category_name}:{trigger_key}")
    if last_fired_str is None:
        return True  # never fired this month
    last_fired = datetime.fromisoformat(last_fired_str)
    return (datetime.now(timezone.utc) - last_fired) >= timedelta(hours=min_hours)


def record_firing(state: dict, category_name: str, trigger_key: str) -> None:
    """Record the current timestamp as the most recent firing for this trigger."""
    month = current_month_key()
    state.setdefault("fired", {}).setdefault(month, {})
    state["fired"][month][f"{category_name}:{trigger_key}"] = datetime.now(timezone.utc).isoformat()


def prune_old_months(state: dict) -> None:
    """Remove fired entries older than the current month."""
    month = current_month_key()
    fired = state.get("fired", {})
    for k in [k for k in fired if k < month]:
        del fired[k]


# ---------------------------------------------------------------------------
# YNAB API
# ---------------------------------------------------------------------------

def fetch_categories(budget_id: str, month: str) -> list[dict]:
    """Fetch all categories for a given budget and month."""
    url = f"{YNAB_BASE}/budgets/{budget_id}/months/{month}/categories"
    headers = {"Authorization": f"Bearer {YNAB_TOKEN}"}
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    return r.json()["data"]["categories"]


def build_category_map(categories: list[dict]) -> dict[str, dict]:
    """Key categories by ID for fast lookup."""
    return {cat["id"]: cat for cat in categories}


# ---------------------------------------------------------------------------
# Threshold parsing
# ---------------------------------------------------------------------------

def parse_threshold(at_value: str) -> tuple[str, float]:
    """
    Parse an 'at' expression into (type, value).
      "$200 remaining"  -> ("dollars_remaining", 200.0)
      "75%"             -> ("percent_spent", 75.0)
      "5% over"         -> ("percent_over", 5.0)
    """
    at = str(at_value).strip()

    match_dollars = re.match(r"^\$([0-9]+(?:\.[0-9]+)?)\s*remaining$", at, re.IGNORECASE)
    if match_dollars:
        return ("dollars_remaining", float(match_dollars.group(1)))

    match_percent_over = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*%\s*over$", at, re.IGNORECASE)
    if match_percent_over:
        return ("percent_over", float(match_percent_over.group(1)))

    match_percent = re.match(r"^([0-9]+(?:\.[0-9]+)?)%$", at)
    if match_percent:
        return ("percent_spent", float(match_percent.group(1)))

    raise ValueError(f"Unparseable threshold expression: '{at}'")


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

def milliunits_to_dollars(mu: int) -> float:
    return mu / 1000.0


def evaluate_goal_threshold(category: dict, trigger: dict) -> bool:
    """
    Returns True if the trigger condition is met.
    category: raw YNAB category object for the current month.
    trigger: a single trigger dict, e.g. {at: "75%", severity: "warning"}
    """
    goal_target = category.get("goal_target")
    if goal_target is None:
        return False

    activity = category.get("activity", 0)
    balance = category.get("balance", 0)

    threshold_type, threshold_value = parse_threshold(trigger["at"])

    if threshold_type == "percent_spent":
        percent_spent = (activity / goal_target) * 100 if goal_target != 0 else 100.0
        return percent_spent >= threshold_value

    elif threshold_type == "dollars_remaining":
        return milliunits_to_dollars(balance) <= threshold_value

    return False


def evaluate_pacing(category: dict, trigger: dict, now: datetime) -> tuple[bool, dict]:
    """
    Returns (triggered, context) where context holds the computed pacing figures
    for use in the notification message.

    Projection math:
      expected_spend = goal_target × (days_elapsed / days_in_month)
      projected_eom  = activity × (days_in_month / days_elapsed)
      percent_over   = ((projected_eom - goal_target) / goal_target) × 100
    """
    goal_target = category.get("goal_target")
    if goal_target is None or goal_target == 0:
        return (False, {})

    activity = category.get("activity", 0)

    year, month = now.year, now.month
    days_in_month = calendar.monthrange(year, month)[1]
    # days_elapsed: how far into the month we are (at least 1 to avoid div-by-zero)
    days_elapsed = max(now.day, 1)

    expected_spend = goal_target * (days_elapsed / days_in_month)
    projected_eom = activity * (days_in_month / days_elapsed)
    percent_over = ((projected_eom - goal_target) / goal_target) * 100

    context = {
        "activity": activity,
        "goal_target": goal_target,
        "expected_spend": expected_spend,
        "projected_eom": projected_eom,
        "percent_over": percent_over,
        "days_elapsed": days_elapsed,
        "days_in_month": days_in_month,
    }

    threshold_type, threshold_value = parse_threshold(trigger["at"])
    if threshold_type != "percent_over":
        raise ValueError(f"Pacing rule trigger must use 'X% over' syntax, got: '{trigger['at']}'")

    # Only fire if we're actually projected over AND by at least the threshold
    return (percent_over >= threshold_value, context)


# ---------------------------------------------------------------------------
# Pushover notifications
# ---------------------------------------------------------------------------

def send_alert(category_name: str, trigger: dict, category: dict, pacing_context: dict | None = None) -> None:
    """Send a Pushover notification to all configured user keys."""
    goal_target = category.get("goal_target", 0)
    activity = category.get("activity", 0)
    balance = category.get("balance", 0)
    severity = trigger.get("severity", "warning")

    spent_str = f"${milliunits_to_dollars(activity):.2f}"
    goal_str = f"${milliunits_to_dollars(goal_target):.2f}"
    remaining_str = f"${milliunits_to_dollars(balance):.2f}"
    percent_str = f"{(activity / goal_target * 100):.0f}%" if goal_target else "N/A"

    title = f"{'⚠️' if severity == 'warning' else '🔴'} Tripwire: {category_name}"

    if pacing_context:
        # Pacing-specific message: show current spend, expected spend, and projection
        expected_str = f"${milliunits_to_dollars(pacing_context['expected_spend']):.2f}"
        projected_str = f"${milliunits_to_dollars(pacing_context['projected_eom']):.2f}"
        over_str = f"{pacing_context['percent_over']:.1f}%"
        message = (
            f"On pace to overspend.\n"
            f"Spent: {spent_str} (expected by now: {expected_str})\n"
            f"Projected end of month: {projected_str} vs goal {goal_str} (+{over_str})\n"
            f"Trigger: {trigger['at']} [{severity}]"
        )
    else:
        # Goal threshold message
        message = (
            f"Spent {spent_str} of {goal_str} ({percent_str})\n"
            f"Remaining: {remaining_str}\n"
            f"Trigger: {trigger['at']} [{severity}]"
        )

    # Pushover priority: -1 = low (warning), 1 = high (urgent)
    priority = -1 if severity == "warning" else 1

    for user_key in PUSHOVER_USER_KEYS:
        payload = {
            "token": PUSHOVER_API_TOKEN,
            "user": user_key,
            "title": title,
            "message": message,
            "priority": priority,
        }
        r = requests.post("https://api.pushover.net/1/messages.json", data=payload)
        r.raise_for_status()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    config = load_config()
    budget_id = config["budget_id"]
    now = datetime.now(timezone.utc)
    month_str = now.strftime("%Y-%m-01")  # YNAB expects YYYY-MM-01

    # Fetch YNAB data
    categories = fetch_categories(budget_id, month_str)
    cat_map = build_category_map(categories)

    # Load state
    state = load_state()
    state_sha = get_state_sha()
    prune_old_months(state)
    state_dirty = False

    # Hours elapsed since the start of this month (for warm_up_hours check)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    hours_into_month = (now - month_start).total_seconds() / 3600

    # Evaluate each configured category
    for cat_name, cat_config in config["categories"].items():
        if not cat_config.get("enabled", True):
            continue

        goal_id = cat_config["goal_id"]
        ynab_category = cat_map.get(goal_id)
        if ynab_category is None:
            print(f"WARNING: category '{cat_name}' (id: {goal_id}) not found in YNAB for {month_str}")
            continue

        for rule in cat_config.get("rules", []):
            rule_type = rule["type"]
            min_hours = rule.get("min_hours_between_alerts", 744)

            # Pacing warm-up guard
            if rule_type == "pacing":
                warm_up = rule.get("warm_up_hours", 72)
                if hours_into_month < warm_up:
                    print(f"SKIP (warm-up): {cat_name} pacing — {hours_into_month:.1f}h into month, warm_up_hours={warm_up}")
                    continue

            for trigger in rule.get("triggers", []):
                trigger_key = trigger["at"]

                # Check min_hours_between_alerts
                if not should_alert(state, cat_name, trigger_key, min_hours):
                    print(f"SKIP (cooldown): {cat_name} — {trigger_key}")
                    continue

                # Evaluate by rule type
                fired = False
                pacing_context = None

                if rule_type == "goal_threshold":
                    fired = evaluate_goal_threshold(ynab_category, trigger)

                elif rule_type == "pacing":
                    fired, pacing_context = evaluate_pacing(ynab_category, trigger, now)

                else:
                    print(f"SKIP (unknown rule type): {cat_name} — {rule_type}")
                    continue

                if fired:
                    print(f"FIRED: {cat_name} — {trigger_key} [{trigger.get('severity', 'warning')}]")
                    send_alert(cat_name, trigger, ynab_category, pacing_context)
                    record_firing(state, cat_name, trigger_key)
                    state_dirty = True

    # Persist state if anything changed
    if state_dirty:
        save_state(state, state_sha)
        print("State updated on branch: state")
    else:
        print("No state changes.")


if __name__ == "__main__":
    main()
