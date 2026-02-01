import os
import re
import json
import calendar
from datetime import datetime, timezone
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
# ---------------------------------------------------------------------------

def _github_headers() -> dict:
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }


def load_state() -> dict:
    """Read state.json from the state branch. Returns empty dict if missing."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STATE_FILE}?ref={STATE_BRANCH}"
    r = requests.get(url, headers=_github_headers())
    if r.status_code == 404:
        return {}
    r.raise_for_status()
    import base64
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
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m")


def has_fired(state: dict, category_name: str, trigger_key: str) -> bool:
    """Check if a specific trigger already fired this month."""
    month = current_month_key()
    fired = state.get("fired", {}).get(month, [])
    return f"{category_name}:{trigger_key}" in fired


def mark_fired(state: dict, category_name: str, trigger_key: str) -> None:
    """Record that a trigger fired this month."""
    month = current_month_key()
    state.setdefault("fired", {}).setdefault(month, [])
    key = f"{category_name}:{trigger_key}"
    if key not in state["fired"][month]:
        state["fired"][month].append(key)


def prune_old_months(state: dict) -> None:
    """Remove fired entries older than the current month."""
    month = current_month_key()
    fired = state.get("fired", {})
    keys_to_remove = [k for k in fired if k < month]
    for k in keys_to_remove:
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
    """
    at = str(at_value).strip()

    match_dollars = re.match(r"^\$([0-9]+(?:\.[0-9]+)?)\s*remaining$", at, re.IGNORECASE)
    if match_dollars:
        return ("dollars_remaining", float(match_dollars.group(1)))

    match_percent = re.match(r"^([0-9]+(?:\.[0-9]+)?)%$", at)
    if match_percent:
        return ("percent_spent", float(match_percent.group(1)))

    raise ValueError(f"Unparseable threshold expression: '{at}'")


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------

def milliunits_to_dollars(mu: int) -> float:
    return mu / 1000.0


def evaluate_goal_threshold(
    category: dict,
    trigger: dict,
) -> bool:
    """
    Returns True if the trigger condition is met.
    category: raw YNAB category object for the current month.
    trigger: a single trigger dict from config, e.g. {at: "75%", severity: "warning"}
    """
    goal_target = category.get("goal_target")
    if goal_target is None:
        # No goal set in YNAB — can't evaluate this rule
        return False

    activity = category.get("activity", 0)  # total spend this month, in milliunits
    balance = category.get("balance", 0)    # remaining balance, in milliunits

    threshold_type, threshold_value = parse_threshold(trigger["at"])

    if threshold_type == "percent_spent":
        percent_spent = (activity / goal_target) * 100 if goal_target != 0 else 100.0
        return percent_spent >= threshold_value

    elif threshold_type == "dollars_remaining":
        dollars_remaining = milliunits_to_dollars(balance)
        return dollars_remaining <= threshold_value

    return False


# ---------------------------------------------------------------------------
# Pushover notifications
# ---------------------------------------------------------------------------

def send_alert(category_name: str, trigger: dict, category: dict) -> None:
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
            if rule["type"] != "goal_threshold":
                # Other rule types TBD
                continue

            once = rule.get("once_per_trigger", True)

            for trigger in rule.get("triggers", []):
                trigger_key = trigger["at"]

                # Check once_per_trigger state
                if once and has_fired(state, cat_name, trigger_key):
                    continue

                # Evaluate
                if evaluate_goal_threshold(ynab_category, trigger):
                    print(f"FIRED: {cat_name} — {trigger_key} [{trigger.get('severity', 'warning')}]")
                    send_alert(cat_name, trigger, ynab_category)

                    if once:
                        mark_fired(state, cat_name, trigger_key)
                        state_dirty = True

    # Persist state if anything changed
    if state_dirty:
        save_state(state, state_sha)
        print("State updated on branch: state")
    else:
        print("No state changes.")


if __name__ == "__main__":
    main()
