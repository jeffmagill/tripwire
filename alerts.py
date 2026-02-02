import os
import re
import json
import logging
import calendar
from datetime import datetime, timezone, timedelta
from typing import Any
from dataclasses import dataclass, field

import requests
import yaml

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# Format: timestamp [LEVEL] message
# All output goes to stderr (Actions captures both stdout and stderr in the
# log, but stderr is the conventional home for diagnostics).
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S UTC",
    stream=__import__("sys").stderr,
)
log = logging.getLogger("tripwire")


# ---------------------------------------------------------------------------
# Config & env
# ---------------------------------------------------------------------------

def expand_env_vars(value):
    """
    Recursively expand ${VAR} environment variable references.
    Works on strings, lists, and dicts.
    Only supports ${VAR} syntax (not bare $VAR) to avoid conflicts with dollar amounts.
    """
    if isinstance(value, str):
        import re
        # Match ${VAR} only (not bare $VAR, to avoid matching dollar amounts like $200)
        pattern = r'\$\{([A-Za-z0-9_]+)\}'
        def replacer(match):
            var_name = match.group(1)
            env_value = os.environ.get(var_name)
            if env_value is None:
                raise ValueError(f"Environment variable '{var_name}' not set (referenced in config)")
            return env_value
        return re.sub(pattern, replacer, value)
    elif isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    else:
        return value


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        raw = yaml.safe_load(f)
    return expand_env_vars(raw)


YNAB_TOKEN = os.environ["YNAB_TOKEN"]
PUSHOVER_API_TOKEN = os.environ["PUSHOVER_API_TOKEN"]
PUSHOVER_USER_KEYS = [k.strip() for k in os.environ["PUSHOVER_USER_KEYS"].split(",")]

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]          # Actions automatic token
GITHUB_REPO = os.environ["GITHUB_REPOSITORY"]      # e.g. "yourusername/tripwire"
STATE_BRANCH = "state"
STATE_FILE = "state.json"

YNAB_BASE = "https://api.ynab.com/v1"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Firing:
    """A single trigger that fired. Carries everything needed to send the alert."""
    category_name: str
    trigger: dict                      # the trigger block from config, e.g. {at: "75%", severity: "warning"}
    ynab_category: dict                # raw YNAB category object
    pacing_context: dict = field(default_factory=dict)  # populated only for pacing rules


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
        log.info("State file not found on '%s' branch — starting fresh", STATE_BRANCH)
        return {}
    r.raise_for_status()
    raw = base64.b64decode(r.json()["content"]).decode()
    state = json.loads(raw)
    log.debug("Loaded state: %d month(s), %d total firings",
              len(state.get("fired", {})),
              sum(len(v) for v in state.get("fired", {}).values()))
    return state


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
    log.info("State saved to '%s' branch (sha: %s)", STATE_BRANCH, r.json().get("content", {}).get("sha", "?"))


def get_state_sha() -> str | None:
    """Get the SHA of state.json on the state branch (needed for updates)."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STATE_FILE}?ref={STATE_BRANCH}"
    r = requests.get(url, headers=_github_headers())
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["sha"]


def current_month_key(now: datetime | None = None) -> str:
    """e.g. '2026-01'. Accepts an optional now for testability."""
    if now is None:
        now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m")


def should_alert(state: dict, category_name: str, trigger_key: str, min_hours: int, now: datetime | None = None) -> bool:
    """
    Returns True if enough time has passed since the last firing of this trigger
    to warrant a new alert. Also returns True if the trigger has never fired.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    month = current_month_key(now)
    last_fired_str = state.get("fired", {}).get(month, {}).get(f"{category_name}:{trigger_key}")
    if last_fired_str is None:
        return True  # never fired this month
    last_fired = datetime.fromisoformat(last_fired_str)
    return (now - last_fired) >= timedelta(hours=min_hours)


def record_firing(state: dict, category_name: str, trigger_key: str, now: datetime | None = None) -> None:
    """Record the current timestamp as the most recent firing for this trigger."""
    if now is None:
        now = datetime.now(timezone.utc)
    month = current_month_key(now)
    state.setdefault("fired", {}).setdefault(month, {})
    state["fired"][month][f"{category_name}:{trigger_key}"] = now.isoformat()


def prune_old_months(state: dict, now: datetime | None = None) -> None:
    """Remove fired entries older than the current month."""
    month = current_month_key(now)
    fired = state.get("fired", {})
    old_keys = [k for k in fired if k < month]
    for k in old_keys:
        del fired[k]
    if old_keys:
        log.debug("Pruned stale state for months: %s", ", ".join(old_keys))


# ---------------------------------------------------------------------------
# YNAB API
# ---------------------------------------------------------------------------

def fetch_categories(budget_id: str, month: str) -> list[dict]:
    """Fetch all categories for a given budget and month."""
    url = f"{YNAB_BASE}/budgets/{budget_id}/months/{month}"
    headers = {"Authorization": f"Bearer {YNAB_TOKEN}"}
    log.debug("Fetching categories: %s", url)
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    categories = r.json()["data"]["month"]["categories"]
    log.info("Fetched %d categories from YNAB for %s", len(categories), month)
    return categories


def build_category_map(categories: list[dict]) -> dict[str, dict]:
    """Key categories by name for fast lookup."""
    return {cat["name"]: cat for cat in categories}


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
# Low-level rule evaluation (pure functions, no state, no side effects)
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

    return (percent_over >= threshold_value, context)


# ---------------------------------------------------------------------------
# Rule-level evaluation (one function per rule type)
# Each owns: warm-up guard, trigger iteration, cooldown check.
# Returns a list of Firing objects — empty if nothing tripped.
# ---------------------------------------------------------------------------

def evaluate_goal_threshold_rule(
    category_name: str,
    rule: dict,
    ynab_category: dict,
    state: dict,
    now: datetime,
) -> list[Firing]:
    """Evaluate a goal_threshold rule against a YNAB category. Returns all firings."""
    # Check if category has a goal - warn if not
    if ynab_category.get("goal_target") is None:
        log.warning("SKIP (no goal): %s — goal_threshold rule configured but category has no goal in YNAB", category_name)
        return []

    min_hours = rule.get("min_hours_between_alerts", 744)
    firings = []

    for trigger in rule.get("triggers", []):
        trigger_key = trigger["at"]

        if not should_alert(state, category_name, trigger_key, min_hours, now):
            log.debug("SKIP (cooldown): %s — %s", category_name, trigger_key)
            continue

        if evaluate_goal_threshold(ynab_category, trigger):
            firings.append(Firing(
                category_name=category_name,
                trigger=trigger,
                ynab_category=ynab_category,
            ))
        else:
            log.debug("EVAL (not tripped): %s — %s", category_name, trigger_key)

    return firings


def evaluate_pacing_rule(
    category_name: str,
    rule: dict,
    ynab_category: dict,
    state: dict,
    now: datetime,
    hours_into_month: float,
) -> list[Firing]:
    """Evaluate a pacing rule against a YNAB category. Returns all firings."""
    # Warm-up guard
    warm_up = rule.get("warm_up_hours", 72)
    if hours_into_month < warm_up:
        log.debug("SKIP (warm-up): %s pacing — %.1fh into month, warm_up_hours=%s",
                  category_name, hours_into_month, warm_up)
        return []

    min_hours = rule.get("min_hours_between_alerts", 24)
    firings = []

    for trigger in rule.get("triggers", []):
        trigger_key = trigger["at"]

        if not should_alert(state, category_name, trigger_key, min_hours, now):
            log.debug("SKIP (cooldown): %s — %s", category_name, trigger_key)
            continue

        fired, pacing_context = evaluate_pacing(ynab_category, trigger, now)
        if fired:
            firings.append(Firing(
                category_name=category_name,
                trigger=trigger,
                ynab_category=ynab_category,
                pacing_context=pacing_context,
            ))
        else:
            log.debug("EVAL (not tripped): %s — %s (projected %.1f%% over)",
                      category_name, trigger_key, pacing_context.get("percent_over", 0))

    return firings


# ---------------------------------------------------------------------------
# Category-level evaluation (dispatcher)
# ---------------------------------------------------------------------------

RULE_EVALUATORS = {
    "goal_threshold": evaluate_goal_threshold_rule,
    "pacing":         evaluate_pacing_rule,
}


def evaluate_category(
    category_name: str,
    cat_config: dict,
    ynab_category: dict,
    state: dict,
    now: datetime,
) -> list[Firing]:
    """
    Evaluate all rules for a single category. Returns a flat list of all Firings
    across all rules. Skips disabled categories and unknown rule types.
    """
    if not cat_config.get("enabled", True):
        return []

    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    hours_into_month = (now - month_start).total_seconds() / 3600

    firings = []

    for rule in cat_config.get("rules", []):
        rule_type = rule["type"]
        evaluator = RULE_EVALUATORS.get(rule_type)

        if evaluator is None:
            log.warning("SKIP (unknown rule type): %s — %s", category_name, rule_type)
            continue

        # goal_threshold and pacing have slightly different signatures;
        # pacing needs hours_into_month. We pass it via kwargs so the
        # dispatch stays clean.
        kwargs: dict[str, Any] = dict(
            category_name=category_name,
            rule=rule,
            ynab_category=ynab_category,
            state=state,
            now=now,
        )
        if rule_type == "pacing":
            kwargs["hours_into_month"] = hours_into_month

        firings.extend(evaluator(**kwargs))

    return firings


# ---------------------------------------------------------------------------
# Pushover notifications
# ---------------------------------------------------------------------------

def send_alert(firing: Firing) -> None:
    """Send a Pushover notification to all configured user keys."""
    category = firing.ynab_category
    trigger = firing.trigger
    goal_target = category.get("goal_target", 0)
    activity = category.get("activity", 0)
    balance = category.get("balance", 0)
    severity = trigger.get("severity", "warning")

    spent_str = f"${milliunits_to_dollars(activity):.2f}"
    goal_str = f"${milliunits_to_dollars(goal_target):.2f}"
    remaining_str = f"${milliunits_to_dollars(balance):.2f}"
    percent_str = f"{(activity / goal_target * 100):.0f}%" if goal_target else "N/A"

    title = f"{'⚠️' if severity == 'warning' else '🔴'} Tripwire: {firing.category_name}"

    if firing.pacing_context:
        expected_str = f"${milliunits_to_dollars(firing.pacing_context['expected_spend']):.2f}"
        projected_str = f"${milliunits_to_dollars(firing.pacing_context['projected_eom']):.2f}"
        over_str = f"{firing.pacing_context['percent_over']:.1f}%"
        message = (
            f"On pace to overspend.\n"
            f"Spent: {spent_str} (expected by now: {expected_str})\n"
            f"Projected end of month: {projected_str} vs goal {goal_str} (+{over_str})\n"
            f"Trigger: {trigger['at']} [{severity}]"
        )
    else:
        message = (
            f"Spent {spent_str} of {goal_str} ({percent_str})\n"
            f"Remaining: {remaining_str}\n"
            f"Trigger: {trigger['at']} [{severity}]"
        )

    priority = -1 if severity == "warning" else 1

    log.info("Sending alert to %d recipient(s): %s — %s [%s]",
             len(PUSHOVER_USER_KEYS), firing.category_name, trigger["at"], severity)
    log.debug("Alert payload — title: %s | message: %s", title, message)

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
        log.debug("Pushover delivery OK for user key ending '...%s'", user_key[-4:])


# ---------------------------------------------------------------------------
# Auto-alerts: automatically create alert rules for categories with goals
# ---------------------------------------------------------------------------

def build_final_category_config(config: dict, cat_map: dict[str, dict]) -> dict:
    """
    Build the final category configuration by merging explicit config with auto-detected
    categories (if auto_alerts is enabled).

    Returns a dict of {category_name: category_config}
    """
    final_categories = dict(config.get("categories", {}))

    auto_alerts_config = config.get("auto_alerts", {})
    if not auto_alerts_config.get("enabled", False):
        log.debug("Auto-alerts disabled")
        return final_categories

    exclude_list = set(auto_alerts_config.get("exclude", []))
    default_rules = auto_alerts_config.get("rules", [])

    if not default_rules:
        log.warning("Auto-alerts enabled but no default rules defined — skipping auto-detection")
        return final_categories

    auto_detected = 0
    for cat_name, ynab_cat in cat_map.items():
        # Skip if already explicitly configured
        if cat_name in final_categories:
            continue

        # Skip if in exclude list
        if cat_name in exclude_list:
            log.debug("Auto-alerts: skipping excluded category '%s'", cat_name)
            continue

        # Skip if no goal
        if ynab_cat.get("goal_target") is None:
            continue

        # Add category with auto-detected rules
        final_categories[cat_name] = {
            "enabled": True,
            "rules": default_rules,
            "_auto_detected": True,  # marker for logging
        }
        auto_detected += 1
        log.debug("Auto-alerts: added category '%s' with default rules", cat_name)

    if auto_detected > 0:
        log.info("Auto-alerts: detected %d categories with goals (not explicitly configured)", auto_detected)

    return final_categories


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    config = load_config()
    budget_id = config["budget_id"]
    now = datetime.now(timezone.utc)
    month_str = now.strftime("%Y-%m-01")  # YNAB expects YYYY-MM-01

    log.info("--- Tripwire run started at %s for %s ---", now.isoformat(), month_str)
    log.debug("Budget ID: %s | Categories configured: %d", budget_id, len(config["categories"]))

    # Fetch YNAB data
    categories = fetch_categories(budget_id, month_str)
    cat_map = build_category_map(categories)

    # Load state
    state = load_state()
    state_sha = get_state_sha()
    prune_old_months(state, now)
    state_dirty = False
    total_firings = 0

    # Build final category configuration (explicit + auto-detected)
    final_categories = build_final_category_config(config, cat_map)

    # Evaluate and act
    for cat_name, cat_config in final_categories.items():
        if not cat_config.get("enabled", True):
            log.debug("SKIP (disabled): %s", cat_name)
            continue

        ynab_category = cat_map.get(cat_name)
        if ynab_category is None:
            log.warning("Category '%s' not found in YNAB for %s — skipping", cat_name, month_str)
            continue

        firings = evaluate_category(cat_name, cat_config, ynab_category, state, now)

        for firing in firings:
            log.info("FIRED: %s — %s [%s]", firing.category_name, firing.trigger["at"], firing.trigger.get("severity", "warning"))
            send_alert(firing)
            record_firing(state, firing.category_name, firing.trigger["at"], now)
            state_dirty = True
            total_firings += 1

    # Persist state if anything changed
    if state_dirty:
        save_state(state, state_sha)
    else:
        log.debug("No state changes this run.")

    log.info("--- Tripwire run complete: %d firing(s) ---", total_firings)


if __name__ == "__main__":
    main()
