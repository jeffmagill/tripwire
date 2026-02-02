# Tripwire

Push notifications when your YNAB categories cross a spending threshold.

## How it works

Tripwire polls your YNAB budget every 4 hours via GitHub Actions. For each
category defined in `config.yaml`, it checks whether any alert rules have been
tripped. If so, it fires a Pushover notification to all configured recipients.

State (which triggers have fired and when) is persisted on a dedicated `state`
branch to keep `main` clean.

## Setup

### 1. Create the `state` branch

```bash
git checkout --orphan state
echo '{}' > state.json
git add state.json
git commit -m "init state"
git push origin state
git checkout main
```

### 2. Configure secrets

Go to your repo → Settings → Secrets and Variables → Actions. Add:

| Secret | Value |
|---|---|
| `YNAB_TOKEN` | Your YNAB personal access token (Settings → Developer Settings in YNAB) |
| `YNAB_BUDGET_ID` | Your YNAB budget ID (see step 3 below for how to find this) |
| `PUSHOVER_API_TOKEN` | Your Pushover application token |
| `PUSHOVER_USER_KEYS` | Comma-separated Pushover user keys, e.g. `key1,key2` |

`GITHUB_TOKEN` is provided automatically by Actions — no action needed.

### 3. Edit `config.yaml`

The `budget_id` field uses environment variable substitution — the default
`"${YNAB_BUDGET_ID}"` will be replaced at runtime with the value from your
repository secret.

**Categories are matched by name** (not ID!) so configuration is simple:

```yaml
categories:
  Groceries:      # matches your YNAB category named "Groceries"
    rules: [...]
  "Dining Out":   # use quotes for names with spaces
    rules: [...]
```

**Auto-alerts** (recommended): Enable auto-detection to automatically alert on ALL categories that have goals set in YNAB:

```yaml
auto_alerts:
  enabled: true
  exclude: ["Emergency Fund"]  # optional: skip specific categories
  rules:
    - type: goal_threshold
      min_hours_between_alerts: 744
      triggers:
        - at: "75%"
          severity: warning
        - at: "90%"
          severity: urgent
```

With auto-alerts enabled, you only need to explicitly configure categories when you want custom thresholds that differ from the defaults.

Environment variable syntax: use `${VAR}` format (bare `$VAR` is not supported to avoid conflicts with dollar amounts in threshold expressions).

### 4. Push and wait

The workflow runs on a 4-hour cron. You can also trigger it manually from the
Actions tab → Tripwire → Run workflow.

## Threshold syntax

| Expression | Rule type | Meaning |
|---|---|---|
| `"75%"` | `goal_threshold` | Alert when 75% of the category goal has been spent |
| `"$200 remaining"` | `goal_threshold` | Alert when the remaining balance drops to $200 or below |
| `"5% over"` | `pacing` | Alert when projected end-of-month spend exceeds the goal by 5%+ |

## Severities

| Severity | Pushover priority | Icon |
|---|---|---|
| `warning` | low (-1) | ⚠️ |
| `urgent` | high (1) | 🔴 |

## Alert cadence

All rule types use `min_hours_between_alerts` to control how often a given
trigger can fire. For `goal_threshold` rules, setting this high (e.g. `744` =
31 days) effectively means "fire once per month." For `pacing` rules, a lower
value like `24` acts as a daily re-alert if the category stays over pace.

## Auto-alerts

Tripwire can automatically detect all YNAB categories that have goals and apply
default alert rules to them. Enable this in `config.yaml`:

```yaml
auto_alerts:
  enabled: true
  exclude: ["Emergency Fund", "Savings"]  # optional: skip specific categories
  rules:
    - type: goal_threshold
      min_hours_between_alerts: 744
      triggers:
        - at: "75%"
          severity: warning
        - at: "90%"
          severity: urgent
```

With auto-alerts:
- Any category in YNAB with a goal automatically gets the default alert rules
- Categories in the `exclude` list are skipped
- Explicitly configured categories (in the `categories` section) override auto-detected ones
- Categories without goals are never auto-detected

This is the recommended approach — set reasonable defaults via `auto_alerts`, then only
explicitly configure categories that need custom thresholds.

## Pacing warm-up

The `warm_up_hours` field on `pacing` rules prevents false positives early in
the month. A single large transaction on day 1 would otherwise look like a
catastrophic overspend projection. Setting `warm_up_hours: 72` means pacing
rules don't evaluate until day 3.

## Workflow failure notifications

If the GitHub Actions workflow fails (tests fail, runtime errors, etc.), you'll
receive an urgent Pushover notification with a direct link to the failed run.
This uses the same `PUSHOVER_API_TOKEN` and `PUSHOVER_USER_KEYS` configured for
budget alerts.

## Rule types

Currently supported:

- `goal_threshold` — compares spend against the category's explicit goal in YNAB
- `pacing` — projects end-of-month spend based on current burn rate vs. calendar position

Planned:

- `historical_average` — compares current month spend against a trailing average
