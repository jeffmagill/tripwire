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
| `PUSHOVER_API_TOKEN` | Your Pushover application token |
| `PUSHOVER_USER_KEYS` | Comma-separated Pushover user keys, e.g. `key1,key2` |

`GITHUB_TOKEN` is provided automatically by Actions — no action needed.

### 3. Edit `config.yaml`

Replace the placeholder `budget_id` and `goal_id` values with your own. You
can find your budget ID and category IDs via the YNAB API:

```bash
# List budgets
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.ynab.com/v1/budgets

# List categories for a budget
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.ynab.com/v1/budgets/YOUR_BUDGET_ID/categories
```

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

## Pacing warm-up

The `warm_up_hours` field on `pacing` rules prevents false positives early in
the month. A single large transaction on day 1 would otherwise look like a
catastrophic overspend projection. Setting `warm_up_hours: 72` means pacing
rules don't evaluate until day 3.

## Rule types

Currently supported:

- `goal_threshold` — compares spend against the category's explicit goal in YNAB
- `pacing` — projects end-of-month spend based on current burn rate vs. calendar position

Planned:

- `historical_average` — compares current month spend against a trailing average
