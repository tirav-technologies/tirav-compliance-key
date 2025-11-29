#!/usr/bin/env bash
# post_compliance_summary.sh
# Premium consolidated compliance summary to Slack with verification status.

set -Eeuo pipefail

# ------------------------------
# Configuration
# ------------------------------
: "${SLACK_WEBHOOK_COMPLIANCE:?SLACK_WEBHOOK_COMPLIANCE is required}"
: "${FINGERPRINT:?FINGERPRINT is required}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/home/tirav/carbon_reports/logs/archive}"
CADENCES=("daily" "weekly" "monthly" "quarterly")

# ------------------------------
# Helpers
# ------------------------------

shorten() {
  # Shorten a long hex string for display (default to 12 chars)
  local s="${1:-}"
  local n="${2:-12}"
  if [[ -z "$s" ]]; then
    printf "—"
  else
    printf "%s" "${s:0:$n}"
  fi
}

extract_field() {
  # Extract a value from a log line by label (e.g., "Hash:" or "Prev:")
  # Returns empty if not found
  local file="$1"
  local label="$2"
  if [[ -f "$file" ]]; then
    awk -v L="$label" '$1==L {print $2}' "$file" | tail -n 1
  else
    printf ""
  fi
}

extract_timestamp() {
  # Prefer Timestamp: line in the log, else fallback to signature time via gpg, else current UTC
  local log="$1"
  local sig="$2"
  local ts=""
  if [[ -f "$log" ]]; then
    ts="$(awk '$1=="Timestamp:"{print $2}' "$log" | tail -n 1)"
  fi
  if [[ -z "$ts" && -f "$sig" && -f "$log" ]]; then
    # Parse gpg signature time (best effort)
    # Example: "gpg: Signature made Fri 14 Nov 2025 00:45:17 EST"
    local sigline
    sigline="$(gpg --verify "$sig" "$log" 2>&1 | grep -m1 '^gpg: Signature made ' || true)"
    if [[ -n "$sigline" ]]; then
      # Convert to ISO if possible (requires GNU date with --date). If conversion fails, keep raw.
      # Extract the substring after "Signature made "
      local raw="${sigline#*Signature made }"
      # Attempt conversion
      ts="$(date -u --date="$raw" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
    fi
  fi
  if [[ -z "$ts" ]]; then
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  fi
  printf "%s" "$ts"
}

verify_signature() {
  # Return status string: Good, Bad, Missing
  local sig="$1"
  local log="$2"
  if [[ ! -f "$sig" || ! -f "$log" ]]; then
    printf "Missing"
    return
  fi
  if gpg --verify "$sig" "$log" >/dev/null 2>&1; then
    printf "Good"
  else
    printf "Bad"
  fi
}

# Escape JSON special characters in text (minimal, safe for Slack fields)
json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf "%s" "$s"
}

# ------------------------------
# Build data for each cadence
# ------------------------------
declare -a fields
for c in "${CADENCES[@]}"; do
  log="$ARCHIVE_DIR/${c}_archive.log"
  sig="$ARCHIVE_DIR/${c}_archive.sig"

  status="$(verify_signature "$sig" "$log")"
  hash="$(extract_field "$log" "Hash:")"
  prev="$(extract_field "$log" "Prev:")"
  ts="$(extract_timestamp "$log" "$sig")"

  # Format display elements
  display_hash="$(shorten "$hash" 16)"
  display_prev="$(shorten "$prev" 16)"
  emoji="❌"
  [[ "$status" == "Good" ]] && emoji="✅"
  [[ "$status" == "Missing" ]] && emoji="⚠️"

  text="*$(json_escape "${c^}")*: ${emoji} ${status}\n• Hash: \`$(json_escape "$display_hash")\`\n• Prev: \`$(json_escape "$display_prev")\`\n• Timestamp: \`$(json_escape "$ts")\`"
  fields+=("{\"type\":\"mrkdwn\",\"text\":\"$text\"}")
done

run_ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ------------------------------
# Construct Slack Block Kit payload
# ------------------------------
payload=$(cat <<JSON
{
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "📊 Consolidated Compliance Digest" }
    },
    {
      "type": "context",
      "elements": [
        { "type": "mrkdwn", "text": "Tenant: \`default\` · Run: \`$run_ts\`" }
      ]
    },
    {
      "type": "section",
      "fields": [
        ${fields[*]}
      ]
    },
    { "type": "divider" },
    {
      "type": "context",
      "elements": [
        { "type": "mrkdwn", "text": "🔑 Fingerprint: \`$(json_escape "$FINGERPRINT")\`" },
        { "type": "mrkdwn", "text": "Archive: \`$(json_escape "$ARCHIVE_DIR")\`" }
      ]
    }
  ]
}
JSON
)


# ------------------------------
# Post to Slack
# ------------------------------
curl -s -X POST -H 'Content-type: application/json' \
  --data "$payload" \
  "$SLACK_WEBHOOK_COMPLIANCE" >/dev/null

echo "✅ Consolidated compliance summary posted at $run_ts"
