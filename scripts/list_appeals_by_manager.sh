#!/usr/bin/env bash
#
# Fetch ALL appeals whose requestor's manager_email matches a given value.
#
# Filters on the nested details path:
#   details.__policy_metadata.requestor_details.manager_email
#
# Usage:
#   GUARDIAN_HOST=https://guardian.example.com \
#   AUTH_EMAIL=you@gojek.com \
#     ./list_appeals_by_manager.sh gaddigeppa.muthu@gojek.com
#
# Requires: curl, jq

set -euo pipefail

MANAGER_EMAIL="${1:?usage: $0 <manager_email>}"
GUARDIAN_HOST="${GUARDIAN_HOST:?set GUARDIAN_HOST, e.g. https://guardian.example.com}"
AUTH_EMAIL="${AUTH_EMAIL:?set AUTH_EMAIL, e.g. you@gojek.com}"

DETAILS_PATH="__policy_metadata.requestor_details.manager_email"
PAGE_SIZE="${PAGE_SIZE:-100}"

offset=0
total=-1
all='[]'

while :; do
  page="$(
    curl -sfG "${GUARDIAN_HOST}/v1beta1/appeals" \
      -H "X-Auth-Email: ${AUTH_EMAIL}" \
      --data-urlencode "details_paths=${DETAILS_PATH}" \
      --data-urlencode "details=${MANAGER_EMAIL}" \
      --data-urlencode "size=${PAGE_SIZE}" \
      --data-urlencode "offset=${offset}"
  )"

  total="$(jq -r '.total // 0' <<<"$page")"
  count="$(jq -r '.appeals | length' <<<"$page")"

  all="$(jq -s '.[0] + (.[1].appeals // [])' <<<"$all"$'\n'"$page")"

  offset=$((offset + count))
  [ "$count" -eq 0 ] && break
  [ "$offset" -ge "$total" ] && break
done

# Emit the full array of matching appeals
jq -n --argjson appeals "$all" '{total: ($appeals | length), appeals: $appeals}'
