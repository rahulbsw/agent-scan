#!/usr/bin/env bash
set -eu

uuid=""
if [[ "${1:-}" == "--uuid" ]]; then
  uuid="$2"
  shift 2
fi

if [[ -n "$uuid" ]]; then
  log=$(mktemp "/tmp/mcp_shim.${uuid}.XXXXXX")
else
  log=$(mktemp /tmp/mcp_shim.XXXXXX)
fi
printf 'shim log: %s\n' "$log" >&2
exec "$@" > >(tee -a "$log")
