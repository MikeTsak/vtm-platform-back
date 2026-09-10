#!/bin/sh
# Post-pull deploy steps for the Erebus API on Plesk.
#
# The code is already updated by the time this runs. It does NOT pull.
#
# Wire it in:  Plesk > Websites & Domains > Git > "Additional deployment
# actions"  ->  set the field to exactly:   sh deploy/after-pull.sh
#
# It also gets called by POST /api/_deploy (routes/deploy.js), which does its
# own `git pull` first and passes the pre-pull commit as $1.
#
# Steps: npm install (only if the manifest changed), regenerate the OpenAPI
# spec, write a deploy marker, then trigger a Passenger restart.
# Idempotent. Safe to run twice.
set -e

# cd to the repo root (this script lives in back/deploy/)
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

OLD_SHA="${1:-}"
NEW_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
SHORT_SHA="$(printf '%s' "$NEW_SHA" | cut -c1-7)"

# --- locate npm (not always on PATH when invoked from the app process) --------
NPM_BIN="$(command -v npm 2>/dev/null || true)"
if [ -z "$NPM_BIN" ]; then
  NODE_DIR="$(dirname "$(command -v node 2>/dev/null || echo /usr/bin/node)")"
  [ -x "$NODE_DIR/npm" ] && NPM_BIN="$NODE_DIR/npm"
fi
[ -z "$NPM_BIN" ] && NPM_BIN="npm"

# --- reinstall deps only when the manifest changed in this update -----------
changed_files=""
if [ -n "$OLD_SHA" ] && [ "$OLD_SHA" != "unknown" ] && git cat-file -e "$OLD_SHA" 2>/dev/null; then
  changed_files="$(git diff --name-only "$OLD_SHA" "$NEW_SHA" 2>/dev/null || echo __unknown__)"
elif git rev-parse 'HEAD@{1}' >/dev/null 2>&1; then
  changed_files="$(git diff --name-only 'HEAD@{1}' HEAD 2>/dev/null || echo __unknown__)"
else
  changed_files="__unknown__"   # can't tell -> install to be safe
fi

DEPS_STATE="skipped"
if [ "$changed_files" = "__unknown__" ] || printf '%s\n' "$changed_files" | grep -qE '^package(-lock)?\.json$'; then
  echo "deps: manifest changed (or undetermined) -> $NPM_BIN install"
  "$NPM_BIN" install --omit=dev --no-audit --no-fund
  DEPS_STATE="installed"
else
  echo "deps: unchanged -> skipping install"
fi

# --- regenerate the OpenAPI spec ------------------------------------------------
# Passenger runs the entry file directly, so `npm start`'s swagger step never
# fires on the server. Non-fatal: a stale spec doesn't break the API.
node swagger-autogen.js >/dev/null 2>&1 && echo "swagger: regenerated" || echo "swagger: regen skipped (non-fatal)"

# --- deploy marker (served at /public/deploy-status.json if this is the web
#     root — npm run deploy reads it to show the deployed commit). Non-fatal. ---
if [ -d public ]; then
  printf '{"sha":"%s","short":"%s","at":"%s","deps":"%s"}\n' \
    "$NEW_SHA" "$SHORT_SHA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$DEPS_STATE" \
    > public/deploy-status.json 2>/dev/null && echo "marker: wrote public/deploy-status.json" || true
fi

# --- graceful restart (Phusion Passenger watches this file) -------------------
mkdir -p tmp
touch tmp/restart.txt
echo "restart: touched tmp/restart.txt   (${OLD_SHA:-?} -> ${NEW_SHA})"
