#!/usr/bin/env bash
set -euo pipefail

# check-env-docs.sh
#
# Verifies that the environment variable reference in
# docs/environment-variables.md stays in sync with the code and with
# .env.example.
#
# It fails (non-zero exit) when:
#   * a variable read by the code is missing from the doc
#   * the doc documents a variable the code never reads
#   * .env.example and the doc disagree
#
# Dependencies: bash, grep, sed, sort, comm.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MAIN_RS="$ROOT_DIR/bin/server/src/main.rs"
CONFIG_RS="$ROOT_DIR/crates/store/src/config.rs"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
DOC="$ROOT_DIR/docs/environment-variables.md"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CODE_VARS="$TMP_DIR/code_vars.txt"
EXAMPLE_VARS="$TMP_DIR/example_vars.txt"
DOC_VARS="$TMP_DIR/doc_vars.txt"

fail=0

err() {
    echo "error: $*" >&2
}

# ---------------------------------------------------------------------------
# 1. Variables read by the code.
# ---------------------------------------------------------------------------

: > "$CODE_VARS"

# bin/server/src/main.rs: env::var("NAME") / env::var_os("NAME")
if [[ -f "$MAIN_RS" ]]; then
    grep -oE 'env::var(_os)?\("([A-Za-z_][A-Za-z0-9_]*)"\)' "$MAIN_RS" \
        | sed -E 's/.*\("([A-Za-z_][A-Za-z0-9_]*)"\).*/\1/' \
        >> "$CODE_VARS" || true
else
    err "missing file: $MAIN_RS"
    fail=1
fi

# crates/store/src/config.rs: parse_env("NAME", ...) / secs_env("NAME", ...)
if [[ -f "$CONFIG_RS" ]]; then
    grep -oE '(parse_env|secs_env)\("([A-Za-z_][A-Za-z0-9_]*)"' "$CONFIG_RS" \
        | sed -E 's/.*\("([A-Za-z_][A-Za-z0-9_]*)"$/\1/' \
        >> "$CODE_VARS" || true
else
    err "missing file: $CONFIG_RS"
    fail=1
fi

sort -u -o "$CODE_VARS" "$CODE_VARS"

# ---------------------------------------------------------------------------
# 2. Variables present in .env.example.
# ---------------------------------------------------------------------------

: > "$EXAMPLE_VARS"

if [[ -f "$ENV_EXAMPLE" ]]; then
    # Match lines like `NAME=...` or `export NAME=...`, ignoring comments
    # and blank lines. Trim surrounding whitespace from the name.
    sed -E \
        -e 's/^[[:space:]]*//' \
        -e 's/^export[[:space:]]+//' \
        -e '/^#/d' \
        -e '/^$/d' \
        "$ENV_EXAMPLE" \
        | grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' \
        | sed -E 's/=$//' \
        >> "$EXAMPLE_VARS" || true
else
    err "missing file: $ENV_EXAMPLE"
    fail=1
fi

sort -u -o "$EXAMPLE_VARS" "$EXAMPLE_VARS"

# ---------------------------------------------------------------------------
# 3. Variables documented in docs/environment-variables.md.
# ---------------------------------------------------------------------------
#
# The reference is a Markdown table. Each documented variable is expected to
# appear as a table cell containing a backticked name, e.g. `| `NAME` | ... |`.
# We extract every backticked token from table rows in the first column.

: > "$DOC_VARS"

if [[ -f "$DOC" ]]; then
    # Only consider table rows (lines starting with `|`), take the first cell,
    # and extract a backticked identifier from it.
    grep -E '^[[:space:]]*\|' "$DOC" \
        | sed -E 's/^[[:space:]]*\|[[:space:]]*//' \
        | sed -E 's/[[:space:]]*\|.*$//' \
        | grep -oE '`[A-Za-z_][A-Za-z0-9_]*`' \
        | sed -E 's/^`(.*)`$/\1/' \
        >> "$DOC_VARS" || true
else
    err "missing file: $DOC"
    fail=1
fi

sort -u -o "$DOC_VARS" "$DOC_VARS"

# ---------------------------------------------------------------------------
# 4. Comparisons.
# ---------------------------------------------------------------------------

report_missing() {
    local label="$1" file="$2"
    if [[ -s "$file" ]]; then
        err "$label"
        sed 's/^/  - /' "$file" >&2
        fail=1
    fi
}

# Variables read by the code but not documented.
comm -23 "$CODE_VARS" "$DOC_VARS" > "$TMP_DIR/code_not_doc.txt"
report_missing "environment variables read by the code but missing from $DOC:" \
    "$TMP_DIR/code_not_doc.txt"

# Variables documented but never read by the code.
comm -13 "$CODE_VARS" "$DOC_VARS" > "$TMP_DIR/doc_not_code.txt"
report_missing "environment variables documented in $DOC but never read by the code:" \
    "$TMP_DIR/doc_not_code.txt"

# Variables in .env.example but not documented.
comm -23 "$EXAMPLE_VARS" "$DOC_VARS" > "$TMP_DIR/example_not_doc.txt"
report_missing "environment variables present in $ENV_EXAMPLE but missing from $DOC:" \
    "$TMP_DIR/example_not_doc.txt"

# Variables documented but not present in .env.example.
comm -13 "$EXAMPLE_VARS" "$DOC_VARS" > "$TMP_DIR/doc_not_example.txt"
report_missing "environment variables documented in $DOC but missing from $ENV_EXAMPLE:" \
    "$TMP_DIR/doc_not_example.txt"

if [[ "$fail" -ne 0 ]]; then
    echo "" >&2
    echo "Environment variable documentation is out of date." >&2
    echo "Update $DOC (and $ENV_EXAMPLE) to match the code." >&2
    exit 1
fi

echo "Environment variable documentation is up to date."