#!/usr/bin/env bash
#
# lint-migrations.sh - Lint SQL migrations for destructive or locking statements.
#
# Flags:
#   - DROP TABLE / DROP COLUMN (data loss)
#   - CREATE INDEX without CONCURRENTLY (locks the table)
#   - ALTER TYPE on large tables (rewrites / locks the table)
#
# Files containing a `-- migration-lint: allow <reason>` annotation are skipped.
#
# Usage:
#   scripts/lint-migrations.sh [file ...]
#
# If no files are given, all migrations under crates/store/migrations are scanned.
#
# Exit codes:
#   0 - no violations
#   1 - violations found
#   2 - usage / environment error
#
# See docs/migrations.md for guidance and override annotations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MIGRATIONS_DIR="${REPO_ROOT}/crates/store/migrations"
DOCS_REF="docs/migrations.md"

# Tables considered "large" / hot. ALTER TYPE on these requires an override.
# Keep in sync with the high-volume tables documented in docs/migrations.md.
LARGE_TABLES=(
  "transactions"
  "audit_logs"
  "webhook_deliveries"
  "sessions"
  "payment_link_payments"
  "idempotency_keys"
)

# Annotation that opts a file out of linting.
ALLOW_ANNOTATION_RE='--[[:space:]]*migration-lint:[[:space:]]*allow[[:space:]]+[^[:space:]]'

# Numeric version prefixes already shared by multiple merged migrations.
# New duplicates must be resolved instead of added here.
ALLOWED_DUPLICATE_PREFIXES=(
  "0021"
  "0026"
  "0032"
)

usage() {
  echo "Usage: $0 [file ...]" >&2
  echo "  Lints SQL migrations for destructive or locking statements." >&2
  echo "  With no arguments, scans ${MIGRATIONS_DIR}." >&2
}

# Collect target files.
declare -a FILES=()
if [[ $# -gt 0 ]]; then
  for arg in "$@"; do
    if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
      usage
      exit 0
    fi
    if [[ ! -f "$arg" ]]; then
      echo "error: file not found: $arg" >&2
      exit 2
    fi
    FILES+=("$arg")
  done
else
  if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    echo "error: migrations directory not found: $MIGRATIONS_DIR" >&2
    exit 2
  fi
  while IFS= read -r -d '' f; do
    FILES+=("$f")
  done < <(find "$MIGRATIONS_DIR" -type f -name '*.sql' -print0 | sort -z)
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No migration files to lint."
  exit 0
fi

# Build a regex alternation of large table names.
large_tables_re="$(IFS='|'; echo "${LARGE_TABLES[*]}")"

violations=0

# Strip SQL comments (line comments and block comments) so we don't flag
# patterns that only appear in comments. Preserves line structure.
strip_comments() {
  # Remove /* ... */ block comments (non-greedy across lines), then -- line comments.
  perl -0777 -pe 's{/\*.*?\*/}{}gs; s{--[^\n]*}{}g' "$1"
}

report() {
  local file="$1" lineno="$2" rule="$3" detail="$4"
  echo "  ${file}:${lineno}: [${rule}] ${detail}" >&2
  violations=$((violations + 1))
}

lint_file() {
  local file="$1"

  # Skip files with an explicit override annotation.
  if grep -Eq "$ALLOW_ANNOTATION_RE" "$file"; then
    echo "skip (annotated): ${file}"
    return 0
  fi

  local stripped
  stripped="$(strip_comments "$file")"

  # Iterate over the comment-stripped content, tracking original line numbers.
  # We re-read the file line by line and use the stripped content per line.
  local lineno=0
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    local upper
    upper="$(printf '%s' "$line" | tr '[:lower:]' '[:upper:]')"

    # Rule: DROP TABLE
    if [[ "$upper" =~ (^|[^A-Z_])DROP[[:space:]]+TABLE([^A-Z_]|$) ]]; then
      report "$file" "$lineno" "drop-table" \
        "DROP TABLE is destructive; use a staged migration or annotate with '-- migration-lint: allow <reason>'"
    fi

    # Rule: DROP COLUMN (also ALTER TABLE ... DROP COLUMN)
    if [[ "$upper" =~ (^|[^A-Z_])DROP[[:space:]]+COLUMN([^A-Z_]|$) ]]; then
      report "$file" "$lineno" "drop-column" \
        "DROP COLUMN is destructive; use a staged migration or annotate with '-- migration-lint: allow <reason>'"
    fi

    # Rule: CREATE INDEX without CONCURRENTLY
    if [[ "$upper" =~ (^|[^A-Z_])CREATE[[:space:]]+(UNIQUE[[:space:]]+)?INDEX([^A-Z_]|$) ]]; then
      if [[ ! "$upper" =~ CONCURRENTLY ]]; then
        report "$file" "$lineno" "create-index-non-concurrent" \
          "CREATE INDEX must use CONCURRENTLY to avoid locking the table"
      fi
    fi

    # Rule: ALTER TYPE on large tables
    if [[ "$upper" =~ (^|[^A-Z_])ALTER[[:space:]]+TYPE([^A-Z_]|$) ]]; then
      # Look for a large table reference on the same line.
      if [[ "$upper" =~ (^|[^A-Z_])(${large_tables_re})([^A-Z_]|$) ]]; then
        report "$file" "$lineno" "alter-type-large-table" \
          "ALTER TYPE on a large table rewrites/locks it; use a staged migration or annotate with '-- migration-lint: allow <reason>'"
      fi
    fi
  done <<< "$stripped"

  return 0
}

echo "Linting ${#FILES[@]} migration file(s)..."

for f in "${FILES[@]}"; do
  lint_file "$f"
done

# Rule: duplicate numeric version prefixes across migrations.
check_duplicate_prefixes() {
  local -A prefix_files=()
  local f base prefix

  for f in "${FILES[@]}"; do
    base="$(basename "$f")"
    if [[ "$base" =~ ^([0-9]+) ]]; then
      prefix="${BASH_REMATCH[1]}"
      prefix_files["$prefix"]+="${base}"$'\n'
    fi
  done

  local allowed p
  for p in "${!prefix_files[@]}"; do
    local count
    count="$(printf '%s' "${prefix_files[$p]}" | grep -c .)"
    if [[ $count -le 1 ]]; then
      continue
    fi

    allowed=0
    for a in "${ALLOWED_DUPLICATE_PREFIXES[@]}"; do
      if [[ "$a" == "$p" ]]; then
        allowed=1
        break
      fi
    done
    if [[ $allowed -eq 1 ]]; then
      continue
    fi

    echo "  [duplicate-prefix] version prefix ${p} is shared by ${count} migrations:" >&2
    while IFS= read -r base; do
      [[ -n "$base" ]] && echo "    ${base}" >&2
    done <<< "${prefix_files[$p]}"
    violations=$((violations + 1))
  done
}

check_duplicate_prefixes

if [[ $violations -gt 0 ]]; then
  echo "" >&2
  echo "Found ${violations} migration lint violation(s)." >&2
  echo "See ${DOCS_REF} for safe migration patterns and override annotations." >&2
  exit 1
fi

echo "All migrations passed lint."
exit 0