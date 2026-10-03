#!/usr/bin/env bash
# check-forbidden-endpoints.sh: fail when shipped code or build files mention a
# forbidden endpoint (spec 2026-10-03-cleanup-design.md, section 7).
#
# Usage: check-forbidden-endpoints.sh [--root DIR] [--allowlist FILE]
#   --root DIR        git work tree to scan (default: current directory)
#   --allowlist FILE  TSV file: <path ERE> TAB <line ERE> TAB <justification>
#                     (default: <root>/scripts/forbidden-endpoints.allow, else
#                      <root>/.github/forbidden-endpoints.allow)
# Exit codes: 0 clean, 1 violations found, 2 usage or allowlist error.
set -euo pipefail

root="."
allowlist=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --allowlist) allowlist="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

cd "$root"
if [ -z "$allowlist" ]; then
  if [ -f scripts/forbidden-endpoints.allow ]; then
    allowlist="scripts/forbidden-endpoints.allow"
  elif [ -f .github/forbidden-endpoints.allow ]; then
    allowlist=".github/forbidden-endpoints.allow"
  fi
fi

# Files that are never scanned: credits and license files, upstream notes,
# documentation, tests and fixtures, editor settings, issue templates,
# checksum files, binaries, and this checker with its allowlist (they contain
# the patterns on purpose).
EXCLUDE_RE='(^|/)(LICEN[CS]E|COPYING|NOTICE|CREDITS|AUTHORS)[^/]*$|(^|/)UPSTREAM\.md$|\.md$|(^|/)docs/|(^|/)(test|tests|testdata|__tests__|integrationtests|test\.configs|\.vscode|\.github/ISSUE_TEMPLATE)/|_test\.(go|py|dart)$|(^|/)test_[^/]*\.py$|(^|/)go\.(sum|work\.sum)$|(^|/)check-forbidden-endpoints[^/]*$|\.allow$|\.(png|jpg|jpeg|gif|webp|ico|icns|svg|ttf|otf|woff2?|srs|db|jar|so|dll|dylib|aar|zip|gz|xz|tgz|pb\.go)$'

B0='(^|[^[:alnum:]_])'
E0='([^[:alnum:]_]|$)'
# Rule privacy: telemetry and IP-lookup services, the Telegram domain front, the review prompt.
RULE_PRIVACY="${B0}sentry|${B0}(ip\.sb|ipwho\.is|ipapi\.co|ip-api\.com|ident\.me|translate\.goog|in_app_review)${E0}"
# Rule hiddify-com: any hiddify.com host.
RULE_HIDDIFY_COM="${B0}hiddify\.com${E0}"
# Rule hiddify-github: fetches from Hiddify's GitHub organisations.
RULE_HIDDIFY_GITHUB="((https?|ssh|git)://([^/@[:space:]]+@)?|git@)(www\.)?github\.com[:/](hiddify|hiddify-com|hiddifydeveloper)([/.[:space:]\"']|$)|raw\.githubusercontent\.com/(hiddify|hiddify-com|hiddifydeveloper)/|api\.github\.com/repos/(hiddify|hiddify-com|hiddifydeveloper)/|codeload\.github\.com/(hiddify|hiddify-com|hiddifydeveloper)/|=>[[:space:]]*github\.com/(hiddify|hiddify-com|hiddifydeveloper)/|uses:[[:space:]]*(hiddify|hiddify-com|hiddifydeveloper)/|hiddifydeveloper"

files_list="$(mktemp)"
hits="$(mktemp)"
trap 'rm -f "$files_list" "$hits"' EXIT

git ls-files | grep -vE "$EXCLUDE_RE" > "$files_list" || true

scan() {
  local name="$1" pattern="$2"
  tr '\n' '\0' < "$files_list" \
    | xargs -0 grep -I -n -H -i -E -e "$pattern" -- 2>/dev/null \
    | awk -v rule="$name" '{ print rule "\t" $0 }' >> "$hits" || true
}
scan privacy "$RULE_PRIVACY"
scan hiddify-com "$RULE_HIDDIFY_COM"
scan hiddify-github "$RULE_HIDDIFY_GITHUB"

awk -F'\t' -v allowfile="$allowlist" '
  BEGIN {
    n = 0
    if (allowfile != "") {
      while ((getline line < allowfile) > 0) {
        if (line ~ /^[[:space:]]*(#|$)/) continue
        split(line, f, "\t")
        if (f[1] == "" || f[2] == "" || f[3] == "") {
          print "allowlist error (need path ERE, line ERE, justification): " line > "/dev/stderr"
          bad = 1; continue
        }
        n++; ap[n] = f[1]; al[n] = f[2]; used[n] = 0
      }
    }
    if (bad) exit 2
  }
  {
    rule = $1
    rest = substr($0, length(rule) + 2)
    c1 = index(rest, ":"); path = substr(rest, 1, c1 - 1)
    rest2 = substr(rest, c1 + 1)
    c2 = index(rest2, ":"); lineno = substr(rest2, 1, c2 - 1)
    text = substr(rest2, c2 + 1)
    # go.mod comments never fetch anything.
    if (path ~ /(^|\/)go\.mod$/ && text ~ /^[[:space:]]*\/\//) next
    for (i = 1; i <= n; i++) {
      if (path ~ ap[i] && text ~ al[i]) { used[i] = 1; next }
    }
    count++
    printf "%s:%s: [%s] %s\n", path, lineno, rule, text
  }
  END {
    if (bad) exit 2
    for (i = 1; i <= n; i++) if (!used[i]) printf "warning: unused allowlist entry: %s\t%s\n", ap[i], al[i] > "/dev/stderr"
    if (count > 0) { printf "\n%d forbidden-endpoint hit(s). Fix them or add a justified entry to %s.\n", count, (allowfile == "" ? "the allowlist" : allowfile) > "/dev/stderr"; exit 1 }
    print "forbidden-endpoint check: clean"
  }
' "$hits"
