#!/bin/bash
# installer.sh must verify the archive against the release's SHA256SUMS before installing.
# curl, uname and ldd are stubbed; nothing touches the network or the real system.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/fx/pkg"

if command -v sha256sum >/dev/null 2>&1; then SHA() { sha256sum "$1" | awk '{print $1}'; }
else SHA() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

printf '#!/bin/sh\necho fake core\n' > "$T/fx/pkg/hiddify-core"; chmod +x "$T/fx/pkg/hiddify-core"
tar -czf "$T/fx/hiddify-core-linux-amd64.tar.gz" -C "$T/fx/pkg" hiddify-core
GOOD="$(SHA "$T/fx/hiddify-core-linux-amd64.tar.gz")"
BAD="$(printf 'x' | SHA /dev/stdin)"

cat > "$T/bin/curl" <<'STUB'
#!/bin/bash
url=""; out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; -*) ;; *) url="$1" ;; esac; shift; done
case "$url" in
  *api.github.com*) echo '"tag_name": "core-v9.9.9-derbent.1"'; exit 0 ;;
  */SHA256SUMS) [ -f "$FX/SHA256SUMS" ] || exit 22; cp "$FX/SHA256SUMS" "$out"; exit 0 ;;
  *-glibc.tar.gz) exit 22 ;;  # forces the generic fallback
  */hiddify-core-linux-amd64.tar.gz) cp "$FX/hiddify-core-linux-amd64.tar.gz" "$out"; exit 0 ;;
esac
exit 22
STUB
printf '#!/bin/sh\necho x86_64\n' > "$T/bin/uname"
printf '#!/bin/sh\necho "ldd (GNU libc) glibc 2.39"\n' > "$T/bin/ldd"
chmod +x "$T/bin/"*

fail=0
run() { # name expect(ok|fail) ; SHA256SUMS content on stdin ("-" = no file)
  local name="$1" expect="$2" prefix="$T/root-$1" content; content="$(cat)"
  rm -f "$T/fx/SHA256SUMS"
  [ "$content" = "-" ] || printf '%s\n' "$content" > "$T/fx/SHA256SUMS"
  mkdir -p "$prefix"
  PATH="$T/bin:$PATH" FX="$T/fx" DESTDIR="$prefix" bash "$HERE/installer.sh" >"$T/out-$name" 2>&1
  local rc=$? installed=no; [ -e "$prefix/usr/bin/hiddify-core" ] && installed=yes
  if [ "$expect" = ok ] && [ $rc -eq 0 ] && [ $installed = yes ]; then echo "PASS $name"
  elif [ "$expect" = fail ] && [ $rc -ne 0 ] && [ $installed = no ]; then echo "PASS $name"
  else echo "FAIL $name (rc=$rc installed=$installed)"; sed 's/^/    /' "$T/out-$name"; fail=1; fi
}

echo "$GOOD  hiddify-core-linux-amd64.tar.gz"                          | run matching ok
echo "$BAD  hiddify-core-linux-amd64.tar.gz"                           | run mismatch fail
echo "-"                                                               | run missing-sums fail
echo "$GOOD  hiddify-core-linux-arm64.tar.gz"                          | run no-line fail
echo "$GOOD  other-hiddify-core-linux-amd64.tar.gz"                    | run substring-only fail
echo "$GOOD  hiddify-core-linux-amd64.tar.gz.sig"                      | run prefix-only fail
exit $fail
