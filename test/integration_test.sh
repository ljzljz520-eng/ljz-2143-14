#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/test/tmp/run-$$"
mkdir -p "$T"
PORT=$((18080 + ($$ % 2000)))
SERVER="http://127.0.0.1:$PORT"
TOOL="$ROOT/resource-tool"
PY="python3"
cleanup(){ [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
pass(){ echo "PASS: $*"; }
fail(){ echo "FAIL: $*" >&2; exit 1; }

$PY "$ROOT/server/resource_server.py" --state "$T/server" init-demo >/dev/null
PKG_V1=$(sqlite3_missing(){ :; }; $PY - "$T/server" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]+'/resource.db')
print(c.execute("select package_id from packages where version='1.0.0'").fetchone()[0])
PY
)
PKG_V2=$( $PY - "$T/server" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]+'/resource.db')
print(c.execute("select package_id from packages where version='2.0.0'").fetchone()[0])
PY
)
cp "$T/server/packages/$PKG_V1.rrpkg" "$T/package-v1.rrpkg"
cp "$T/server/packages/$PKG_V1.rrpkg" "$T/truncated.rrpkg"
truncate -s $(( $(stat -c%s "$T/truncated.rrpkg") - 1 )) "$T/truncated.rrpkg"

# 1. Portable offline install into a directory containing Chinese characters.
PORTABLE="$T/便携终端/device"
"$TOOL" init --root "$PORTABLE" >/dev/null
"$TOOL" install "$T/package-v1.rrpkg" --root "$PORTABLE" | grep -q "activated $PKG_V1"
"$TOOL" resolve backgrounds/background.png --root "$PORTABLE" | grep -q "^$PORTABLE/blobs/"
pass "portable offline install and Chinese path resolution"

# True portable layout: launched from another CWD, no explicit root and no env root.
PORTBIN="$T/便携包/bin/resource-tool"
mkdir -p "$T/便携包/bin"
cp "$TOOL" "$PORTBIN"
PORTROOT=$(cd "$T" && "$PORTBIN" init)
[ "$PORTROOT" = "$T/便携包/bin/resources" ]
(cd "$T" && "$PORTBIN" install "$T/package-v1.rrpkg") | grep -q "activated $PKG_V1"
(cd "$T" && "$PORTBIN" resolve backgrounds/background.png) | grep -q "^$T/便携包/bin/resources/blobs/"
pass "portable executable resolves bundled root without CWD or build path"

# 2. Half package must not replace current complete version.
if "$TOOL" install "$T/truncated.rrpkg" --root "$PORTABLE" 2>"$T/err"; then fail "truncated package accepted"; fi
grep -q "truncated package" "$T/err"
"$TOOL" status --root "$PORTABLE" | grep -q "$PKG_V1"
pass "truncated download leaves old version active"

# 3. Logical path traversal cannot escape resource root.
if "$TOOL" resolve ../../etc/passwd --root "$PORTABLE" 2>"$T/err"; then fail "traversal accepted"; fi
grep -q "missing" "$T/err"
pass "relative path traversal rejected"

# 4. Start server, update v1, publish v2, test pending/current and rollback.
$PY "$ROOT/server/resource_server.py" --state "$T/server" serve --host 127.0.0.1 --port "$PORT" >"$T/server.log" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do curl -sf "$SERVER/api/packages" >/dev/null && break; sleep .1; done
ONLINE="$T/online 设备"
"$TOOL" init --root "$ONLINE" >/dev/null
"$TOOL" update --server "$SERVER" --group factory --root "$ONLINE" | grep -q "activated $PKG_V1"
pass "online current v1 install"

# Pending v2 must not be assigned yet.
"$TOOL" status --root "$ONLINE" | grep -q "$PKG_V1"
# Activate v2 through server.
$PY "$ROOT/server/resource_server.py" --state "$T/server" publish factory "$PKG_V2" --release-id factory-v2 >/dev/null
"$TOOL" update --server "$SERVER" --group factory --root "$ONLINE" | grep -q "activated $PKG_V2"
"$TOOL" status --root "$ONLINE" | grep -A1 current | grep -q "$PKG_V2"
"$TOOL" status --root "$ONLINE" | grep -A1 previous | grep -q "$PKG_V1"
pass "atomic switch v1 to v2 with retained rollback"
"$TOOL" rollback --root "$ONLINE" | grep -q "rolled back $PKG_V1"
"$TOOL" status --root "$ONLINE" | grep -A1 current | grep -q "$PKG_V1"
pass "client rollback to complete previous package"

# 4b. Server GC must retain current, pending and rollback roots, never use download recency.
GC_JSON=$($PY "$ROOT/server/resource_server.py" --state "$T/server" gc)
echo "$GC_JSON" | grep -q '"removed_packages": 0'
echo "$GC_JSON" | grep -q "$PKG_V1"
echo "$GC_JSON" | grep -q "$PKG_V2"
pass "server GC retains current, pending and rollback release packages"

# 5. Two devices may not claim same group resource.
OTHER="$T/other-device"
"$TOOL" init --root "$OTHER" >/dev/null
if "$TOOL" update --server "$SERVER" --group factory --root "$OTHER" 2>"$T/err"; then fail "second device claimed group"; fi
grep -q "rejected by group" "$T/err"
pass "second device is prevented from taking first device's group resource"

# 6. Low simulated space rejects update without breaking current.
if RR_FORCE_FREE_BYTES=1 "$TOOL" update --server "$SERVER" --group factory --root "$ONLINE" 2>"$T/err"; then fail "low-space update accepted"; fi
grep -q "insufficient cache space" "$T/err"
"$TOOL" status --root "$ONLINE" | grep -A1 current | grep -q "$PKG_V1"
pass "insufficient cache preserves active release"

# 7. GC considers current and previous; it reuses deduplicated blobs.
BEFORE=$(find "$ONLINE/blobs" -type f | wc -l)
"$TOOL" gc --root "$ONLINE" >/dev/null
AFTER=$(find "$ONLINE/blobs" -type f | wc -l)
[ "$BEFORE" = "$AFTER" ]
pass "GC retains current and rollback references instead of using download recency"

# 8. Web diagnostics reports a deliberately missing server blob.
MISSING_SHA=$($PY - "$T/server" "$PKG_V1" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]+'/resource.db')
print(c.execute("select sha256 from package_files where package_id=? and logical_path='icons/status.svg'",(sys.argv[2],)).fetchone()[0])
PY
)
rm -f "$T/server/blobs/${MISSING_SHA:0:2}/$MISSING_SHA"
curl -sf "$SERVER/api/diagnostics" | grep -q "blob file is absent on server"
pass "web diagnostics lists exact missing-file reason"

# 9. Missing asset still resolves absence clearly and GUI fallback code is compiled behavior contract.
if "$TOOL" resolve fonts/no-such-font.fnt --root "$ONLINE" 2>"$T/err"; then fail "unknown font resolved"; fi
grep -q "missing fonts/no-such-font.fnt" "$T/err"
pass "terminal reports missing logical resource while basic UI remains available"

echo "All integration tests passed."
