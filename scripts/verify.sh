#!/usr/bin/env bash
# End-to-end verification for sb-render.
#
# Runs static checks, builds the binary, starts it against examples/ on a free
# loopback port, and exercises the full HTTP matrix. Every scenario prints one
# PASS/FAIL line. The server is always stopped and the temp dir removed.
#
# Requires: go, gofmt, curl, jq, python3. Optional: sing-box (for `check`).
# SC2016: $hook is a literal JSON key. SC2317: cleanup runs via the EXIT trap.
# shellcheck disable=SC2016,SC2317
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
pass() { printf 'PASS %s\n' "$*"; }
bad() {
	printf 'FAIL %s\n' "$*"
	fail=1
}

expect_status() {
	local label=$1 want=$2 got=$3
	if [[ "$got" == "$want" ]]; then
		pass "$label -> HTTP $want"
	else
		bad "$label -> HTTP ${got:-<no response>}, want $want"
	fi
}

for tool in go gofmt curl jq python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "FAIL required tool not found: $tool" >&2
		exit 1
	fi
done

WORK=$(mktemp -d)
BIN="$WORK/sb-render"
SERVER_LOG="$WORK/server.log"
BODY="$WORK/body.out"
HEADERS="$WORK/headers.out"
TUN_BODY="$WORK/tun.json"
TPROXY_BODY="$WORK/tproxy.json"
EXPECTED="$WORK/expected.out"
pid=""

cleanup() {
	local rc=$?
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	fi
	rm -rf "$WORK"
	exit "$rc"
}
trap cleanup EXIT

# get METHOD URL [curl args...] -> status code, body in $BODY, headers in $HEADERS.
get() {
	local method=$1 url=$2
	shift 2
	: >"$BODY"
	: >"$HEADERS"
	curl -sS -X "$method" -D "$HEADERS" -o "$BODY" -w '%{http_code}' "$@" "$url"
}

# head URL [curl args...] -> status code, no body, headers in $HEADERS.
head_req() {
	local url=$1
	shift
	: >"$HEADERS"
	: >"$BODY"
	curl -sS -I -o /dev/null -D "$HEADERS" -w '%{http_code}' "$@" "$url"
}

header_value() {
	awk -v key="$1" '
		{
			line = $0
			sub(/\r$/, "", line)
			pos = index(line, ":")
			if (pos > 0 && tolower(substr(line, 1, pos - 1)) == tolower(key)) {
				val = substr(line, pos + 1)
				sub(/^[ \t]+/, "", val)
				print val
				exit
			}
		}
	' "$HEADERS"
}

echo "== static checks =="
if go test ./... -count=1; then
	pass "go test ./... -count=1"
else
	bad "go test ./... -count=1"
fi

if go vet ./...; then
	pass "go vet ./..."
else
	bad "go vet ./..."
fi

unformatted=$(gofmt -l .)
if [[ -z "$unformatted" ]]; then
	pass "gofmt -l . (clean)"
else
	bad "gofmt -l . reported: $unformatted"
fi

if go build -trimpath -o "$BIN" ./cmd/sb-render; then
	pass "build ./cmd/sb-render"
else
	bad "build ./cmd/sb-render"
	echo "cannot continue without a binary" >&2
	exit 1
fi

echo "== start server =="
PORT=$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')
BASE="http://127.0.0.1:$PORT"

"$BIN" --config examples --listen "127.0.0.1:$PORT" --log-level error >"$SERVER_LOG" 2>&1 &
pid=$!

ready=0
for ((i = 0; i < 100; i++)); do
	if ! kill -0 "$pid" 2>/dev/null; then
		break
	fi
	code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/healthz" 2>/dev/null || true)
	if [[ "$code" == "200" ]]; then
		ready=1
		break
	fi
	sleep 0.05
done
if [[ "$ready" -ne 1 ]]; then
	echo "FAIL server did not become ready on $BASE" >&2
	cat "$SERVER_LOG" >&2 || true
	exit 1
fi
pass "server ready on $BASE"

echo "== HTTP matrix =="

status=$(get GET "$BASE/render" -H 'X-Auth-User: general' || true)
expect_status "GET /render general (default tun)" 200 "$status"
if [[ "$status" == "200" ]]; then
	cp "$BODY" "$TUN_BODY"
	latent_etag=$(header_value ETag)

	if jq -e '(.inbounds | map(.tag) | index("tun-in")) != null' "$TUN_BODY" >/dev/null 2>&1; then
		pass "tun body contains tun-in inbound"
	else
		bad "tun body missing tun-in inbound"
	fi
	if grep -q '00000000-0000-0000-0000-000000000001' "$TUN_BODY"; then
		pass "tun body contains example UUID"
	else
		bad "tun body missing example UUID"
	fi
	if jq empty "$TUN_BODY" >/dev/null 2>&1; then
		pass "tun body is valid JSON"
	else
		bad "tun body is not valid JSON"
	fi
	if grep -q '\$hook' "$TUN_BODY"; then
		bad "tun body still contains a \$hook marker"
	else
		pass "tun body has no \$hook marker"
	fi
fi

status=$(get GET "$BASE/render?inbound=tproxy" -H 'X-Auth-User: general' || true)
expect_status "GET /render?inbound=tproxy general" 200 "$status"
if [[ "$status" == "200" ]]; then
	cp "$BODY" "$TPROXY_BODY"

	if jq -e '(.inbounds | map(.tag)) == ["tproxy-in"]' "$TPROXY_BODY" >/dev/null 2>&1; then
		pass "tproxy body has only tproxy-in inbound"
	else
		bad "tproxy body has wrong inbound tags"
	fi
	if jq -e '([.route.rules[]? | select(has("$hook") or (.action? == "resolve"))] | length) == 0' "$TPROXY_BODY" >/dev/null 2>&1; then
		pass "tproxy body has no hook/resolve rule"
	else
		bad "tproxy body contains a hook or resolve rule"
	fi
	if grep -q '\$hook' "$TPROXY_BODY" || grep -q '"prefix"' "$TPROXY_BODY"; then
		bad "tproxy body leaks hook/prefix markers"
	else
		pass "tproxy body has no \$hook/prefix marker"
	fi
	if grep -q 'mixed-in' "$TPROXY_BODY"; then
		bad "tproxy body unexpectedly contains mixed-in"
	else
		pass "tproxy body omits mixed-in"
	fi
	if jq empty "$TPROXY_BODY" >/dev/null 2>&1; then
		pass "tproxy body is valid JSON"
	else
		bad "tproxy body is not valid JSON"
	fi
fi

status=$(get GET "$BASE/render?inbound=tproxy" -H 'X-Auth-User: alice' || true)
expect_status "GET /render?inbound=tproxy alice (tproxy not allowed)" 403 "$status"

status=$(get GET "$BASE/render" -H 'X-Auth-User: nobody' || true)
expect_status "GET /render unknown user" 404 "$status"

status=$(get GET "$BASE/render?inbound=bogus" -H 'X-Auth-User: general' || true)
expect_status "GET /render bad inbound" 400 "$status"

status=$(get GET "$BASE/render" || true)
expect_status "GET /render missing X-Auth-User" 401 "$status"

if [[ -n "${latent_etag:-}" ]]; then
	status=$(get GET "$BASE/render" -H 'X-Auth-User: general' -H "If-None-Match: $latent_etag" || true)
	expect_status "GET /render If-None-Match" 304 "$status"
	if [[ ! -s "$BODY" ]]; then
		pass "304 response body is empty"
	else
		bad "304 response body is not empty"
	fi
	if [[ "$(header_value ETag)" == "$latent_etag" ]]; then
		pass "304 response repeats ETag"
	else
		bad "304 response ETag differs"
	fi
else
	bad "no ETag captured from the 200 response"
fi

status=$(head_req "$BASE/render" -H 'X-Auth-User: general' || true)
expect_status "HEAD /render general" 200 "$status"
if [[ ! -s "$BODY" ]]; then
	pass "HEAD /render has no body"
else
	bad "HEAD /render returned a body"
fi
if [[ -n "$(header_value ETag)" ]]; then
	pass "HEAD /render has ETag"
else
	bad "HEAD /render is missing ETag"
fi

status=$(head_req "$BASE/healthz" || true)
expect_status "HEAD /healthz" 200 "$status"
if [[ ! -s "$BODY" ]]; then
	pass "HEAD /healthz has no body"
else
	bad "HEAD /healthz returned a body"
fi

status=$(get GET "$BASE/healthz" || true)
expect_status "GET /healthz" 200 "$status"
printf 'ok\n' >"$EXPECTED"
if cmp -s "$EXPECTED" "$BODY"; then
	pass "GET /healthz body is 'ok\\n'"
else
	bad "GET /healthz body differs from 'ok\\n'"
fi

echo "== optional sing-box check =="
if command -v sing-box >/dev/null 2>&1; then
	for pair in "tun:$TUN_BODY" "tproxy:$TPROXY_BODY"; do
		name=${pair%%:*}
		file=${pair#*:}
		if [[ ! -s "$file" ]]; then
			bad "sing-box check $name skipped: no captured body"
			continue
		fi
		if sing-box check -c "$file" >"$WORK/sing-box-$name.log" 2>&1; then
			pass "sing-box check $name"
		else
			bad "sing-box check $name"
			cat "$WORK/sing-box-$name.log" >&2 || true
		fi
	done
else
	echo "SKIP sing-box check: sing-box binary not on PATH"
fi

echo "== server liveness =="
if kill -0 "$pid" 2>/dev/null; then
	pass "server still running at end of matrix"
else
	bad "server exited unexpectedly during the matrix"
	cat "$SERVER_LOG" >&2 || true
fi

if [[ "$fail" -ne 0 ]]; then
	echo "== server log =="
	cat "$SERVER_LOG" >&2 || true
	echo "FAIL one or more checks failed" >&2
	exit 1
fi

echo "PASS all checks"
exit 0
