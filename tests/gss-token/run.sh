#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

SO_PATH="$REPO_ROOT/sshkey.so"
if [ ! -f "$SO_PATH" ]; then
	echo "Missing $SO_PATH. Run 'make' in repo root first." >&2
	exit 1
fi

CONFIG="$SCRIPT_DIR/gss-mech.conf"
if [ ! -f "$CONFIG" ]; then
	echo "Missing $CONFIG." >&2
	exit 1
fi

MECH_NAME="${MECH_NAME:-sshkey}"
SERVICE="${SERVICE:-sshkey}"
HOST="${HOST:-$(hostname)}"
COUNT="${COUNT:-1}"
CC="${CC:-cc}"
GSSAPI_LIB="${GSSAPI_LIB:-/lib/x86_64-linux-gnu/libgssapi.so.3}"
GSS_TOKEN="${GSS_TOKEN:-/usr/local/bin/gss-token}"
KNC="${KNC:-/usr/local/bin/knc}"
KNC_PORT="${KNC_PORT:-45679}"
WORK_DIR=

cleanup() {
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT

if ! command -v unshare >/dev/null 2>&1; then
	echo "unshare not found; cannot create private /etc/gss." >&2
	exit 1
fi
if [ ! -f "$GSSAPI_LIB" ]; then
	echo "Missing GSSAPI_LIB=$GSSAPI_LIB." >&2
	exit 1
fi
if [ ! -x "$GSS_TOKEN" ]; then
	echo "Missing executable GSS_TOKEN=$GSS_TOKEN." >&2
	exit 1
fi
if [ ! -x "$KNC" ]; then
	echo "Missing executable KNC=$KNC." >&2
	exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sshkey-gss.XXXXXX")
mkdir -p "$WORK_DIR/bin" "$WORK_DIR/gss"

sed "s#../../sshkey.so#$SO_PATH#" "$CONFIG" > "$WORK_DIR/gss/mech"
"$CC" -Wall -g -I/usr/include/heimdal -o "$WORK_DIR/bin/smoke" \
	"$SCRIPT_DIR/smoke.c" "$GSSAPI_LIB"

echo "Using private /etc/gss/mech for $MECH_NAME"
unshare -Ur -m sh -c '
	set -e
	mount --bind "$1/gss" /etc/gss
	i=0
	while [ "$i" -lt "$4" ]; do
		"$2" "$3"
		i=$((i + 1))
	done
' sh "$WORK_DIR" "$WORK_DIR/bin/smoke" "$SERVICE@$HOST" "$COUNT"

SSHKEY_TEST_SERVER_FIRST=1 LD_PRELOAD="$SO_PATH" \
	"$WORK_DIR/bin/smoke" "$SERVICE@$HOST"

python3 "$SCRIPT_DIR/gss-token-driver.py" "$SO_PATH" "$GSS_TOKEN"

KNC_MESSAGE="sshkey knc wrap smoke"
KNC_REPLY="$WORK_DIR/knc.reply"
KNC_SERVER_ERR="$WORK_DIR/knc.server.err"
KNC_CLIENT_ERR="$WORK_DIR/knc.client.err"

LD_PRELOAD="$SO_PATH" "$KNC" -lf -M 1 -T 10 "$KNC_PORT" /bin/cat \
	>/dev/null 2>"$KNC_SERVER_ERR" &
KNC_SERVER_PID=$!
sleep 1

if ! printf '%s\n' "$KNC_MESSAGE" | LD_PRELOAD="$SO_PATH" \
	"$KNC" "$SERVICE@127.0.0.1" "$KNC_PORT" \
	>"$KNC_REPLY" 2>"$KNC_CLIENT_ERR"; then
	cat "$KNC_CLIENT_ERR" >&2
	cat "$KNC_SERVER_ERR" >&2
	kill "$KNC_SERVER_PID" >/dev/null 2>&1 || true
	wait "$KNC_SERVER_PID" >/dev/null 2>&1 || true
	exit 1
fi
wait "$KNC_SERVER_PID" || true

if ! cmp -s "$KNC_REPLY" - <<EOF
$KNC_MESSAGE
EOF
then
	echo "knc reply mismatch" >&2
	cat "$KNC_REPLY" >&2
	cat "$KNC_CLIENT_ERR" >&2
	cat "$KNC_SERVER_ERR" >&2
	exit 1
fi

echo "knc wrap smoke: ok"
