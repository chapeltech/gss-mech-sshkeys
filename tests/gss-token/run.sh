#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
SO_PATH="$REPO_ROOT/sshkey.so"
CONFIG="$SCRIPT_DIR/gss-mech.conf"
MECH_NAME="${MECH_NAME:-sshkey}"
MECH_OID="${MECH_OID:-1.3.6.1.4.1.99999.1}"
SERVICE="${SERVICE:-sshkey}"
HOST="${HOST:-$(hostname)}"
COUNT="${COUNT:-1}"
CC="${CC:-cc}"
GSSAPI_INCLUDE_DIR="${GSSAPI_INCLUDE_DIR:-/usr/include/heimdal}"
GSSAPI_LIB="${GSSAPI_LIB:-}"
MIT_GSSAPI_PKG_CONFIG="${MIT_GSSAPI_PKG_CONFIG:-mit-krb5-gssapi}"
GSS_TOKEN="${GSS_TOKEN:-gss-token}"
KNC="${KNC:-knc}"
KNC_PORT="${KNC_PORT:-45679}"
REQUIRE_GSS_LOADERS="${REQUIRE_GSS_LOADERS:-0}"
REQUIRE_SSH_AGENT="${REQUIRE_SSH_AGENT:-0}"
WORK_DIR=
AGENT_PID=
SKIPPED=0
PHASES_RUN=0

cleanup() {
	if [ -n "$AGENT_PID" ]; then
		kill "$AGENT_PID" >/dev/null 2>&1 || true
		wait "$AGENT_PID" >/dev/null 2>&1 || true
	fi
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT

skip_phase() {
	echo "skipped $1: $2"
	SKIPPED=1
}

skip_loader_phase() {
	if [ "$REQUIRE_GSS_LOADERS" -eq 1 ]; then
		echo "required $1 unavailable: $2" >&2
		exit 1
	fi
	skip_phase "$1" "$2"
}

skip_agent_phase() {
	if [ "$REQUIRE_SSH_AGENT" -eq 1 ]; then
		echo "required $1 unavailable: $2" >&2
		exit 1
	fi
	skip_phase "$1" "$2"
}

pass_phase() {
	echo "$1: ok"
	PHASES_RUN=$((PHASES_RUN + 1))
}

find_executable() {
	local candidate=$1

	if [ -x "$candidate" ]; then
		printf '%s\n' "$candidate"
		return 0
	fi
	command -v "$candidate" 2>/dev/null
}

find_gss_token() {
	local candidate

	if find_executable "$GSS_TOKEN"; then
		return 0
	fi
	if [ "$GSS_TOKEN" != "gss-token" ]; then
		return 1
	fi
	for candidate in \
	    "$REPO_ROOT/../heimdal/lib/gssapi/gss-token"; do
		if [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	return 1
}

if [ -z "$GSSAPI_LIB" ]; then
	for candidate in \
	    /usr/lib64/heimdal/lib/libgssapi.so.3 \
	    /lib/x86_64-linux-gnu/libgssapi.so.3 \
	    /usr/lib64/heimdal/lib/libgssapi.so; do
		if [ -f "$candidate" ]; then
			GSSAPI_LIB=$candidate
			break
		fi
	done
fi

if [ ! -f "$SO_PATH" ]; then
	echo "Missing $SO_PATH. Run 'make' first." >&2
	exit 1
fi
if [ ! -f "$CONFIG" ]; then
	echo "Missing $CONFIG." >&2
	exit 1
fi
case "$COUNT" in
	''|*[!0-9]*|0)
		echo "COUNT must be a positive integer." >&2
		exit 1
		;;
esac
case "$REQUIRE_GSS_LOADERS:$REQUIRE_SSH_AGENT" in
	0:0|0:1|1:0|1:1)
		;;
	*)
		echo "REQUIRE_GSS_LOADERS and REQUIRE_SSH_AGENT must be 0 or 1." \
		    >&2
		exit 1
		;;
esac

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sshkey-gss.XXXXXX")
mkdir -p "$WORK_DIR/bin" "$WORK_DIR/gss"

FIXTURE_REASON=
if ! command -v ssh-keygen >/dev/null 2>&1; then
	FIXTURE_REASON="missing ssh-keygen"
elif ! ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/host_ed25519" ||
    ! ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/id_ed25519" ||
    ! ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/id_rejected" ||
    ! ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/id_agent"; then
	FIXTURE_REASON="ssh-keygen could not create a test key"
else
	read -r host_key_type host_key_data _ < "$WORK_DIR/host_ed25519.pub"
	read -r user_key_type user_key_data _ < "$WORK_DIR/id_ed25519.pub"
	read -r rejected_key_type rejected_key_data _ \
	    < "$WORK_DIR/id_rejected.pub"
	read -r agent_key_type agent_key_data _ < "$WORK_DIR/id_agent.pub"
	cp "$WORK_DIR/id_agent.pub" "$WORK_DIR/agent_identity.pub"
	user=$(id -un)
	printf '%s %s gss-sshkey test\n' "$user_key_type" "$user_key_data" \
	    > "$WORK_DIR/authorized_keys"
	printf '%s %s gss-sshkey rejected test\n' \
	    "$rejected_key_type" "$rejected_key_data" \
	    > "$WORK_DIR/authorized_keys_rejected"
	printf '%s %s gss-sshkey agent test\n' \
	    "$agent_key_type" "$agent_key_data" \
	    > "$WORK_DIR/authorized_keys_agent"
	printf '%s %s %s\n' "$HOST,localhost,127.0.0.1" \
	    "$host_key_type" "$host_key_data" > "$WORK_DIR/known_hosts"
	printf '%s %s %s\n' "$HOST,localhost,127.0.0.1" \
	    "$rejected_key_type" "$rejected_key_data" \
	    > "$WORK_DIR/known_hosts_rejected"
	printf '%s\n' \
	    "Host *" \
	    "  User $user" \
	    "  IdentityAgent none" \
	    "  IdentitiesOnly yes" \
	    "  IdentityFile $WORK_DIR/id_ed25519" \
	    "  UserKnownHostsFile $WORK_DIR/known_hosts" \
	    "  GlobalKnownHostsFile none" \
	    "  GSSAPIAuthentication yes" \
	    "  PreferredAuthentications gssapi-with-mic" \
	    > "$WORK_DIR/ssh_config"
	printf '%s\n' \
	    "Host *" \
	    "  User $user" \
	    "  IdentityAgent none" \
	    "  IdentitiesOnly yes" \
	    "  IdentityFile $WORK_DIR/missing_identity" \
	    "  UserKnownHostsFile $WORK_DIR/known_hosts" \
	    "  GlobalKnownHostsFile none" \
	    "  GSSAPIAuthentication yes" \
	    "  PreferredAuthentications gssapi-with-mic" \
	    > "$WORK_DIR/ssh_config_no_identity"
	printf '%s\n' \
	    "Host *" \
	    "  User $user" \
	    "  IdentityAgent none" \
	    "  IdentitiesOnly yes" \
	    "  IdentityFile $WORK_DIR/id_ed25519" \
	    "  UserKnownHostsFile $WORK_DIR/known_hosts_rejected" \
	    "  GlobalKnownHostsFile none" \
	    "  GSSAPIAuthentication yes" \
	    "  PreferredAuthentications gssapi-with-mic" \
	    > "$WORK_DIR/ssh_config_rejected_host"
	printf '%s\n' \
	    "Host *" \
	    "  User $user" \
	    "  IdentityAgent $WORK_DIR/agent.sock" \
	    "  IdentitiesOnly yes" \
	    "  IdentityFile $WORK_DIR/agent_identity" \
	    "  UserKnownHostsFile $WORK_DIR/known_hosts" \
	    "  GlobalKnownHostsFile none" \
	    "  GSSAPIAuthentication yes" \
	    "  PreferredAuthentications gssapi-with-mic" \
	    > "$WORK_DIR/ssh_config_agent"
	printf '%s\n' \
	    "Host sshkey-config-test" \
	    "  HostName $HOST" \
	    "  User $user" \
	    "  IdentityAgent none" \
	    "  IdentitiesOnly yes" \
	    "  UserKnownHostsFile $WORK_DIR/known_hosts" \
	    "  GlobalKnownHostsFile none" \
	    "  GSSAPIAuthentication yes" \
	    "  PreferredAuthentications gssapi-with-mic" \
	    "Match final host $HOST" \
	    "  IdentityFile $WORK_DIR/id_ed25519" \
	    > "$WORK_DIR/ssh_config_match"
	printf '%s\n' \
	    "GSSAPIAuthentication yes" \
	    "StrictModes no" \
	    > "$WORK_DIR/sshd_config"
	printf '%s\n' \
	    "GSSAPIAuthentication yes" \
	    "StrictModes no" \
	    "AllowUsers $user@192.0.2.0/24" \
	    > "$WORK_DIR/sshd_config_source"

	export SSHKEY_HOST_KEY="$WORK_DIR/host_ed25519"
	export SSHKEY_AUTHORIZED_KEYS="$WORK_DIR/authorized_keys"
	export SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config"
	export SSHKEY_SSHD_CONFIG="$WORK_DIR/sshd_config"
	export SSHKEY_TEST_EXPECTED_USER="$user"
	export SSHKEY_CTX_KEY=
	SSHKEY_CTX_KEY="$(
	    printf '00%.0s' {1..32}
	)"
	export SSHKEY_CTX_KEY
fi

if [ -z "$FIXTURE_REASON" ] && KNC_PATH=$(find_executable "$KNC"); then
	username_hex=$(printf '%s' "$user" | od -An -tx1 |
	    tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
	printf -v username_length '%08X' "${#user}"
	expected_export_name="0401000B06092B06010401868D1F01"
	expected_export_name+="$username_length$username_hex"
	expected_mech="2B06010401868D1F01"
	message="sshkey knc wrap smoke"
	LD_PRELOAD="$SO_PATH" "$KNC_PATH" -lf -M 1 -T 10 "$KNC_PORT" \
	    /bin/sh -c '
		printf "KNC_EXPORT_NAME=%s\nKNC_MECH=%s\n" \
		    "${KNC_EXPORT_NAME-}" "${KNC_MECH-}"
		exec /bin/cat
	    ' > /dev/null 2> "$WORK_DIR/knc-server.err" &
	server_pid=$!
	sleep 1
	if ! printf '%s\n' "$message" | LD_PRELOAD="$SO_PATH" \
	    "$KNC_PATH" "$SERVICE@127.0.0.1" "$KNC_PORT" \
	    > "$WORK_DIR/knc.reply" 2> "$WORK_DIR/knc-client.err"; then
		kill "$server_pid" >/dev/null 2>&1 || true
		wait "$server_pid" >/dev/null 2>&1 || true
		cat "$WORK_DIR/knc-client.err" >&2
		cat "$WORK_DIR/knc-server.err" >&2
		exit 1
	fi
	wait "$server_pid" || true
	{
		printf 'KNC_EXPORT_NAME=%s\n' "$expected_export_name"
		printf 'KNC_MECH=%s\n' "$expected_mech"
		printf '%s\n' "$message"
	} | cmp - "$WORK_DIR/knc.reply"
	pass_phase "knc authenticated wrap smoke"
else
	skip_phase "knc authenticated wrap smoke" \
	    "${FIXTURE_REASON:-missing executable KNC=$KNC}"
fi

HEIMDAL_REASON=$FIXTURE_REASON
if ! command -v "$CC" >/dev/null 2>&1; then
	HEIMDAL_REASON="missing compiler CC=$CC"
elif [ ! -f "$GSSAPI_INCLUDE_DIR/gssapi.h" ]; then
	HEIMDAL_REASON="missing $GSSAPI_INCLUDE_DIR/gssapi.h"
elif [ ! -f "$GSSAPI_LIB" ]; then
	HEIMDAL_REASON="missing GSSAPI_LIB=$GSSAPI_LIB"
fi

if [ -n "$HEIMDAL_REASON" ]; then
	skip_loader_phase "Heimdal loader smoke" "$HEIMDAL_REASON"
	skip_phase "direct GSS smoke" "$HEIMDAL_REASON"
	skip_agent_phase "real ssh-agent exchange" "$HEIMDAL_REASON"
else
	sed "s#../../sshkey.so#$SO_PATH#" "$CONFIG" > "$WORK_DIR/gss/mech"
	"$CC" -Wall -Wextra -I"$REPO_ROOT/include" \
	    -I"$GSSAPI_INCLUDE_DIR" -o "$WORK_DIR/bin/smoke" \
	    "$SCRIPT_DIR/smoke.c" "$GSSAPI_LIB" -ldl

	if command -v unshare >/dev/null 2>&1 && \
	    unshare -Ur -m sh -c '
		set -e
		mount --bind "$1/gss" /etc/gss
		i=0
		while [ "$i" -lt "$4" ]; do
			"$2" "$3"
			i=$((i + 1))
		done
	    ' sh "$WORK_DIR" "$WORK_DIR/bin/smoke" \
	        "$SERVICE@$HOST" "$COUNT"; then
		pass_phase "Heimdal loader smoke"
	else
		skip_loader_phase "Heimdal loader smoke" \
		    "private /etc/gss mount namespace unavailable"
	fi

	i=0
	while [ "$i" -lt "$COUNT" ]; do
		SSHKEY_TEST_SERVER_FIRST=1 LD_PRELOAD="$SO_PATH" \
		    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
		i=$((i + 1))
	done
	SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config_match" \
	    SSHKEY_TEST_PEER_BINDING_MISMATCH=1 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@sshkey-config-test"
	SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config_no_identity" \
	    SSHKEY_TEST_EXPECT_NO_USER_CRED=1 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
	SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config_rejected_host" \
	    SSHKEY_TEST_EXPECT_HOST_REJECT=1 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
	SSHKEY_AUTHORIZED_KEYS="$WORK_DIR/authorized_keys_rejected" \
	    SSHKEY_TEST_EXPECT_USER_REJECT=1 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
	SSHKEY_SSHD_CONFIG="$WORK_DIR/sshd_config_source" \
	    SSHKEY_TEST_PEER_ADDRESS=192.0.2.10 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
	SSHKEY_SSHD_CONFIG="$WORK_DIR/sshd_config_source" \
	    SSHKEY_TEST_PEER_ADDRESS=198.51.100.10 \
	    SSHKEY_TEST_EXPECT_USER_REJECT=1 LD_PRELOAD="$SO_PATH" \
	    "$WORK_DIR/bin/smoke" "$SERVICE@$HOST"
	pass_phase "direct GSS smoke"

	AGENT_REASON=$FIXTURE_REASON
	if ! command -v ssh-agent >/dev/null 2>&1; then
		AGENT_REASON="missing ssh-agent"
	elif ! command -v ssh-add >/dev/null 2>&1; then
		AGENT_REASON="missing ssh-add"
	fi
	if [ -n "$AGENT_REASON" ]; then
		skip_agent_phase "real ssh-agent exchange" "$AGENT_REASON"
	else
		ssh-agent -D -a "$WORK_DIR/agent.sock" \
		    > "$WORK_DIR/agent.out" 2> "$WORK_DIR/agent.err" &
		AGENT_PID=$!
		i=0
		while [ ! -S "$WORK_DIR/agent.sock" ] && [ "$i" -lt 50 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		if [ ! -S "$WORK_DIR/agent.sock" ] ||
		    ! SSH_AUTH_SOCK="$WORK_DIR/agent.sock" \
		    ssh-add "$WORK_DIR/id_agent" >/dev/null 2>&1; then
			skip_agent_phase "real ssh-agent exchange" \
			    "agent could not load the fixture key"
		else
			SSH_AUTH_SOCK="$WORK_DIR/agent.sock" \
			    SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config_agent" \
			    SSHKEY_AUTHORIZED_KEYS="$WORK_DIR/authorized_keys_agent" \
			    LD_PRELOAD="$SO_PATH" "$WORK_DIR/bin/smoke" \
			    "$SERVICE@$HOST"
			pass_phase "real ssh-agent exchange"
		fi
	fi
fi

MIT_REASON=$FIXTURE_REASON
if ! command -v "$CC" >/dev/null 2>&1; then
	MIT_REASON="missing compiler CC=$CC"
elif ! command -v pkg-config >/dev/null 2>&1; then
	MIT_REASON="missing pkg-config"
elif ! pkg-config --exists "$MIT_GSSAPI_PKG_CONFIG"; then
	MIT_REASON="missing pkg-config package $MIT_GSSAPI_PKG_CONFIG"
fi

if [ -n "$MIT_REASON" ]; then
	skip_loader_phase "MIT krb5 loader smoke" "$MIT_REASON"
else
	printf '%s %s %s\n' "$MECH_NAME" "$MECH_OID" "$SO_PATH" \
	    > "$WORK_DIR/gss/mit-mech"
	# shellcheck disable=SC2046
	"$CC" -Wall -Wextra -I"$REPO_ROOT/include" \
	    $(pkg-config --cflags "$MIT_GSSAPI_PKG_CONFIG") \
	    -o "$WORK_DIR/bin/mit-smoke" "$SCRIPT_DIR/smoke.c" \
	    $(pkg-config --libs "$MIT_GSSAPI_PKG_CONFIG") -ldl
	GSS_MECH_CONFIG="$WORK_DIR/gss/mit-mech" \
	    "$WORK_DIR/bin/mit-smoke" "$SERVICE@$HOST"
	pass_phase "MIT krb5 loader smoke"
fi

if [ -z "$FIXTURE_REASON" ] && GSS_TOKEN_PATH=$(find_gss_token)
then
	python3 "$SCRIPT_DIR/gss-token-driver.py" "$SO_PATH" "$GSS_TOKEN_PATH"
	pass_phase "gss-token exchange"
else
	skip_phase "gss-token exchange" \
	    "${FIXTURE_REASON:-missing executable GSS_TOKEN=$GSS_TOKEN}"
fi

if [ "$SKIPPED" -eq 1 ]; then
	echo "GSS smoke completed with skips ($PHASES_RUN phase(s) ran)"
else
	echo "GSS smoke completed ($PHASES_RUN phase(s) ran)"
fi
