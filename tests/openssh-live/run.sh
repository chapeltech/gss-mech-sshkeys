#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
SO_PATH="$REPO_ROOT/sshkey.so"
SSH_BIN="${SSH_BIN:-ssh}"
SSHD_BIN="${SSHD_BIN:-sshd}"
PORT="${OPENSSH_TEST_PORT:-45680}"
WORK_DIR=
SSHD_PID=

cleanup() {
	if [ -n "$SSHD_PID" ]; then
		kill "$SSHD_PID" >/dev/null 2>&1 || true
		wait "$SSHD_PID" >/dev/null 2>&1 || true
	fi
	if [ -n "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT

find_executable() {
	local candidate=$1

	if [ -x "$candidate" ]; then
		printf '%s\n' "$candidate"
		return 0
	fi
	command -v "$candidate" 2>/dev/null
}

if [ ! -f "$SO_PATH" ]; then
	echo "Missing $SO_PATH. Run 'make' first." >&2
	exit 1
fi
if ! SSH_PATH=$(find_executable "$SSH_BIN"); then
	echo "Missing executable SSH_BIN=$SSH_BIN." >&2
	exit 1
fi
if ! SSHD_PATH=$(find_executable "$SSHD_BIN"); then
	echo "Missing executable SSHD_BIN=$SSHD_BIN." >&2
	exit 1
fi
if ! command -v ssh-keygen >/dev/null 2>&1; then
	echo "Missing ssh-keygen." >&2
	exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sshkey-openssh.XXXXXX")
ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/id_ed25519"
ssh-keygen -q -t ed25519 -N "" -f "$WORK_DIR/host_ed25519"
read -r user_key_type user_key_data _ < "$WORK_DIR/id_ed25519.pub"
read -r host_key_type host_key_data _ < "$WORK_DIR/host_ed25519.pub"
user=$(id -un)

printf '%s %s gss-sshkey OpenSSH test\n' \
	"$user_key_type" "$user_key_data" > "$WORK_DIR/authorized_keys"
printf '[127.0.0.1]:%s %s %s\n' "$PORT" \
	"$host_key_type" "$host_key_data" > "$WORK_DIR/known_hosts"
printf '%s\n' \
	"Host sshkey-test 127.0.0.1" \
	"  HostName 127.0.0.1" \
	"  Port $PORT" \
	"  User $user" \
	"  IdentityAgent none" \
	"  IdentitiesOnly yes" \
	"  IdentityFile $WORK_DIR/id_ed25519" \
	"  UserKnownHostsFile $WORK_DIR/known_hosts" \
	"  GlobalKnownHostsFile none" \
	"  StrictHostKeyChecking yes" \
	"  PubkeyAuthentication no" \
	"  GSSAPIAuthentication yes" \
	"  GSSAPIDelegateCredentials no" \
	"  PreferredAuthentications gssapi-with-mic" \
	"  BatchMode yes" > "$WORK_DIR/ssh_config"
printf '%s\n' \
	"Port $PORT" \
	"ListenAddress 127.0.0.1" \
	"HostKey $WORK_DIR/host_ed25519" \
	"PidFile $WORK_DIR/sshd.pid" \
	"AuthorizedKeysFile $WORK_DIR/authorized_keys" \
	"StrictModes no" \
	"UsePAM no" \
	"PasswordAuthentication no" \
	"KbdInteractiveAuthentication no" \
	"PubkeyAuthentication no" \
	"GSSAPIAuthentication yes" \
	"GSSAPIStrictAcceptorCheck no" \
	"AuthenticationMethods gssapi-with-mic" \
	"AllowUsers $user" \
	"PermitRootLogin no" \
	"LogLevel VERBOSE" > "$WORK_DIR/sshd_config"

export SSHKEY_HOST_KEY="$WORK_DIR/host_ed25519"
export SSHKEY_AUTHORIZED_KEYS="$WORK_DIR/authorized_keys"
export SSHKEY_SSH_CONFIG="$WORK_DIR/ssh_config"
export SSHKEY_SSHD_CONFIG="$WORK_DIR/sshd_config"
SSHKEY_CTX_KEY=$(printf '00%.0s' {1..32})
export SSHKEY_CTX_KEY

LD_PRELOAD="$SO_PATH" "$SSHD_PATH" -D -e \
	-f "$WORK_DIR/sshd_config" > "$WORK_DIR/sshd.out" \
	2> "$WORK_DIR/sshd.err" &
SSHD_PID=$!
sleep 1
if ! kill -0 "$SSHD_PID" >/dev/null 2>&1; then
	cat "$WORK_DIR/sshd.err" >&2
	exit 1
fi

message="sshkey openssh authenticated command"
if ! LD_PRELOAD="$SO_PATH" "$SSH_PATH" -vv \
	-F "$WORK_DIR/ssh_config" sshkey-test \
	'printf "%s\n" "sshkey openssh authenticated command"' \
	> "$WORK_DIR/reply" 2> "$WORK_DIR/ssh.err"; then
	cat "$WORK_DIR/ssh.err" >&2
	cat "$WORK_DIR/sshd.err" >&2
	exit 1
fi

printf '%s\n' "$message" | cmp - "$WORK_DIR/reply"
grep -Fq 'using "gssapi-with-mic"' "$WORK_DIR/ssh.err"
grep -Fq "Accepted gssapi-with-mic for $user" "$WORK_DIR/sshd.err"
grep -Fq "ssh2: $user" "$WORK_DIR/sshd.err"
echo "OpenSSH GSSAPI-only login: ok"
