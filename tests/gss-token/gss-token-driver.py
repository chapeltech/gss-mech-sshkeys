#!/usr/bin/env python3

import os
import select
import subprocess
import sys


def read_nonempty_line(proc, label, timeout=None):
    while True:
        if timeout is not None:
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                return None
        line = proc.stdout.readline()
        if line == "":
            return None
        if line.strip():
            return line


def main():
    if len(sys.argv) != 3:
        print(
            "usage: gss-token-driver.py "
            "/path/to/sshkey.so /path/to/gss-token"
        )
        return 2

    so_path = sys.argv[1]
    gss_token = sys.argv[2]
    env = os.environ.copy()
    env["LD_PRELOAD"] = so_path

    client = subprocess.Popen(
        [gss_token, "-N", "sshkey@localhost"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    server = subprocess.Popen(
        [gss_token, "-N", "-r", "sshkey@localhost"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        client_token = read_nonempty_line(client, "client", timeout=5)
        if client_token is None:
            raise RuntimeError("client did not produce an initial token")
        if not client_token.startswith("Negotiate "):
            raise RuntimeError("client token missing Negotiate prefix")
        client_tokens = 0
        server_tokens = 0
        client_extra = []
        server_extra = []

        while client_token is not None:
            client_tokens += 1
            server.stdin.write(client_token + "\n")
            server.stdin.flush()

            server_token = read_nonempty_line(server, "server", timeout=5)
            if server_token is None:
                break
            if not server_token.startswith("Negotiate "):
                server_extra.append(server_token)
                break
            server_tokens += 1
            client.stdin.write(server_token + "\n")
            client.stdin.flush()

            client_token = read_nonempty_line(client, "client", timeout=5)
            if client_token is not None and not client_token.startswith(
                "Negotiate "
            ):
                client_extra.append(client_token)
                client_token = None

        client.stdin.close()
        server.stdin.close()

        client_tail = client.stdout.read()
        server_tail = server.stdout.read()
        client_stderr = client.stderr.read()
        server_stderr = server.stderr.read()
        client_rc = client.wait(timeout=5)
        server_rc = server.wait(timeout=5)
    except Exception:
        client.kill()
        server.kill()
        raise

    print(f"gss-token client tokens={client_tokens}")
    print(f"gss-token server tokens={server_tokens}")
    for line in client_extra:
        print(line, end="")
    for line in server_extra:
        print(line, end="")
    if client_tail:
        print(client_tail, end="")
    if server_tail:
        print(server_tail, end="")
    if client_stderr:
        print(client_stderr, end="", file=sys.stderr)
    if server_stderr:
        print(server_stderr, end="", file=sys.stderr)

    if client_rc != 0 or server_rc != 0:
        print(f"gss-token client exit={client_rc}", file=sys.stderr)
        print(f"gss-token server exit={server_rc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
