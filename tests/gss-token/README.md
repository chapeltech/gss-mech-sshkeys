# GSS loader smoke test

This directory provides a local GSS mechanism config and a runner for
testing that Heimdal can load `sshkey.so` without changing the real
`/etc/gss/mech`.

The runner uses an unprivileged user and mount namespace to bind a temporary
`/etc/gss` directory over the system one for the duration of the test. The
smoke binary then calls `gss_init_sec_context()` with the `sshkey` OID,
passes the resulting token to `gss_accept_sec_context()`, and completes the
initiator side with the acceptor token.

The runner also drives `/usr/local/bin/gss-token` through the same
initiator/acceptor token exchange.  This uses `LD_PRELOAD` for that binary
because this Heimdal build's `gss-token -m` path cannot map dynamically
configured mechanism names with `gss_name_to_oid()`.

The runner also starts `/usr/local/bin/knc` as a local listener running
`/bin/cat`, connects with a `knc` client, and checks that one line is echoed
through the GSS-protected stream.  That covers `gss_wrap()` and
`gss_unwrap()` through an external program.

## Quick start
1. Install a Rust toolchain with `cargo`.
2. Build the library: `make`
3. Run: `make test-gss-token`

## Notes
- `gss-mech.conf` uses the Heimdal `/etc/gss/mech` format. The runner
  rewrites the `../../sshkey.so` path to an absolute path in its temporary
  config.
- `gss-token -m ?` is not used here because this Heimdal build's
  `gss_oid_to_name()` returns `NULL` for dynamically configured mechanism
  OIDs, and `gss-token` does not handle that.
- Override the `gss-token` path with `GSS_TOKEN=/path/to/gss-token`.
- Override the `knc` path with `KNC=/path/to/knc`.
- Override the local `knc` listener port with `KNC_PORT=45679`.
- For repeated loader testing, set `COUNT` (default is 1), e.g.:
  `COUNT=25 ./run.sh`
