# GSS smoke tests

`run.sh` exercises `sshkey.so` through installed GSS-API libraries without
changing the host's permanent mechanism registry.

The runner creates a temporary Ed25519 key with `ssh-keygen` and uses it as:

- the initiator's unencrypted `IdentityFile`;
- the acceptor's host key;
- the entry in a temporary `known_hosts` file; and
- the entry in a temporary `authorized_keys` file.

This gives every context exchange real host authentication and user-key
authorization.  It does not use anonymous fallback or an SSH transport.

Separate keys exercise a real `ssh-agent`, rejected host trust, rejected user
authorization, and numeric source-address policy.  A client fixture resolves
an alias through `Host` and obtains its identity from `Match final`.  The C
driver checks peer channel-binding mismatch, `gss_userok()`, MIC, sealed and
signed wrap, and IOV wrap through the public GSS ABI.  Deterministic DNSSEC
SSHFP proof classification is covered by the Rust suite.

Available phases are:

- an external `knc` authenticated wrap/unwrap exchange which verifies the
  exported source name against the requested username;
- a Heimdal loader exchange using a private `/etc/gss` mount namespace;
- a direct `LD_PRELOAD` exchange, including acceptor-first establishment;
- an MIT krb5 loader exchange;
- an external `gss-token` exchange.

Missing optional local tools are reported as skips.  The direct exchange runs
whenever a C compiler, Heimdal headers and library, and `ssh-keygen` are
available.  The runner finds `gss-token` on `PATH` or in a sibling Heimdal
build at `../heimdal/lib/gssapi/gss-token`.

Set `REQUIRE_GSS_LOADERS=1` to make a missing or unrunnable Heimdal or MIT
loader phase fatal.  Set `REQUIRE_SSH_AGENT=1` to require the real-agent
phase.  `make test-alpha` enables both settings.

Run the suite after building:

```sh
make test-gss-token
```

Useful overrides include `CC`, `GSSAPI_INCLUDE_DIR`, `GSSAPI_LIB`,
`MIT_GSSAPI_PKG_CONFIG`, `GSS_TOKEN`, `KNC`, `KNC_PORT`, `HOST`, and `COUNT`.
