# gss-sshkey

`gss-sshkey` is a GSS-API mechanism that authenticates users with ordinary SSH
public keys.  It lets a GSS-enabled service reuse common SSH identity,
host-trust, and `authorized_keys` policy without implementing or tunnelling
the SSH protocol.

The mechanism answers a focused login question:

> May this authenticated SSH key log in as this local account from this
> source?

It does not implement SSH transport packets, SSH userauth messages, shells,
commands, forwarding, TTY handling, or post-login session restrictions.

## Current Milestone

The `0.1` goal is the common SSH public-key authentication case:

- Ed25519 and ECDSA user keys from `ssh-agent` or an unencrypted
  `IdentityFile`;
- RSA-SHA2 user keys through `ssh-agent`;
- non-interactive host-key verification through a caller-verified host key,
  `known_hosts`, or DNSSEC-validated SSHFP records;
- a requested username from typed caller context, resolved `User`, or the
  invoking local username;
- plain `authorized_keys` authorization, with unexpired `expiry-time` entries;
- common client and server `Host`, `Match`, and `Include` configuration; and
- GSS integrity, confidentiality, replay, and sequencing services after
  establishment.

The exact requirements and non-goals are in `REQUIREMENTS.md`.  In particular,
the mechanism does not prompt.  Missing identity material, an unverified host
key, or unresolved security-critical configuration makes authentication fail.
The mechanism stands on its own through the standard GSS-API; native OpenSSH
integration is optional and does not gate a release.

The current release is `0.1.0-alpha.1`, distributed as source plus separate
Heimdal and MIT krb5 binary archives.  It is not published on crates.io.  See
`RELEASE-NOTES.md` for the alpha's security limitations.

## Repository Layout

- `src/lib.rs` implements the mechanism-specific ASN.1 exchange and focused
  SSH credential and authorization adapters.
- `src/host_trust.rs` combines caller-verified keys, `known_hosts`, and SSHFP
  host trust.
- `src/sshfp.rs` performs DNSSEC validation and SSHFP fingerprint matching
  through Hickory.
- `sshkey.asn1` is the message schema and concise protocol description.
- `draft-dowdeswell-kitten-gss-sshkey-00.xml` is the protocol specification.
- `include/gss_sshkey.h` defines the optional typed integration boundary.
- `../ssh-config` parses and resolves client and server configuration and
  parses `authorized_keys` entries.
- `../gss-mech-builder` owns generic GSS ABI and loader integration.
- `../rfc4121` provides message protection only through
  `gss-mech-builder`.

`ARCHITECTURE.md` records these ownership boundaries.  `TODO.md` contains only
release-blocking work; deferred compatibility work is in `BACKLOG.md`.

## Build

An existing Rust toolchain with Cargo is required.  The adjacent
`ssh-config`, `gss-mech-builder`, and `rfc4121` repositories must be present at
the paths shown above.

Build the shared object:

```sh
make
```

The result is `sshkey.so`.  Cargo generates Rust bindings from `sshkey.asn1`
in its build directory; generated ASN.1 files are not committed.

## Test

Run the focused Rust, header, install, package, and GSS smoke tests:

```sh
make test
```

The Rust tests run Cargo in offline mode and also test the adjacent
`rfc4121`, `gss-mech-builder`, and `ssh-config` crates.  The GSS smoke runner
creates temporary Ed25519 identity, host-key, `known_hosts`, and
`authorized_keys` fixtures.  It covers a real `ssh-agent`, client
configuration selection, authentication rejection, source policy, channel
bindings, local-name authorization, MIC, and wrap.  Optional Heimdal, MIT
krb5, `gss-token`, and `knc` phases report a skip when their local
prerequisites are unavailable.

Mechanism-level Rust conformance tests use the black-box harness from
`gss-mech-builder`. The `gss-sshkey` fixture supplies keys, configuration,
credentials, exchange flags, and acceptor-result validation only. The harness
owns the conventional public GSS bindings and generic establishment,
authorization, message-protection, extension, and failure tests. RFC 4121
token and cryptographic behavior is tested in `rfc4121`; builder ABI adaptation
is tested in `gss-mech-builder`.

Before publishing an alpha, run the strict acceptance target:

```sh
make test-alpha
```

This requires the real-agent, Heimdal loader, and MIT loader phases.  A
missing prerequisite or unavailable loader namespace is an error, not a
skip.

Run individual groups with:

```sh
make test-rust
make test-context-helper
make test-gss-token
make test-install
make test-package
make test-source-package
```

The opt-in OpenSSH test performs a real `gssapi-with-mic` login with native
public-key authentication disabled.  It requires an OpenSSH server built with
the focused integration patch documented in `tests/openssh-live/README.md`:

```sh
make test-openssh-live SSHD_BIN=/path/to/integrated/sshd
```

This is optional application-integration evidence, not part of the release
acceptance suite.

## Install

The default install uses Heimdal's four-field mechanism configuration:

```sh
sudo make install
```

For MIT krb5:

```sh
sudo make install GSS_MECH_CONFIG_FORMAT=mit
```

Important path variables are `PREFIX`, `LIBDIR`, `INCLUDEDIR`, `SYSCONFDIR`,
`GSS_MECH_DIR`, and `GSS_MECH_LIBDIR`.  `DESTDIR` supports staged packaging.

The current OID, `1.3.6.1.4.1.99999.1`, is private and experimental.  It must
be replaced by an assigned mechanism OID before interoperable deployment.

## Package

Build and test all release archives with:

```sh
make release-alpha
```

This reruns `make test-alpha` and writes three versioned archives under
`dist/`:

- `gss-sshkey-0.1.0-alpha.1-source.tar.gz` contains `gss-sshkey` and the
  exact sibling `gss-mech-builder`, `rfc4121`, and `ssh-config` sources needed
  by its path dependencies;
- `gss-sshkey-0.1.0-alpha.1-heimdal.tar.gz` contains an installed shared
  object, public header, Heimdal mechanism configuration, licence, and release
  notes; and
- `gss-sshkey-0.1.0-alpha.1-mit.tar.gz` contains the corresponding MIT krb5
  mechanism configuration.

The source archive has a top-level `SOURCE-MANIFEST.txt`.  Package tests
recompute that manifest, reject VCS/build/cache material, resolve all path
dependencies from the extracted tree, and compare the complete binary archive
file list.

## Use

A GSS initiator imports a host-based service name such as
`imap@mail.example.com` and requests the GSS-SSHKEY mechanism OID.  The host
component selects client configuration and host-key policy.  The acceptor
loads a host private key, verifies the user proof, and authorizes the key for
the requested local account.  A completed context reports that requested
username as its authenticated GSS source name.

Direct RSA private-key signing is disabled because the current Rust RSA
backend is not suitable for this use.  RSA-SHA2 user keys remain available
through `ssh-agent`, and RSA public signatures remain verifiable.  Acceptor
host keys and direct `IdentityFile` signing must use Ed25519 or ECDSA.

An embedding client or server can stage facts already established by its
transport through `include/gss_sshkey.h`:

- client `user`: the requested remote account;
- client `host-key`: the verified raw SSH public-key blob; and
- server `peer-address`: the numeric source address used by authorization
  policy.

Fields are one-shot and thread-local.  The next applicable context creation
consumes them.  Supplying a verified host key avoids rereading `known_hosts`,
but only an exact key match is accepted.

The acceptor never uses a DNS client hostname for authorization.  It does not
perform reverse DNS, accept a client-asserted hostname, or reinterpret a
numeric peer address as a hostname.  Hostname-dependent server policy fails
closed.  Address-dependent policy is evaluated only when the embedding
transport supplies its locally observed numeric `peer-address`; otherwise it
also fails closed when it could affect authorization.

Example client setup:

```c
gss_sshkey_context_field fields[] = {
    gss_sshkey_context_string(GSS_SSHKEY_FIELD_USER, "alice"),
    gss_sshkey_context_bytes(GSS_SSHKEY_FIELD_HOST_KEY,
        host_key_blob, host_key_blob_len),
};

major = gss_sshkey_set_client_context(&minor, fields,
    GSS_SSHKEY_ARRAY_LEN(fields));
```

The remote username is not supplied through `gss_acquire_cred()`.  Credential
acquisition identifies the SSH credential principal; it does not select an
account on a remote host.  Version `0.1` supports default credential
acquisition for initiators and returns `GSS_S_UNAVAILABLE` for a non-null
initiator desired name.  Named acceptor credentials remain supported.
The mechanism binds the canonical host-based acceptor name into host and user
signatures and key confirmation.  Acceptor-first establishment therefore
requires a named acceptor credential; ordinary initiator-first SSH operation
may use the default acceptor credential because the initiator supplies the
name before the host signature is made.

## Configuration

By default, the initiator reads `~/.ssh/config` and
`/etc/ssh/ssh_config`.  It resolves the destination and relevant authentication
settings through the adjacent `ssh-config` crate.  Supported common settings
include:

```text
Host
Match
Include
HostName
User
Port
IdentityAgent
IdentityFile
IdentitiesOnly
PubkeyAcceptedAlgorithms
HostKeyAlias
UserKnownHostsFile
GlobalKnownHostsFile
VerifyHostKeyDNS
GSSAPIAuthentication
PreferredAuthentications
```

`VerifyHostKeyDNS yes` permits a DNSSEC-validated matching SSHFP record to
authenticate a host that is not present in `known_hosts`.  Insecure,
indeterminate, bogus, missing, or mismatching DNS data never establishes
trust.  `ask` cannot authorize a key because the mechanism has no interactive
prompt channel.  `HostKeyAlias` selects the `known_hosts` lookup name; SSHFP
uses the resolved `HostName`.

User keys are attempted in OpenSSH order: configured identities available
through the agent, other agent identities unless `IdentitiesOnly` is set, and
then remaining configured private-key files.  Signature algorithms for each
key follow `PubkeyAcceptedAlgorithms`.  If a valid signature is not authorized,
the acceptor returns a session-authenticated retry and the initiator advances
to the next key or algorithm.  It never advances on an unauthenticated retry.

The acceptor reads `/etc/ssh/sshd_config` and uses common login policy from:

```text
Match User
Match Address
Match Group
AuthorizedKeysFile
AllowUsers
DenyUsers
AllowGroups
DenyGroups
PermitRootLogin
RevokedKeys
PubkeyAcceptedAlgorithms
RequiredRSASize
StrictModes
GSSAPIAuthentication
```

Valid unrelated directives do not invalidate either configuration.  A
malformed supported directive or an unsupported condition that could change
the selected host, user, identity, trust, or authorization result fails the
affected authentication attempt.

The acceptor supports plain `authorized_keys` entries and entries containing
only an unexpired `expiry-time`.  Any other key option makes that entry
unavailable to this mechanism.  In particular, `from=` address restrictions,
certificate-authority entries, forced commands, and SSH session restrictions
are not silently discarded.

The following environment variables remain compatibility and test adapters:

- `SSHKEY_SSH_CONFIG`: colon-separated client configuration paths;
- `SSHKEY_SSHD_CONFIG`: server configuration path;
- `SSHKEY_HOST_KEY`: acceptor OpenSSH private-key path;
- `SSHKEY_AUTHORIZED_KEYS`: colon-separated authorization file paths;
- `SSHKEY_KNOWN_HOSTS`: colon-separated host-trust file paths;
- `SSHKEY_USER`: requested username when typed context is unavailable;
- `SSHKEY_HOST`: target-host override;
- `SSHKEY_CTX_KEY`: 32-byte hexadecimal continuation-state key.

Normal embedding should prefer typed context for facts already known by the
caller.  Environment variables are process-wide and therefore unsuitable for
mixing independent transport contexts in one process.  A server peer address
is connection-specific and is accepted only through typed context.

If `SSHKEY_CTX_KEY` is absent, the process generates a local random key.  A
shared key is required when different acceptor processes may begin and finish
the same exchange.  Invalid configured key material or unavailable operating
system randomness fails closed.

Sealed acceptor continuation state carries an authenticated issuance time and
is bound to its canonical acceptor name.  The server applies its local age
policy; version `0.1` accepts it for less than 120 seconds.  Without carrier
replay mitigation, a captured completed exchange remains a bearer token during
that window.  This is an explicit limitation: the mechanism does not require a
replay cache or channel bindings that many reverse-proxied deployments cannot
provide.  OpenSSH additionally binds GSS authentication to its fresh transport
session through `gssapi-with-mic`.

## Protocol

The ASN.1 exchange performs ephemeral key agreement, proves possession of the
acceptor host key and initiator user key, encrypts the username and user proof,
confirms the derived key, and establishes RFC 4121-style message protection.
When supplied, the complete GSS channel-binding structure is included in key
derivation and every authentication transcript.

SSH public-key and signature encodings are reused as credential formats.  The
signed data is the GSS-SSHKEY transcript defined by `sshkey.asn1`, not an
`SSH_MSG_USERAUTH_REQUEST`.

Protocol-visible changes must update both `sshkey.asn1` and the
Internet-Draft.

## License

`gss-sshkey` is distributed under the BSD 2-Clause License.  See `COPYING`.
