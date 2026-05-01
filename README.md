# gss-sshkey

`gss-sshkey` is a GSS-API mechanism for authenticating with SSH keys.  The
goal is to make SSH identity useful outside SSH without asking users to learn a
new credential system.

The intended user experience is:

1. A user already has an SSH key, often loaded in `ssh-agent`.
2. A server already authorizes that user with normal `authorized_keys` data.
3. A GSS-enabled application can authenticate with that SSH key.

For example, if an IMAP server runs on a host where `alice` has her SSH public
key in `~alice/.ssh/authorized_keys`, then Alice should be able to use a
GSS-capable IMAP client such as `mutt` without typing an IMAP password.  The
mechanism should reuse the SSH deployment that already exists: OpenSSH key
files, `ssh-agent`, SSH signature formats, SSH host-key trust data, and
`authorized_keys` authorization.

## Status

This repository is currently a Rust conversion and protocol prototype.  It
builds a standalone shared object, `sshkey.so`, that Heimdal can load as a GSS
mechanism.  The shared object is intended to remain independent of Heimdal
internals so it can later be loaded by MIT krb5 as well.

Implemented so far:

- Rust `cdylib` build producing `sshkey.so`.
- ASN.1 generation from `sshkey.asn1` through `rasn-compiler` and `rasn`.
- Anonymous X25519 context establishment.
- A SAnon-X25519-compatible SP800-108 HMAC-SHA256 KDF.
- SSH signature blob encode, decode, sign, and verify helpers.
- Acceptor host-key signatures from OpenSSH private keys.
- Initiator user-key signatures through `ssh-agent`.
- Client host-key trust through OpenSSH `known_hosts` files and
  DNSSEC-validated SSHFP records.
- Encrypted stateless acceptor context returned through `sctx`.
- Client-first and acceptor-first context establishment.
- RFC 4121-style per-message wrapping with `gss_wrap`,
  `gss_unwrap`, `gss_wrap_iov`, and `gss_unwrap_iov`.
- Smoke tests using `/usr/local/bin/gss-token`.

Not complete yet:

- `authorized_keys` lookup and authorization.
- Finished MAC key confirmation from the current draft.
- Production OID assignment and packaged installation.

Without a configured user key, the mechanism still completes anonymously and
has the same man-in-the-middle limitation as an anonymous ECDH mechanism.

## Build

Install Rust through `rustup`, then build from the repository root:

```sh
make
```

The build uses Cargo and writes its Rust toolchain state under the repository
by default:

```make
RUSTUP_HOME ?= $(CURDIR)/.rustup
CARGO_HOME ?= $(CURDIR)/.cargo
```

The output file is:

```text
sshkey.so
```

## Test

Run the Rust unit tests and the GSS smoke tests:

```sh
make test
```

The GSS test runner creates a private `/etc/gss/mech` mount namespace and uses
`/usr/local/bin/gss-token` by default.  Override paths with environment
variables when needed:

```sh
GSS_TOKEN=/path/to/gss-token make test
GSSAPI_LIB=/path/to/libgssapi.so make test
```

## Configuration

For local testing, the mechanism stanza is in
`tests/gss-token/gss-mech.conf`:

```text
sshkey 1.3.6.1.4.1.99999.1 ../../sshkey.so -
```

The OID is a placeholder.  A real deployment needs an assigned OID and an
installation path appropriate for the host GSS implementation.

Prototype signing configuration is environment-variable based.  The initiator
uses `SSH_AUTH_SOCK` and asks `ssh-agent` to sign, because a GSS mechanism
generally cannot interactively ask the user for SSH key passphrases.

- `SSHKEY_HOST_KEY`: OpenSSH private key used by the acceptor to sign its ECDH
  reply.
- `SSHKEY_KNOWN_HOSTS`: optional colon-separated list of known-hosts files for
  initiator host-key trust.  Defaults to the user's OpenSSH files and
  `/etc/ssh/ssh_known_hosts`.
- `SSHKEY_HOST`: optional host-name override for tests.  Normal operation uses
  the host component of the GSS target name.
- `SSHKEY_USER`: authorization name signed by the initiator.  Defaults to
  `USER`, then `sshkey`.
- `SSHKEY_CTX_KEY`: 32-byte hex key used to encrypt acceptor continuation
  state for stateless or load-balanced servers.

If `SSHKEY_CTX_KEY` is not set, the process creates a random local key.  That
works for one acceptor process but cannot support a different server process
finishing the authentication.

## Protocol

The protocol is documented in `sshkey.asn1` and in
`draft-dowdeswell-kitten-gss-sshkey-00.xml`.

The anonymous ECDH base intentionally follows Heimdal SAnon-X25519's key
derivation so the Rust implementation can be tested against known behavior
while remaining standalone.  The intended signed flow has two conceptual
pieces:

- peers sign their ECDH contribution and associated algorithm, name, and
  channel-binding context with SSH keys;
- after ECDH, peers demonstrate knowledge of the derived session key with a
  Finished MAC.

User authentication remains an encrypted ASN.1 payload.  It may appear in any
token sent after the sender has enough ECDH material to derive the session key.
In initiator-first protocols this keeps the username and user public key out of
the first cleartext token without adding a round trip.

The mechanism also supports acceptor-first operation.  If a protocol calls
`gss_accept_sec_context()` before any initiator token exists, the acceptor sends
a signed ECDH challenge and encrypted `sctx`; the initiator returns its ECDH
public key, encrypted userauth, key confirmation, and the same `sctx`.
HTTP Negotiate can use this mode naturally: the server can include an
acceptor-first token in a `401 WWW-Authenticate` header, and the client can
return its response token in the `Authorization` header.

The next step is policy: verifying the host key through normal SSH trust data
including `known_hosts` and DNSSEC-validated SSHFP records, and checking the
user key against the target user's `authorized_keys`.
