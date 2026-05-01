# Architecture

The protocol specification lives in
`draft-dowdeswell-kitten-gss-sshkey-00.xml`, with message syntax mirrored in
`sshkey.asn1`.  This file is intentionally not a second protocol
specification.  It records implementation choices, temporary limitations, and
places where the code has not yet caught up with the intended mechanism.

Any change that affects token syntax, transcript inputs, negotiation, key
derivation, context-state semantics, or GSS-visible behavior must update the
Internet-Draft and `sshkey.asn1` in the same change.

## Implementation Choices

The mechanism builds as a Rust `cdylib` named `sshkey.so`.  It exports the GSS
entrypoints directly and uses only public C ABI types at the mechanism boundary.
Heimdal is a loader and test environment, not an internal dependency.  The same
shared object should eventually be loadable by MIT krb5.

ASN.1 Rust bindings are generated from `sshkey.asn1` with `rasn-compiler`.
Generated ASN.1 files are build artifacts and must not be committed.

The current crypto implementation is mixed:

- OpenSSL FFI is still used for X25519, HMAC-SHA256, and AES-256-GCM.
- The `ssh-key` and `signature` crates are used for SSH public key and
  signature blob handling.

This is a staging point, not a final crypto abstraction.  Prefer moving toward
idiomatic Rust crypto crates where that does not reduce interoperability with
existing SSH key material.

`gss_wrap()` and `gss_unwrap()` are implemented through the IOV code path so
normal buffers and IOV buffers share per-message protection behavior.

## Local Configuration

Prototype credential and state configuration is environment-variable based:

- `SSHKEY_HOST_KEY`: OpenSSH private key used for acceptor host signatures.
- `SSHKEY_USER`: requested authorization identity.
- `SSHKEY_CTX_KEY`: 32-byte hex key for encrypted acceptor continuation state.
- `SSH_AUTH_SOCK`: OpenSSH agent socket used for initiator user signatures.

If `SSHKEY_CTX_KEY` is absent, the process creates a random local key.  That is
fine for a single process smoke test, but it means another acceptor process
cannot finish the same authentication.

## Current Deviations

Host signatures and user signatures are cryptographically verified, but policy
is not complete:

- host key trust is not checked against `known_hosts` or SSHFP;
- user keys are not checked against `authorized_keys`;
- the draft's Finished MAC key confirmation is not implemented;
- user signature retry negotiation is only partially wired.

Without configured and authorized user credentials, the mechanism can still
complete anonymously.  That remains useful for loader, KDF, and per-message
testing, but it is not complete SSH-key authentication.

Heimdal's generic mechglue in the current test environment does not dispatch an
absent initial token to a dynamically loaded mechanism.  The client-first path
is tested through Heimdal loading.  The acceptor-first path is tested by direct
`.so` interposition until loader behavior is addressed.

## Source Map

- `src/lib.rs`: mechanism implementation.
- `sshkey.asn1`: ASN.1 schema and inline protocol notes.
- `draft-dowdeswell-kitten-gss-sshkey-00.xml`: normative protocol draft.
- `build.rs`: ASN.1 generation through `rasn-compiler`.
- `tests/gss-token/`: Heimdal loader, direct interposition, and `gss-token`
  smoke tests.
- `Makefile`: Cargo build wrapper and test entrypoint.
