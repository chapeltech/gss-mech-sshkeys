# TODO

The Internet-Draft and `sshkey.asn1` are the protocol source of truth until
publication.  Any protocol-affecting implementation change must update both.

## Completed

- Add SSH agent signing.  Client-side user authentication uses
  `SSH_AUTH_SOCK` and does not read SSH private key files or prompt for
  passphrases.
- Add host key trust policy.  Initiator hostauth verification now checks
  OpenSSH `known_hosts` files, including hashed hostnames and revoked entries,
  and DNSSEC-validated SSHFP records.
- Add Finished MAC key confirmation.  Context establishment now carries
  nonces and role-separated MACs proving knowledge of the ECDH-derived
  session key.
- Start the RFC 4121 crate split.  The `rfc4121` crate now owns token
  framing, role checks, sequence handling, EC/RRC handling, and signed/sealed
  wrap token layout behind a protocol-neutral `CryptoProfile`.
- Start the GSS mechanism builder crate.  The `gss-mech-builder` crate now
  provides GSS ABI types and constants, buffer and IOV helpers, RFC4121 context
  plumbing, and a macro to export the RFC4121 per-message entrypoints for a
  mechanism context type.
- Integrate `gss-mech-builder` for per-message services.  The ssh-key
  mechanism now implements the builder's RFC4121 context trait and delegates
  `gss_wrap()`, `gss_unwrap()`, and IOV entrypoints to the builder.
- Finish the first reusable `rfc4121` crate slice.  The crate now owns wrap
  and MIC token framing, split-token size planning, and the
  `aes256-gcm-sha256` profile used by this mechanism.
- Add the signed-ECDH builder API scaffold.  The builder now has canonical
  auth and Finished transcripts, signer/verifier traits, ECDH hooks, and
  continuation-state and key-confirmation traits for higher-level mechanisms.

## Next Steps

1. Finish and integrate `gss-mech-builder`.

   Build it as layered API surfaces:

   - Low-level GSS ABI layer: constants, C-compatible types, OID/name/buffer
     helpers, IOV helpers, status mapping, context/credential ownership, and
     optional mechanism registration metadata.  This layer must not own
     mechanism crypto or token policy.
   - RFC4121 per-message layer: the mechanism implements
     `gss_init_sec_context()` and `gss_accept_sec_context()`, derives or
     receives a session key, implements a `CryptoProfile`, and lets the builder
     export `gss_wrap()`, `gss_unwrap()`, IOV entrypoints, and eventually MIC.
   - Signed-ECDH mechanism layer: the builder owns ephemeral ECDH generation,
     canonical signed transcripts, client-first and acceptor-first tokens,
     encrypted acceptor continuation state, Finished MAC key confirmation, and
     handoff to the RFC4121 backend.  The mechanism author supplies identity,
     signing, verification, host trust, and initiator authorization callbacks.

   Add the remaining common exports, then move this mechanism's current
   signed-ECDH handshake onto the new builder module without hiding the lower
   layers from simpler mechanisms.

2. Add `authorized_keys` authorization.

   The acceptor currently verifies that the user signature matches the supplied
   public key, but it does not check whether that key is authorized for the
   requested user.  Start with local `authorized_keys` compatibility.

3. Finish user signature retry negotiation.

   The acceptor can return a narrower signature algorithm list, but the
   initiator does not yet retry with a different acceptable signature algorithm.
   This matters most for old RSA keys and legacy `ssh-rsa`.

4. Replace remaining OpenSSL FFI where practical.

   X25519, HMAC-SHA256, and AES-256-GCM still use direct OpenSSL FFI.  Evaluate
   RustCrypto crates or idiomatic bindings while preserving interoperability
   and avoiding private Heimdal APIs.

5. Harden encrypted context state.

   `sctx` is encrypted and integrity protected, but it needs freshness and
   replay controls such as expiration, single-use identifiers, or cache-backed
   replay detection.

6. Settle mechanism identity and packaging.

   Replace the private placeholder OID before real deployment, document
   installation for Heimdal and MIT krb5, and add packaging/install targets.

7. Add interoperability tests.

   Keep the current Heimdal loader and `/usr/local/bin/gss-token` tests, then
   add tests for agent-backed user keys, host-key policy, HTTP-style
   acceptor-first exchanges, and eventually MIT krb5 loading.
