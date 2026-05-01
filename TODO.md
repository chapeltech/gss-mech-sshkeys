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

## Next Steps

1. Finish the `rfc4121` crate.

   Add checksum/MIC tokens, IOV-style buffer planning, and a real
   aes256-gcm-sha256 profile while keeping API names protocol-neutral.  Do not
   add legacy DES, Triple-DES, RC4, or other old enctypes.

2. Finish and integrate `gss-mech-builder`.

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

   Add the remaining common exports, then add the higher-level signed-ECDH API
   under a separate module so simpler mechanisms can keep using lower layers.

3. Add `authorized_keys` authorization.

   The acceptor currently verifies that the user signature matches the supplied
   public key, but it does not check whether that key is authorized for the
   requested user.  Start with local `authorized_keys` compatibility.

4. Finish user signature retry negotiation.

   The acceptor can return a narrower signature algorithm list, but the
   initiator does not yet retry with a different acceptable signature algorithm.
   This matters most for old RSA keys and legacy `ssh-rsa`.

5. Replace remaining OpenSSL FFI where practical.

   X25519, HMAC-SHA256, and AES-256-GCM still use direct OpenSSL FFI.  Evaluate
   RustCrypto crates or idiomatic bindings while preserving interoperability
   and avoiding private Heimdal APIs.

6. Implement missing GSS services.

   `gss_get_mic()` and `gss_verify_mic()` are still unavailable.  Implement them
   using the same per-message key schedule and RFC 4121-style token framing.

7. Harden encrypted context state.

   `sctx` is encrypted and integrity protected, but it needs freshness and
   replay controls such as expiration, single-use identifiers, or cache-backed
   replay detection.

8. Settle mechanism identity and packaging.

   Replace the private placeholder OID before real deployment, document
   installation for Heimdal and MIT krb5, and add packaging/install targets.

9. Add interoperability tests.

   Keep the current Heimdal loader and `/usr/local/bin/gss-token` tests, then
   add tests for agent-backed user keys, host-key policy, HTTP-style
   acceptor-first exchanges, and eventually MIT krb5 loading.
