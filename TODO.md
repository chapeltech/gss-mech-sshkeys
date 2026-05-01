# TODO

The Internet-Draft and `sshkey.asn1` are the protocol source of truth until
publication.  Any protocol-affecting implementation change must update both.

## Completed

- Add SSH agent signing.  Client-side user authentication uses
  `SSH_AUTH_SOCK` and does not read SSH private key files or prompt for
  passphrases.

## Next Steps

1. Add host key trust policy.

   The initiator currently verifies host signatures cryptographically but does
   not decide whether the host key is trusted.  Add OpenSSH-compatible
   `known_hosts` lookup and verification, including hashed hostnames and
   revoked entries.  Also add DNSSEC-validated SSHFP lookup; SSHFP support is
   required, not a later optional extension.

2. Add Finished MAC key confirmation.

   The draft now separates SSH signatures over the ECDH contributions from
   session-key confirmation.  Add `SshKeyFinished`, transcript hashing, and
   role-separated HMAC keys so each side proves knowledge of the derived ECDH
   session key without another SSH-agent operation.

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
