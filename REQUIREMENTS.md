# Current Requirements

This document defines the current `0.1` goal for `gss-sshkey`.  The
Internet-Draft and `sshkey.asn1` remain the source of truth for protocol syntax
and cryptographic transcript details.

## Goal

`gss-sshkey` must provide a useful GSS-API authentication mechanism based on
ordinary SSH keys.  Its current milestone is a standalone GSS mechanism that
reuses common OpenSSH credential, host-trust, and authorization configuration,
not exhaustive compatibility with every OpenSSH feature.

The mechanism must work through the standard GSS-API without integration into
any particular application.  Native OpenSSH support and its application glue
are useful interoperability work, but are not release requirements.

The mechanism must reuse common SSH identity, host-trust, and
`authorized_keys` policy.  It must answer only the login question: may this SSH
key authenticate as this local account from this source now?

## Client Requirements

- Operate as a GSS initiator using an SSH key as the authenticated identity.
- Return the requested login username as the authenticated GSS source name.
- Resolve the destination host from the GSS target name.
- Obtain the requested login username in this order:
  - Use explicit typed caller context when it is available.
  - Otherwise use the resolved `ssh_config` `User` value.
  - Otherwise use the invoking local username.
- Do not use `gss_acquire_cred()` as a channel for the remote login username.
  Its desired name identifies the credential principal, not the account being
  requested on a remote server.  Version `0.1` supports only default
  initiator credential acquisition and must reject a non-null desired name
  rather than silently selecting a different user key.
- Resolve the common client configuration needed for authentication:
  `Host`, `Match`, `Include`, `HostName`, `User`, `Port`, `IdentityAgent`,
  `IdentityFile`, `IdentitiesOnly`, `PubkeyAcceptedAlgorithms`,
  `HostKeyAlias`, `UserKnownHostsFile`, `GlobalKnownHostsFile`,
  `VerifyHostKeyDNS`, `GSSAPIAuthentication`, and
  `PreferredAuthentications`.
- Treat conditional resolution as security-critical.  The client must
  evaluate applicable `Host`, `Match`, and `Include` blocks before choosing
  the effective destination hostname and requested login username.
- Apply OpenSSH's first-obtained-value rule and configuration passes when
  resolving authentication settings.  Support host and user pattern lists,
  negation, and the common `Match` criteria needed to select `HostName` and
  `User`, including `all`, `host`, `originalhost`, `user`, `localuser`,
  `canonical`, and `final`.
- Do not silently use an unmatched default when an unsupported condition
  could change `HostName`, `User`, identity selection, or host trust.  Keep
  the configuration valid, but fail authentication for that target when its
  required client policy cannot be resolved safely.
- Support common path handling, including home-directory expansion and the
  common `%h`, `%n`, `%p`, `%r`, and `%d` tokens where OpenSSH permits them.
- Use ordinary `ssh-agent` identities or unencrypted OpenSSH private keys.
- Support common Ed25519 and ECDSA keys directly, and RSA-SHA2 user keys
  through `ssh-agent`.  Direct RSA private-key signing is unavailable until a
  suitable constant-time implementation is available.
- Try usable identities in OpenSSH order and signature algorithms in
  `PubkeyAcceptedAlgorithms` order.  Continue after a session-authenticated
  authorization rejection, and fail when the candidates are exhausted.
- Never advance to another identity or signature algorithm in response to an
  unauthenticated or malformed retry.
- Authenticate the server SSH host key.  Use a verified transport host key
  supplied by the caller when available; otherwise use matching
  `known_hosts` entries or, when `VerifyHostKeyDNS yes` applies, a matching
  DNSSEC-validated SSHFP record.
- Treat SSHFP records as authentic only when their DNSSEC chain validates to
  a configured trust anchor.  Insecure, indeterminate, bogus, unavailable,
  missing, or mismatching DNS data must not establish host trust.
- Never prompt for host trust or use unauthenticated trust-on-first-use.  The
  mechanism has no interactive I/O channel.  `VerifyHostKeyDNS ask` cannot
  authorize a key automatically.  If the mechanism cannot validate the host
  key, authentication must fail.
- Bind the requested username, user key, canonical host-based GSS acceptor
  name, mechanism transcript, nonces, and GSS channel bindings into
  authentication.
- Bind both address types, both address values, and application data.  Keep
  absent bindings distinct from a present empty structure, reject changes
  during a multipass exchange, and report channel binding only after use.
- Fail closed when required identity or trust information is missing,
  malformed, or inconsistent.
- Report GSS mutual authentication, integrity, confidentiality, replay,
  sequencing, channel-binding, and transfer capabilities accurately.

## Server Requirements

- Operate as a GSS acceptor and prove possession of an Ed25519 or ECDSA SSH
  host private key.  Direct RSA host-key signing has the same restriction as
  direct RSA user-key signing.
- Receive the requested login username inside the authenticated mechanism
  exchange.
- Verify possession of the offered SSH user private key.
- Resolve the common server configuration needed for login authorization:
  `AuthorizedKeysFile`, `Match User`, `Match Address`, `Match Group`,
  `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`,
  `PermitRootLogin`, `RevokedKeys`, `RequiredRSASize`, and accepted
  user-signature algorithms.
- Apply normal ownership and permission checks to authorization files.
- Require the requested local account to exist and pass the supported account
  policy.
- Authorize only when the exact key is permitted for the exact requested
  account and, when address policy applies, the locally supplied numeric
  source address.
- The acceptor may use its own hostname while parsing local configuration,
  but must never use a DNS client hostname for authorization.  It must not
  perform reverse DNS, accept a client-asserted hostname, or treat a numeric
  peer address as a hostname.
- Evaluate address-dependent authorization only when the embedding transport
  supplies its locally observed numeric peer address.  Fail closed when
  missing address context or permanently unsupported hostname context could
  affect authorization.
- Parse complete `authorized_keys` entries through `ssh-config`.  Support
  plain entries and entries containing only an unexpired `expiry-time`.
  Treat every other key option, including `from=`, `cert-authority`, forced
  commands, and session restrictions, as unsupported policy that makes that
  entry unavailable.
- Fail closed when a known authorization condition cannot be reduced to a
  plain login allow or deny decision.
- Return the requested login username as the authenticated GSS source name.
- Make `gss_authorize_localname()` succeed only for the local account
  authenticated and authorized during the exchange.
- Verify GSS channel bindings and reject mismatches.
- Report and provide the corresponding GSS integrity, confidentiality,
  replay, sequencing, channel-binding, and transfer capabilities accurately.

## Continuation Replay Model

- Encrypt and authenticate acceptor continuation state, including its
  canonical acceptor audience and issuance time.
- Apply the server's local maximum-age policy to the authenticated issuance
  time.  Version `0.1` rejects state that is at least 120 seconds old, and
  rejects missing, malformed, or excessively future-dated issuance times.
- Treat a completed stateless exchange without fresh carrier binding or
  other carrier replay mitigation as a bearer token while server age policy
  accepts it.  This bounded replay exposure is an accepted `0.1` limitation.
- Keep GSS per-message replay and sequencing detection independent from this
  context-establishment limitation.
- Do not require a replay cache or mandatory channel bindings for `0.1`.

## Configuration Compatibility

- A syntactically valid client or server configuration must not be rejected
  merely because it contains a valid directive that the implementation does
  not understand or support.
- Unknown and unrelated directives must be retained or ignored without
  changing supported authentication policy.
- A known but unsupported authorization condition that would be required to
  grant access must make that login candidate unavailable, not make the whole
  configuration unparsable.
- A malformed supported directive that affects authentication, host trust, or
  authorization must fail closed.
- Exact OpenSSH behavior outside the supported subset is not a `0.1`
  requirement.

## Acceptance Requirements

- A GSS initiator and acceptor can establish an authenticated context using
  SSH host and user credentials, with the user key authorized for the exact
  requested local account.
- Context establishment succeeds with a common key supplied by `ssh-agent`.
- Context establishment can advance from an unauthorized agent identity to a
  later authorized identity, and can try another RSA-SHA2 algorithm for the
  same agent key.
- Context establishment succeeds with a common unencrypted Ed25519 or ECDSA
  `IdentityFile`.
- A configured `User` value selects the account authenticated by the
  mechanism.
- `Host` and supported `Match` conditions select the same effective
  `HostName` and `User` as OpenSSH for representative common configurations.
- A condition that cannot be evaluated and could change the effective host,
  user, identity, or host trust causes authentication to fail closed.
- When `User` is absent, the invoking local username is used.
- An unauthorized key and an incorrect account are rejected.
- A missing, untrusted, or mismatched host key is rejected without prompting.
- A DNSSEC-validated matching SSHFP record can authenticate an otherwise
  unknown host when `VerifyHostKeyDNS yes` applies.
- Insecure, bogus, unavailable, or mismatching SSHFP data does not
  authenticate a host.
- Mismatched GSS channel bindings are rejected.
- The mechanism loads through both Heimdal and MIT krb5.
- GSS MIC and wrap operations work after authenticated context establishment.

## Non-Goals For 0.1

- Exhaustive OpenSSH configuration compatibility.
- Other SSH authentication methods.
- Post-authentication session restrictions or permissions.
- Address-based `authorized_keys` restrictions.
- Native integration into OpenSSH or any other particular GSS application.
- SSH user certificates.
- Destination-constrained or confirmation-required agent keys.
- PKCS#11 and security-key providers.
- Interactive host-trust or private-key prompts.
- Host certificates and known-hosts file updates.
- PAM and platform-specific account-policy parity.
- Distribution-specific packaging.
