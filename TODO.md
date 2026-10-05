# TODO

This file records the work required to publish an experimental alpha and the
remaining external gate for an interoperable `0.1` release.  Deferred
compatibility work belongs in `BACKLOG.md`.  Historical roadmap material is
under `docs/archive/`.

## Alpha Exit Condition

The alpha may be published when every alpha gate below is closed, the
acceptance suite passes without required phases being skipped, and the
remaining limitations are stated accurately.  The alpha may use an explicitly
experimental mechanism OID, but it must not claim wire-level interoperability
with a future assigned OID.

## Alpha Gates

1. Correct multipass client configuration resolution (`ssh-config`).

   Status: closed 2026-08-19.

   Preserve one option accumulator across OpenSSH's initial and final passes
   so first-obtained scalar values are not discarded or replaced.  Resolve the
   initial pass against the destination alias, determine the effective
   `HostName`, then evaluate the final pass against that effective hostname
   while retaining `originalhost`.  `Match final` and `Match canonical` must
   be enabled only in their applicable pass.  Unsupported hostname
   canonicalization must continue to fail closed.

   `ssh-config` now owns the complete connection-resolution state machine and
   retains one option accumulator across every applicable pass.  Its tests
   compare `HostName`, `User`, identity and trust paths, `Host`, `Match host`,
   `Match originalhost`, `Match canonical`, and `Match final` directly with
   `ssh -G`.  They cover second-pass attempts to replace first-pass values,
   second-pass values that were previously unset, unavailable canonicalization,
   and unsupported final-pass conditions.  `gss-sshkey` makes one resolver
   call and performs only mechanism-specific validation of the returned host.
   SR-004 is closed.

2. Enforce or fail closed on applicable server policy (`ssh-config` and
   `gss-sshkey`).

   Status: closed 2026-08-19.

   Resolve the requested account's primary and supplementary groups through
   NSS.  Enforce `AllowGroups`, `DenyGroups`, `Match Group`, and
   `RequiredRSASize`.  This mechanism permanently does not use a DNS client
   hostname for server authorization: hostname-dependent policy must fail
   closed whenever it could affect the result.  Evaluate address-dependent
   policy only from a numeric peer address supplied by the embedding
   transport, and fail closed when required address context is missing.  Add
   allow, deny, missing-context, and RSA-size tests.

   `gss-sshkey` now obtains the requested account's primary and supplementary
   groups through NSS and supplies them to `ssh-config`.  Group policy,
   `Match Group`, and `RequiredRSASize` are enforced.  `Match Host` and DNS
   hostname-qualified account policy fail closed because the mechanism has no
   authenticated client hostname.  Numeric source policy is evaluated only
   from a typed peer address supplied by the embedding transport.  Focused
   tests cover allow, deny, missing context, local NSS lookup, and RSA size.

3. Complete or narrow GSS channel-binding support (`gss-sshkey` and
   `gss-mech-builder`).

   Status: closed 2026-08-19.

   Prefer binding a canonical representation of the complete GSS
   channel-binding structure, including initiator and acceptor address types
   and values.  Distinguish null bindings from a present empty structure and
   set `GSS_C_CHANNEL_BOUND_FLAG` only when the supported binding was actually
   used.  If the alpha intentionally supports application data only, narrow
   the protocol and requirements explicitly and reject nonempty unsupported
   address fields.  Resolve SR-008 and add mismatch tests for every bound
   field.

   `gss-mech-builder` now validates the complete GSS channel-binding
   structure and provides a canonical encoding of both address types, both
   address values, and application data.  The encoding distinguishes absent
   bindings from a present empty structure.  `gss-sshkey` binds those bytes
   into key derivation and every authentication transcript, rejects changes
   during multipass establishment, and reports the channel-bound flag only
   for a completed bound context.  Rust tests cover every component and the
   null/empty distinction; direct Heimdal and MIT loader tests cover a fully
   populated binding and `GSS_S_BAD_BINDINGS` on change.  SR-008 is closed.

4. Correct RFC 4121 replay and sequencing behavior (`rfc4121` and
   `gss-mech-builder`).

   Status: closed 2026-08-19.

   Authenticate each received wrap or MIC token before classifying its
   sequence number.  Distinguish duplicate, old, gap, and reordered tokens
   with the appropriate GSS supplementary status bits instead of mapping
   every mismatch to `GSS_S_UNSEQ_TOKEN`.  Ignore unknown received token flag
   bits as RFC 4121 requires.  Add focused tampering, replay, gap, and
   reordering tests.

   `rfc4121` now authenticates wrap and MIC tokens before updating a
   persistent 64-token receive window.  Authenticated suspect messages retain
   their output and report duplicate, old, unsequenced, or gap status; forged
   sequence numbers do not alter state.  Unknown flag bits are ignored while
   known invalid combinations remain rejected.  `gss-mech-builder` maps and
   returns the corresponding GSS supplementary bits through flat-buffer,
   IOV, AEAD, RFC 1508, and Kerberos lucid-context paths.  Focused tests cover
   tampering, every ordering class, replayed output, and flag handling.

5. Retry usable user keys and signature algorithms (`gss-sshkey`).

   Status: closed 2026-08-19.

   Do not stop permanently after the first signable agent key or
   `IdentityFile` is rejected.  Preserve enough authenticated handshake state
   in a retry token to try the next configured candidate safely and in
   OpenSSH order.  Cover multiple agent identities where the first key is not
   authorized but a later key is, plus algorithm fallback for the same key.

   The initiator now builds an OpenSSH-ordered queue of configured agent keys,
   other permitted agent keys, and remaining configured private-key files.
   Each key has policy-ordered signature-algorithm candidates.  An acceptor
   retry is authenticated with the session key and binds the handshake, exact
   rejected encrypted userauth, and sealed server context.  The client accepts
   only a structurally exact retry for its pending attempt, advances through
   signable candidates, and fails when they are exhausted.  Focused tests use
   an SSH-agent protocol stub to cover key and RSA-SHA2 algorithm fallback,
   OpenSSH ordering, tampering, and exhaustion.

6. Align the protocol specification and implementation (`gss-sshkey`).

   Status: closed 2026-08-20.

   Update both `sshkey.asn1` and the Internet-Draft so the authenticated GSS
   source name is the requested username rather than a key fingerprint.
   Replace the draft's AES-GCM descriptions with the encryption and CFX
   profile actually implemented, or change the implementation deliberately.
   Add protocol vectors or assertions that keep transcript and wire-format
   documentation synchronized with the code.

   The ASN.1 comments and Internet-Draft now define the requested username as
   the authenticated GSS source name, document RFC 2743 initial-token framing,
   and describe the implemented AES128-CTS-HMAC-SHA256-128 private-field and
   RFC 4121 per-message profiles.  Fixed DER and transcript vectors are
   asserted by the Rust suite and embedded in the draft.  Profile tests check
   private-field framing, round trips, and integrity failures.

7. Repair or hide the signed-ECDH builder API (`gss-mech-builder`).

   Status: closed 2026-08-21.

   The public API currently derives role-dependent session inputs and verifies
   a local Finished proof rather than a peer proof, so two peers do not share
   the advertised behavior.  Either define canonical initiator/acceptor input
   ordering and mutual Finished verification with interoperability tests, or
   make the module private and explicitly unavailable in the alpha.  The
   `gss-sshkey` mechanism does not currently depend on this API.

   The public API now stores initiator and acceptor nonces in canonical order
   and omits the local role from session-key derivation.  Finished proofs are
   generated only from a derived session and peer verification requires the
   opposite role.  The confirmation provider receives the derived session key.
   Two-peer tests derive an identical key, verify both Finished directions,
   and reject changed roles, nonces, transcripts, protocol labels, negotiated
   algorithms, and caller contexts.

8. Close GSS ABI and secret-lifecycle defects (`gss-mech-builder`, `rfc4121`,
   and `gss-sshkey`).

   Status: closed 2026-08-24.

   Release a newly allocated inner context when initial establishment fails.
   Commit send and receive sequence changes only after all caller-visible
   buffer or IOV output succeeds.  Return stable mechanism-owned read-only OID
   metadata and make lucid export report only key roles that actually exist.
   Zeroize mechanism session keys and remove or redact `Debug` output for
   secret-bearing types.  Add failure-path, repeated-query, and secret-lifetime
   tests.

   Newly created establishment contexts are now released through the
   mechanism hook on first-call failure, while pre-existing contexts remain
   caller-owned.  RFC 4121 MIC, wrap, unwrap, AEAD, and IOV paths stage send
   or receive state and publish it only after caller output succeeds, for both
   native and imported Kerberos contexts.  Context operations return one
   process-lifetime static OID descriptor.  Lucid export places its sole key
   in either the context-key or acceptor-subkey role, never both.  RFC 4121
   profiles and imported Kerberos keys use zeroizing storage, signed-ECDH
   secret Debug output is redacted, and `gss-sshkey` keeps derived X25519
   shared secrets and session keys in zeroizing storage while wiping context
   keys before replacement, clearing, or drop.  Focused tests cover failure
   cleanup, repeated OID identity, failed IOV output, key roles, redaction,
   and explicit secret cleanup.

9. Complete repeatable alpha acceptance coverage.

   Status: closed 2026-08-24.

   Exercise a real `ssh-agent` as well as unencrypted Ed25519 or ECDSA
   `IdentityFile` credentials.  Cover representative `Host` and `Match`
   selection, rejected host and user keys, DNSSEC-valid and invalid SSHFP
   answers, server source policy, channel-binding mismatch, local-name
   authorization, and post-establishment MIC and wrap.  Run direct
   `rfc4121` tests from `make test`.  Required MIT and Heimdal loader phases
   must fail rather than silently skip in the release environment.

   The GSS acceptance runner now uses both an unencrypted Ed25519 identity and
   a key loaded into a real `ssh-agent`.  Public-ABI exchanges cover `Host`
   alias resolution with `Match final`, rejected host and user keys, accepted
   and rejected numeric source-address policy, peer channel-binding mismatch,
   requested-name `gss_userok()` authorization, MIC, signed and sealed wrap,
   and IOV wrap.  Deterministic Hickory proof tests accept matching secure
   SSHFP records and reject secure mismatches, insecure data, and bogus
   answers.  `make test` invokes `rfc4121` directly.  `make test-alpha`
   requires the real-agent, Heimdal loader, and MIT loader phases and treats
   missing prerequisites or an unavailable loader namespace as failures.  The
   strict suite passes with every required phase run.

10. Prepare publishable source and packages.

    Status: closed 2026-10-05.

    Add licence metadata and licence files to `gss-sshkey` and `ssh-config`.
    Decide whether the alpha is a source/binary release or a crates.io release;
    for crates.io, package the dependency crates in this order: `rfc4121`,
    `gss-mech-builder`, `ssh-config`, then `gss-sshkey`.  Use an alpha version,
    include release notes and security limitations, verify clean package
    contents, and commit the current multi-repository work intentionally.

    The experimental alpha is a source and binary release, not a crates.io
    release.  `gss-sshkey` is versioned `0.1.0-alpha.1`; it and `ssh-config`
    declare BSD-2-Clause and ship matching licence files.  Release notes state
    the experimental OID, bounded completed-exchange replay exposure, key and
    prompt limitations, fail-closed configuration behavior, and authorization
    restrictions.

    `make release-alpha` runs the strict acceptance suite and creates a source
    archive containing all four sibling crates plus separate Heimdal and MIT
    krb5 binary archives.  The source package has an exact manifest, excludes
    VCS, cache, build, and binary material, and builds with the top-level lock
    file after extraction.  Binary package tests compare their complete file
    lists and require the shared object, public header, loader configuration,
    licence, and release notes.  The dependency repositories were committed
    in build order, `ssh-config` was separated from its unrelated parent
    checkout, and this repository records the complete alpha release state.

## Interoperable 0.1 Gate

Obtain a legitimate permanent GSS-API mechanism OID.  Submit the
Internet-Draft to the Kitten working group and obtain IESG Approval for its
`TBD1` request in the IANA "SMI Security for Mechanism Codes" registry.  After
assignment, replace the experimental OID consistently in the implementation,
protocol specification, integration adapters, tests, installer, and
documentation.

## Working Rules

- Protocol-visible changes update both the Internet-Draft and `sshkey.asn1`.
- Tests for a behavior change accompany that change.
- Valid unsupported configuration must remain parseable and fail closed only
  when it could affect authentication or authorization.
- Do not implement other SSH authentication methods or post-login session
  policy as part of this milestone.
