# Pre-0.1 Roadmap Archive

This file preserves the roadmap that preceded the focused `0.1` requirements.
It is historical context, not an active task list or release gate.
Its completed-history companion is `TODO-completed-pre-0.1.md`.

The Internet-Draft and `sshkey.asn1` are the protocol source of truth until
publication.  Any protocol-affecting implementation change must update both.

## Handover Summary

- Goal: implement SSH Public Key Authentication compatibility through this GSS
  mechanism, so it is a seamless SSH login replacement for OpenSSH public-key
  authentication when SSH is configured with
  `PublicKeyAuthentication=no` and `GSSAPIAuthentication=yes`.
- Scope: SSH public-key authentication replacement only: authentication and
  plain login authorization.  Do not add work for post-authentication
  permissions such as X11, agent, forwarding, TTY, environment, user-rc, or
  forced-command enforcement.
- Non-scope: do not implement password, keyboard-interactive, or hostbased
  authentication.  References to those methods are only parser or
  method-selection guardrails needed to fail closed or to prove that this
  mechanism is selected as the public-key-authentication replacement.
  The active roadmap has no implementation tasks for those methods.
  Existing oracle names and completed-history notes may mention those methods;
  they are not future implementation work.
- Roadmap scope rule: every active TODO item must name SSH public-key login
  behavior, the GSS mechanism behavior that replaces it, or an explicit
  fail-closed guardrail around selecting that mechanism.
- Communication rule: summarize off-scope method rows as "non-scope method
  guardrails" unless an exact OpenSSH directive or fixture name is required.
- Architecture: `ARCHITECTURE.md` documents the login compatibility model,
  context-field classes, and the decision to fail closed for unsupported
  session restrictions instead of granting partially enforceable logins.
- Current implementation: client config, identity selection, ssh-agent
  signing, host trust, server config, authorized-key/certificate checks,
  revocation, account policy, local-name authorization, and typed-context
  plumbing all have substantial local coverage.
- Oracle: `tests/openssh-compat/fixtures.tsv` is the compatibility inventory.
  It splits runnable client `ssh -G`, server `sshd -T`, fake-agent, and
  cargo-backed policy fixtures from explicit recorded oracle gap rows.
- Local gaps: stock `sshd` still rejects custom GSS mechanism OIDs before
  token exchange unless the mechanism is in OpenSSH's server-side GSSAPI
  authorization table.  The opt-in integrated `sshd` build target has
  demonstrated GSSAPI-only plain user-key login with prototype typed SSH
  transport context.  Remaining live-login gaps are native OpenSSH transport
  hooks, certificates, denial cases, provider-backed identities, and real-agent
  policy coverage.
- Local tool caveat: cargo-backed checks work with the existing
  `/u/elric/.cargo/bin/cargo`; use
  `CARGO_TARGET_DIR=/tmp/gss-sshkey-target` to avoid workspace filesystem
  pressure.
- Latest verification: on 2026-07-29, `make test-openssh-live` passed,
  observing GSSAPI-only userauth reachability and the current stock-`sshd`
  boundary rejection.  The same harness also passed through
  `OPENSSH_SRC_DIR=/path/to/openssh-10.2p1 make test-openssh-live-integrated`
  against a disposable integrated OpenSSH 10.2p1 build, demonstrating a
  GSSAPI-only plain user-key login with native SSH public-key authentication
  disabled.  The OpenSSH 10.2p1 server integration patch in
  `tests/openssh-live/openssh-gss-sshkey-10.2p1.patch` dry-runs cleanly
  against the Fedora OpenSSH 10.2p1 source tree.  The filtered
  `client-cname-resolver-shim` OpenSSH oracle rows passed, covering
  resolver-exposed CNAME canonicalization, source-to-final CNAME acceptance,
  and hop-rule rejection through a temporary C `LD_PRELOAD` resolver shim.  The
  public C context smoke passed with local Heimdal library detection and now
  covers fail-closed missing client session id, server session id, verified
  host key, and server source-address context.
  `OPENSSH_COMPAT_KIND=gap make test-openssh-compat` passed with 25 recorded
  gap rows.  The current manifest has 1541 runnable fixtures plus those 25
  gap rows.
- The direct `tests/gss-token/run.sh` smoke now isolates anonymous loader
  exchange from the developer's real SSH config and runs a public C typed
  context login smoke that completed an authenticated user-key exchange with
  local-name authorization.  This does not close the OpenSSH live-login gaps.
- `make test-openssh-live` is an opt-in stock-boundary live probe.  It starts a
  disposable local `sshd`, disables native SSH public-key authentication,
  selects `gssapi-with-mic`, verifies that OpenSSH reaches the GSSAPI userauth
  path and that the client emits a GSSAPI userauth packet, then records the
  current stock-`sshd` GSS mechanism-list rejection before context completion.
  The same harness has an opt-in success mode for an externally supplied
  integrated `sshd`:
  `OPENSSH_LIVE_EXPECT_SUCCESS=1 SSHD_BIN=/path/to/sshd`.
- Next useful slice: replace the prototype environment transport context with
  native OpenSSH session-id and host-key transport hooks.

## Completed History

Completed entries were moved to `TODO.completed.md` to keep this file
focused on active public-key-login work.  The archive is historical audit
context.  Any entry naming another SSH authentication method remains non-scope
and must not be expanded beyond fail-closed parser or method-selection
guardrails for the public-key-equivalent GSSAPI login path.

## Path to SSH Login-Compatible GSSAPI Deployment

The long-term compatibility target is documented in `ARCHITECTURE.md`.  This
roadmap narrows the next deliverable to logging in through SSH with
`PublicKeyAuthentication=no` and `GSSAPIAuthentication=yes`.

The login milestone means:

- The client chooses the same target user, host alias, identity files,
  certificate files, agent socket, agent identities, and host-trust policy
  that OpenSSH public key authentication would choose for the same invocation.
- The server accepts or rejects the same local user, key or certificate,
  source address, and account state that sshd public key authentication would
  use to decide whether login is allowed.
- `gss_authorize_localname()` returns success only when the SSH login
  authorization result permits that exact local account.
- ssh-agent receives enough verified remote-counterparty identity to make the
  same key policy decision that it would make for ordinary SSH public key
  authentication.

The login milestone stops at the question "may this account log in with this
key or certificate from this source now?"  This TODO tracks authentication and
login authorization only.  It deliberately excludes post-authentication session
feature enforcement.  If an OpenSSH key, certificate, or server option cannot
be interpreted as a plain login allow/deny decision, record the limitation or
fail closed in the login path instead of adding post-login enforcement work.
It also does not track implementation of any other SSH authentication methods;
they may appear only as parser or method-selection guardrails around the
public-key-equivalent GSSAPI login path.
Do not add TODO work for enforcing X11, agent, TCP, stream-local, tunnel, TTY,
user-rc, environment, or forced-command session behavior.
`PermitRootLogin forced-commands-only` is in this same category because the
GSSAPI layer cannot know whether SSH will issue or enforce a command after
authentication.

Milestone status:

- Milestone 0 is continuous: keep the OpenSSH oracle ahead of implementation.
- Milestone 1 is covered: the typed context boundary exists and must remain
  the stable boundary for file-derived login context, SSH transport facts, and
  server authorization data.
- Milestone 2 is active: run real `ssh` client tests using the resolved
  client config, identity, agent, and host-trust policy.
- Milestone 3 is active: run real `sshd` tests for successful and rejected
  user-key, certificate, revocation, and account-policy logins.
- Milestone 4 is active: finish protocol, builder, packaging, OID, and
  documentation work required for Heimdal and MIT krb5 deployment.

Roadmap exit criteria:

- A real OpenSSH client can authenticate with
  `PublicKeyAuthentication=no` and `GSSAPIAuthentication=yes` while using the
  same login-relevant client policy that public key authentication would have
  used.
- A real sshd acceptor path can accept or reject the same user, key,
  certificate, source address, and account state that sshd public key
  authentication would have used for login authorization.
- Destination-constrained and confirmation-required agent keys see enough
  verified SSH peer identity to make the same policy decision they would make
  for normal SSH public key authentication.
- Login authorization fails closed when a matching key or certificate cannot
  be interpreted as a login grant by this milestone.
- Post-login session permissions and restrictions are outside this roadmap,
  including X11, agent, TCP, stream-local, tunnel, TTY, user-rc, environment,
  forced commands, and command-execution enforcement.
- Protocol, ASN.1, README, architecture notes, and oracle fixtures are updated
  with every behavior change that affects interoperability.

Near-term commit strategy:

- For each OpenSSH behavior, add or extend the `ssh -G`, `sshd -T`,
  fake-agent, or live OpenSSH oracle first.
- Implement only the parser, policy, or protocol surface needed for that
  oracle-covered login behavior.
- Wire the behavior into the initiator or acceptor decision path and add a
  fail-closed test for malformed, missing, or integration-dependent inputs.
- Document any intentional deviation immediately, rather than leaving it as an
  implicit implementation quirk.
- Keep reusable GSS and RFC4121 work in the sibling repositories; keep this
  repository focused on SSH login policy and mechanism glue.

Covered baseline, not active work unless a new oracle gap appears:

- The typed login boundary exists as `ClientLoginContext`,
  `ServerLoginContext`, and `LocalMechanismContext`.  Environment variables are
  only a compatibility adapter around that boundary.
- Focused OpenSSH oracle and local policy tests already cover client config,
  identity selection, method selection, fake-agent signing behavior, host-trust
  inputs, server config, authorized-key and certificate login authorization,
  revocation, account policy, local-name authorization, and source hygiene.
- The public C context-field smoke covers an authenticated user-key exchange
  driven by `include/gss_sshkey.h`, including client, server, local, and SSH
  transport context fields plus local-name authorization.  It also covers
  fail-closed behavior when required client session id, server session id,
  verified host-key, or server source-address context is unavailable.
- The opt-in OpenSSH live probe covers the current GSSAPI-only userauth
  boundary with native SSH public-key authentication disabled.  Stock `sshd`
  still rejects the custom mechanism OID.  The integrated-`sshd` mode has
  demonstrated successful plain user-key login through the integrated build
  target, but still depends on prototype environment-provided transport context.
- The OpenSSH oracle covers resolver-exposed CNAME canonicalization through
  `client-cname-resolver-shim`, `client-cname-final-resolver-shim`, and
  `client-cname-hop-rules-resolver-shim`.
- The compatibility manifest records 1541 runnable fixtures and 25 gap rows.
  The gap rows, not the covered maintenance surface, define the remaining
  implementation blockers.

Remaining active work:

1. Build the live OpenSSH GSSAPI-only login harness.

   Add real integration tests that run `ssh` with native public-key
   authentication disabled and GSSAPI authentication enabled against an `sshd`
   configured to use this mechanism.  The initial `test-openssh-live` probe
   reaches GSSAPI-only userauth and records the current stock-`sshd` mechanism
   table rejection.  `tests/openssh-live/openssh-gss-sshkey-10.2p1.patch`
   records the current OpenSSH server integration hook, and
   `OPENSSH_SRC_DIR=/path/to/openssh-10.2p1 make test-openssh-live-integrated`
   builds a disposable integrated `sshd` and demonstrates plain user-key
   success.  The remaining work is to replace prototype transport context and
   turn these manifest gaps into successful runnable tests:

   - `live-gssapi-only-login` (integrated target works; native transport open)
   - `live-user-key-login` (integrated target works; native transport open)
   - `live-user-cert-login`
   - `live-implicit-cert-fallback`

2. Wire SSH transport context into the mechanism.

   The live harness and agent policy need verified SSH transport facts:
   session id, KEX host-key signature, verified host key, target host, peer
   address, and local address.  The public C context smoke now owns the
   negative missing-transport-facts case at the typed boundary.  Remaining
   work in this area is the live SSH integration evidence:

   - `verified-transport-host-key`

3. Finish live host-trust behavior.

   Host signatures should be accepted or rejected for the same reasons as an
   SSH transport host key.  Convert these gaps to live tests once transport
   context is available:

   - `live-host-key-rejection`
   - `live-hashed-known-hosts`
   - `live-revoked-host-key`
   - `live-dns-sshfp-host-key`
   - `live-host-cert-ca-trust`
   - `live-host-cert-ca-rejection`
   - `live-knownhostscommand-fingerprint`
   - `live-update-hostkeys-write`
   - `live-hash-known-hosts-update`

4. Finish real ssh-agent policy coverage.

   Fake-agent tests cover protocol decisions; real OpenSSH agent behavior still
   needs the live SSH transport path and, for confirmation, a prompt path:

   - `destination-constrained-agent`
   - `confirmation-required-agent`
   - `live-agent-refusal-fallback`

5. Finish live server authorization denial coverage.

   The local policy tests cover the decision code.  The live harness still
   needs rejected-login coverage through actual SSH client/server execution:

   - `live-denied-account`
   - `live-pam-account-policy`
   - `live-platform-account-policy`
   - `live-revoked-user-key`
   - `live-expired-user-cert`
   - `live-unavailable-credential`

6. Finish provider-backed identity loading.

   Add live SSH tests for identities that require external provider libraries:

   - `live-pkcs11-provider-identity`
   - `live-security-key-provider-identity`

7. Keep protocol changes tied to named public-key-login gaps.

   Extend GSS-SSHKEY only when one of the remaining gaps requires new
   transcript inputs, retry messages, certificate data, or agent-binding
   context.  Update the Internet-Draft and `sshkey.asn1` with every
   protocol-visible change.

8. Finish deployment identity and packaging.

   Replace the private placeholder OID, validate mechanism registration with
   packaged Heimdal and MIT krb5 deployments, and extend staged install or
   tarball support into distribution-native packaging.

9. Revisit dependencies only for proven gaps.

    Keep `ssh-key`, the narrow `rsa` use, local OpenSSH config parsers, helper
    backed KRL handling, and the sibling GSS/RFC4121 crates unless an oracle
    or packaging result proves that a different component is required.
