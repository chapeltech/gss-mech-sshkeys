# Pre-0.1 Completed TODO History

This file preserves completed work from the previous compatibility roadmap.
It is historical context, not a current requirements document.

This archive preserves completed audit notes moved out of `TODO.md`.

## Completed

Completed entries are historical audit notes.  Any entry naming another SSH
authentication method remains non-scope and must not be expanded beyond
fail-closed parser or method-selection guardrails for the
public-key-equivalent GSSAPI login path.

- Added a public C context-field login smoke.  The new `tests/gss-token`
  phase sets client, server, local, and SSH transport context through
  `include/gss_sshkey.h`, writes temporary test-only OpenSSH key and config
  files, completes an authenticated user-key GSS exchange, and checks
  `gss_authorize_localname()` plus `gss_localname()`.  This proves the typed
  context ABI from outside Rust.  The same smoke now verifies fail-closed
  behavior when client session id, server session id, verified host key, or
  server source-address context is unavailable, while the OpenSSH live-login
  gaps remain open until `ssh` and `sshd` can supply the same context
  directly.
- Added an opt-in OpenSSH live boundary probe.  `make test-openssh-live`
  starts a disposable local `sshd`, disables native SSH public-key
  authentication, selects `gssapi-with-mic`, preloads the existing
  `sshkey.so`, and verifies that OpenSSH reaches GSSAPI userauth and that the
  client sends a GSSAPI userauth packet.  The expected result remains a failed
  login because stock `sshd` rejects the offered GSSAPI mechanism before
  context completion, so successful OpenSSH login gaps remain active.
- Added the `client-cname-resolver-shim` OpenSSH oracle row.  The compatibility
  runner now builds a temporary C `LD_PRELOAD` resolver shim for that row, and
  `ssh -G` proves that a resolver-exposed CNAME canonical name feeds canonical
  login host policy in the target GSSAPI public-key replacement mode.  The
  resolver shim now also covers a resolver-exposed final canonical name with a
  direct permitted-CNAME rule, plus rejection when only hop-by-hop rules are
  configured for that final name.  The old multi-hop DNS CNAME gap was removed
  because OpenSSH applies `CanonicalizePermittedCNAMEs` to the canonical name
  exposed by `getaddrinfo()`, not to a separate hidden chain input.
- Reduced `TODO.md` to the remaining active blocker set.  Covered
  parser/policy surfaces now stay in the architecture notes, compatibility
  audit, fixture manifest, and this archive instead of appearing as future
  implementation work.  The active roadmap is now the live OpenSSH harness,
  SSH transport context, real agent and provider paths, full DNS chain
  canonicalization context, protocol updates required by named public-key-login
  gaps, OID replacement, and packaging.
- Moved closed active-roadmap sections out of `TODO.md`.  The detailed current
  oracle baseline, Milestone 1 typed-context closeout, and regular SSH
  local-name authorization closeout now remain only in this archive and the
  architecture notes, leaving active TODO numbering for remaining work.
- Documented the administrator migration path from OpenSSH public key auth to
  GSSAPI-only auth.  `README.md` now names the GSSAPI and publickey method
  settings, preserves existing authorized-key and certificate policy as the
  source of login authorization, records the ssh-agent expectation for
  encrypted keys, keeps post-authentication restrictions outside the mechanism,
  and names the SSH transport facts needed for production integration.  The
  OpenSSH oracle README now carries the same target-mode and non-scope
  guardrail wording.
- Added explicit client and server OpenSSH oracle rows for the target
  public-key-equivalent GSSAPI login mode.  The new rows verify
  `GSSAPIAuthentication yes`, `PubkeyAuthentication no`, and
  `gssapi-with-mic` method selection together, rather than relying only on
  separate single-option fixtures.
- Added minimal target-mode OpenSSH oracle rows for the documented migration
  state.  The client row records `GSSAPIAuthentication yes` with
  `PubkeyAuthentication no` and no `PreferredAuthentications` override.  The
  server row records the same method toggles with `AuthenticationMethods any`.
- Added mixed-method target-mode OpenSSH oracle rows.  The client row records
  that `PreferredAuthentications gssapi-with-mic,publickey` remains viable
  when native publickey is disabled.  The server row records that
  `AuthenticationMethods gssapi-with-mic publickey` remains viable because
  disabled native publickey is only an alternative method chain.
- Added the reverse mixed-method server oracle row.  OpenSSH records
  `AuthenticationMethods publickey gssapi-with-mic` as viable even when native
  publickey is disabled, because `gssapi-with-mic` remains an alternative
  method chain.
- Added chained target-mode OpenSSH oracle rows.  The client row records that
  `PreferredAuthentications publickey,gssapi-with-mic` still leaves
  `gssapi-with-mic` available when native publickey is disabled.  The server
  row records OpenSSH rejecting the single-chain `AuthenticationMethods` value
  `gssapi-with-mic,publickey` because it requires disabled native publickey
  after GSSAPI.
- Added target-mode negative OpenSSH oracle rows.  Client rows record that the
  replacement path is unavailable when `GSSAPIAuthentication` is disabled or
  `PreferredAuthentications` excludes `gssapi-with-mic`.  Server rows record
  OpenSSH rejecting unsatisfiable authentication-method chains when GSSAPI is
  disabled or the disabled native publickey method is required.
- Recorded the full multi-hop CNAME canonicalization gap in the OpenSSH oracle
  manifest and audit.  The gap now names the missing DNS resolver shim instead
  of remaining only as prose in the active client-configuration TODO.  The
  oracle runner and README now label the gap inventory as recorded oracle gaps,
  since not every gap is a live-login row.
- Reworded active manifest and audit descriptions for password,
  keyboard-interactive, and hostbased client/server rows as off-scope parser,
  alias, scoping, or method-selection guardrails.  The rows no longer describe
  alternate authentication methods as implementation targets.
- Retired the stale test-matrix wording that grouped Heimdal and MIT krb5
  loader coverage with live-login gaps.  Loader coverage remains owned by
  `make test-gss-token` and `make test`, while recorded OpenSSH live-login
  gaps stay limited to SSH transport, login, host policy, account, and
  provider identity behavior.
- Retired the broad remaining helper-command parity roadmap item for
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand`.  Existing focused
  cargo-backed rows cover safe paths, command users, argv/token expansion,
  nonzero exits, output limits, invalid UTF-8, timeouts, stderr discard,
  process-group cleanup, and missing `%C`/`%D` transport context.  Future
  helper work must name a concrete public-key login oracle gap.
- Closed the Milestone 1 typed-context boundary for the current login API.
  `ClientLoginContext`, `ServerLoginContext`, and `LocalMechanismContext`
  now consume validated adapter snapshots or explicit v1 context fields, with
  source-hygiene coverage limiting production process-environment reads to
  `AdapterContextSnapshot` and `SSHKEY_TRACE`.  Remaining live-agent and SSH
  transport integration belongs to explicit oracle gaps and later live tests.
- Closed the item (1) oracle-definition work for the current baseline.
  `tests/openssh-compat/fixtures.tsv`, `AUDIT.md`, and `run.sh` now define
  the login-only OpenSSH oracle, validate manifest/audit symmetry, report
  runnable fixture and gap counts, and require concrete unblockers for
  non-runnable live-login gap rows.
- Retired the stale interoperability-matrix item for adding initial `ssh -G`
  and `sshd -T` golden tests.  The current oracle already runs 572 client
  and 293 server golden fixtures; future matrix work should add focused rows
  only for new public-key-login behavior.
- Retired the stale client-config roadmap item for wiring the internal
  resolver into initiator policy selection.  `resolve_client_policy()` now
  builds a `ClientLoginContext`, delegates to
  `resolve_client_policy_with_context()`, and feeds the initiator before
  userauth identity selection.
- Retired the stale protocol/builder roadmap item for finishing the initial
  signed-ECDH builder integration.  This crate now depends on sibling
  `gss-mech-builder` and `rfc4121` checkouts, uses the signed-ECDH builder
  traits in the mechanism, and carries focused oracle rows for signed-ECDH and
  RFC4121 behavior.
- Retired the stale hardening roadmap wording that treated private-key, agent,
  transcript, and buffer cleanup as unaudited.  Focused source-hygiene oracle
  rows now cover private-key buffers, agent replies and userauth transcripts,
  handshake transcripts, KDF/MAC material, authorization results, typed
  context buffers, and constant-time byte comparison.
- Retired the stale packaging roadmap wording for adding the initial tarball
  target.  `make install`, `make uninstall`, `make package`,
  `make test-install`, and `make test-package` now cover staged shared-object,
  public-header, and Heimdal/MIT mechanism-fragment installs.  Remaining
  packaging work is permanent OID assignment and distribution-native release
  packaging.
- Make packaging honor external Cargo target directories.  The Makefile now
  derives `RUST_LIB` from `CARGO_TARGET_DIR`, so `make`, `make package`, and
  `make test-package` can use `/tmp/gss-sshkey-target` without looking for the
  release shared object under the workspace `target/` directory.
- Settle the near-term OpenSSH config parser strategy.  This crate keeps the
  local `ssh_config` and `sshd_config` parsers gated by the OpenSSH oracle
  instead of adopting `ssh2-config-rs`; reconsider only for a concrete
  oracle-backed parser gap.
- Retired stale identity-selection roadmap wording that treated default
  identity ordering, `IdentitiesOnly`, private fallback file policy, and
  common certificate pairing as initial work.  Focused oracle rows now cover
  configured, default, agent, and private identity ordering, `IdentityFile` and
  `CertificateFile` sentinels, sidecar certificates, symlink, non-regular,
  malformed, owner, and mode policy cases, plus agent/private certificate
  pairing.  Remaining ordering work is limited to concrete OpenSSH-oracle gaps
  such as the live raw-key rejection to implicit certificate fallback.
- Retired stale ssh-agent roadmap wording that treated identity listing, sign
  requests, RSA retry flags, session binding, host-bound payloads, and generic
  failure fallback as initial work.  Focused oracle rows now cover fake-agent
  session binding, destination-constrained behavior, confirmation denial,
  malformed replies, refusal/fallback behavior, RSA retry flags, and identity
  ordering.  Remaining agent work is limited to live real-agent and SSH
  transport or prompt-path gaps.
- Retired stale host-trust roadmap wording that treated known-hosts files,
  hashed hostnames, revoked entries, host-certificate CAs, DNS SSHFP parsing,
  helper output, strict-host-key modes, `CheckHostIP`, aliases, and host-key
  update policy as initial work.  Focused oracle rows now cover those local
  decisions.  Remaining host-trust work is limited to live SSH transport
  validation and integration-owned known-hosts update writes.
- Retired stale server-login roadmap wording that treated broad
  `sshd_config`, authorization-source, certificate, revocation, account, and
  local-name work as initial coverage.  Focused oracle rows now cover many
  server config, helper-command, authorization-file, trusted-CA, revocation,
  account, and local-name decisions.  Remaining server-side work must name a
  concrete public-key login gap, such as live GSSAPI-only user-key or
  certificate success, denied accounts, PAM or platform account policy,
  revoked user keys, or expired certificates.
- Retired stale client-config roadmap wording that treated `Host`, `Include`,
  `Match`, first-value precedence, command-line overrides, canonicalization
  knobs, token expansion, identity/agent/method controls, and algorithm policy
  as initial work.  Focused oracle rows now cover those local decisions.
  Remaining client-config work is limited to concrete OpenSSH gaps such as
  multi-hop DNS CNAME canonicalization, new system-level inputs,
  provider-backed live identities, or new login-relevant options.
- Closed GSS local-name authorization for the current regular SSH login
  profile.  Focused oracle rows now prove authenticated exact-name checks,
  missing or denied authorization rejection, exported local-name handoff,
  SSH authorization-result use, and authorized local-user mapping.  Non-login
  authorization-name profiles are outside this public-key-login TODO.
- Split the remaining in-scope malformed `ProxyJump` assertions out of the
  residual broad `client/invalid` fixture, then removed that residual broad
  fixture and its off-scope connection, session, and alternate-authentication
  parser assertions from the login oracle.  Focused `invalid-*`,
  `include-invalid-*`, `ignoreunknown-invalid`, and `tilde-invalid` rows now
  own malformed client configuration coverage.
- Removed off-scope client `ChannelTimeout` invalid OpenSSH fixtures from the
  login oracle and pruned the residual `client/invalid` missing-argument
  assertion for the same directive.  Valid ordinary non-login directive parsing
  remains covered by the cargo-backed `client-known-nonlogin-arity` row and
  the narrowed `client/nonlogin` smoke row.
- Narrowed the broad client `nonlogin` OpenSSH row to the login-relevant
  assertion that ordinary non-login directives do not block resolved login
  user policy.  The cargo-backed `client-known-nonlogin-arity` row keeps parser
  acceptance coverage for those ordinary directives without carrying their
  resolved post-authentication or transport output in the public-key-login
  oracle.
- Split broad server `Match LocalPort` coverage into focused matching-port,
  default-port fallback, and unrelated high-port fallback rows.  This only
  isolates existing local-port policy coverage; it does not add local-port
  roadmap scope.
- Pruned already-focused login-target, source-routing, method-selection,
  identity/provider, host-trust, canonicalization, tag, and algorithm arity
  assertions from the residual broad `client/invalid` row.  Focused client
  invalid rows own those fail-closed checks, leaving the residual row free of
  password, keyboard-interactive, hostbased, GSSAPI, and public-key method
  arity assertions.
- Split broad agent login-boundary-policy coverage into focused post-login
  control, forced-command, authorized-key, authorized-principals, certificate,
  and trusted-CA session-restriction rows.  Focused cargo-backed oracle rows
  now record each login-only boundary behavior separately without adding
  post-authentication enforcement work.
- Split broad agent server-config-match-policy coverage into focused typed
  context, inline option, invalid config, path override, `Include`,
  host/address `Match`, user `Match`, and host/routing validation rows.  The
  existing local-connection `Match` assertion is isolated in its own row and
  is not expanded as public-key-auth roadmap work.
- Pruned already-focused client invalid path-argument, quote, scalar-value,
  host-trust, canonicalization, and timing expectations before the broad
  `client/invalid` row was removed.  Focused client invalid rows now own those
  fail-closed assertions.
- Split broad agent source-hygiene-hardening coverage into focused adapter,
  public-context, zeroization, helper, private-key, config, typed-context,
  identity-candidate, mechanism-context, and randomness-boundary rows.  Focused
  cargo-backed oracle rows now record each login-sensitive hygiene invariant
  separately.
- Split broad agent server-config-parser-policy coverage into focused
  `Include`, override, authorization-source, account, GSSAPI, public-key,
  certificate, algorithm, revocation, and strict-mode parser rows.  Password,
  keyboard-interactive, and hostbased-only assertions are not carried as
  public-key-auth compatibility rows.
- Split broad agent host-trust-policy coverage into focused known-hosts,
  certificate-authority, verified-transport, revocation, `KnownHostsCommand`,
  localhost-bypass, `CheckHostIP`, strict-host-key, fingerprint, and SSHFP
  rows.  Focused cargo-backed oracle rows now record each host-trust behavior
  separately.
- Split broad agent failure-fallback coverage into focused sign-response,
  signature-validation, agent transport, identity-list parser, identity-list
  failure, and sign-failure rows.  Focused cargo-backed oracle rows now record
  each agent failure fallback or fail-closed behavior separately.
- Split broad agent identity-ordering coverage into focused configured
  identity precedence, agent/default certificate fallback, source-reporting,
  deduplication, sidecar, and encrypted identity rows.  Focused cargo-backed
  oracle rows now record each identity-ordering behavior separately.
- Split broad agent server-revocation-policy coverage into focused
  `RevokedKeys none`, command-sourced key, command-sourced certificate,
  trusted-CA certificate, plain-file key, tilde-home, KRL key, KRL scratch-dir,
  helper timeout, missing helper, minimal helper `PATH`, missing/malformed
  file, invalid KRL, plain certificate subject/CA, and KRL certificate CA
  rows.  Focused cargo-backed oracle rows now record each server revocation
  behavior separately.
- Split broad agent server-continuation-policy coverage into focused
  replay-id, context-key validation, context-key generation, local mechanism
  adapter, in-process single-use, shared replay-directory, continuation-state
  sealing, direct `LoginGraceTime`, and resolved `LoginGraceTime` rows.  Focused
  cargo-backed oracle rows now record each continuation-state behavior
  separately.
- Split broad agent signed-ecdh-protocol coverage into focused X25519,
  signed-ECDH exchange, SP800-108 KDF, session deriver, Finished MAC,
  key-confirmation, KEX negotiation, malformed KEX, Ed25519 transcript signer,
  RSA transcript signer, and userauth-state sealing rows.  Focused cargo-backed
  oracle rows now record each signed-ECDH behavior separately.
- Split broad agent session-binding coverage into focused context-ABI,
  host-bound success, bind-failure fallback, bind-failure fail-closed,
  malformed-bind fallback, malformed-bind fail-closed, missing-host-key
  fallback, local session-id binding, missing-host-key fail-closed,
  missing-signature fallback, local host-key binding, and missing-signature
  fail-closed rows.  Focused cargo-backed oracle rows now record each
  session-binding behavior separately.
- Split broad agent client-path-expansion-policy coverage into focused identity
  token, certificate token, path environment, host-trust token, `IdentityAgent`
  braced environment, context environment, unset `IdentityAgent` environment,
  host-trust environment, tilde-user, unknown tilde-user, unset host-trust
  environment, OpenSSH argument-error, and missing-environment rows.  Focused
  cargo-backed oracle rows now record each client path-expansion behavior
  separately.
- Split broad agent certificate-policy coverage into focused trusted-CA policy,
  certificate source-address, certificate revocation, trusted-CA principal,
  `TrustedUserCAKeys none`, CA-signature algorithm, certificate
  validity/critical-option, session-restriction, trusted-CA source-address,
  authorized-principals file, comment-hash, quoted-value, duplicate-exclusive,
  and authorized-principals command rows.  Focused cargo-backed oracle rows now
  record each certificate authorization behavior separately.
- Split broad agent authorized-keys-policy coverage into focused plain-key
  match, hash-comment, `from`/`expiry-time`, case-insensitive option,
  expired/unknown option, session-restriction, quoted-value, session-option
  syntax, duplicate-exclusive, certificate-authority principal,
  certificate-authority option, case-insensitive CA option, empty-principal,
  from-negation, host/address from-pattern, empty from-pattern, and
  malformed-CIDR rows.  Existing security-key presence coverage remains in its
  focused row.
- Split broad agent host-trust-edge-policy coverage into focused
  `UpdateHostKeys ask`, known-host path token expansion, literal global
  known-hosts, literal `HostKeyAlias none`, bare-host port fallback, literal
  `KnownHostsCommand` path, command stderr, resolved-host command, disabled
  command, `CheckHostIP` context-address, port address-name, IPv6 port
  address-name, address mismatch, address command reason, and address-command
  fail-closed rows.  Focused cargo-backed oracle rows now record each
  host-trust edge behavior separately.
- Split broad agent client-context-policy coverage into focused malformed
  init config, malformed init context, config-path order, invalid config-path
  override, invalid host-address, invalid known-hosts override, typed override,
  invalid adapter override, target-host override, adapter snapshot, hex
  host-key, bracketed host-address, local-user capture, invalid local-user,
  home tilde-path, home environment snapshot, agent environment, invalid
  session context, and default local-user rows.  Focused cargo-backed oracle
  rows now record each client typed-context behavior separately.
- Split broad agent client-identity-selection-policy coverage into focused
  implicit certificate, explicit certificate preference, non-user certificate,
  `CertificateFile none`, `IdentityFile none`, `IdentityFile none`
  `IdentitiesOnly`, default identity-home, default identity agent-filter,
  default certificate agent-filter, default security-key agent-filter, default
  certificate-home, sparse default order, explicit-certificate suppression,
  private fallback suppression, private fallback `none`, agent fallback
  suppression, agent fallback `none`, `IdentitiesOnly` agent-filter,
  `IdentitiesOnly` agent-certificate, configured agent order, configured
  certificate pairing, and agent `IdentitiesOnly` rows.  Focused cargo-backed
  oracle rows now record each client identity-selection behavior separately.
- Split broad agent account-policy coverage into focused `PermitRootLogin`,
  `AllowUsers`/`DenyUsers`, `AllowGroups`/`DenyGroups`, locked-account,
  PAM fail-closed, expired-account, login-shell validity, default-shell,
  password-lock marker, and shadow-expiry rows.  Focused cargo-backed oracle
  rows now record each account-policy behavior separately.
- Split broad agent server-authorization-file-policy coverage into focused
  `AuthorizedKeysFile none`, `AuthorizedPrincipalsFile` policy,
  `AuthorizedKeysFile` strict modes, `TrustedUserCAKeys` tilde-home,
  `AuthorizedPrincipalsFile none`, principals-file token expansion,
  principals-file glob/strict-mode, authorized-keys template expansion, and
  authorized-keys template-list rows.  Focused cargo-backed oracle rows now
  record each server authorization-file behavior separately.
- Split broad agent security-key-policy coverage into focused authorized-keys
  option parsing, signature flag parsing, server `PubkeyAuthOptions`,
  authorized-keys signature policy, later matching lines,
  authorized-principals policy, certificate/principal restrictive merging, and
  certificate option carry-through rows.  Focused cargo-backed oracle rows now
  record each security-key login-policy behavior separately.
- Split broad agent retry-and-rsa coverage into focused RSA flag values,
  acceptor algorithm filtering, RSA SHA-2 512, RSA SHA-2 256, legacy
  `ssh-rsa`, RSA-size filtering, security-key signing, and direct agent flag
  rows.  Focused cargo-backed oracle rows now record each agent signing
  retry/RSA behavior separately.
- Split broad agent localname-policy coverage into focused authenticated exact
  match, local-name export, missing authorization, SSH authorization,
  authorized local-user mapping, denied authorization, and authorization
  inquiry session-restriction rows.  Focused cargo-backed oracle rows now
  record each GSS local-name and authorization-inquiry behavior separately.
- Split broad agent sshkey-token-protocol coverage into focused initial-token
  fields, initial-token framing, signature-retry algorithms,
  acceptor-KEX rejection, signature-blob tamper, security-key trailer
  strictness, and certificate-identity rows.  Focused cargo-backed oracle rows
  now record each SSHKEY token and SSH signature behavior separately.
- Split broad agent rfc4121-cfx-protocol coverage into focused sealed-wrap
  replay, signed-wrap tamper, MIC replay, split-IOV wrap, and sign-only IOV
  rows.  Focused cargo-backed oracle rows now record each RFC4121 CFX
  per-message behavior separately.
- Split broad agent mechanism-hardening-primitives coverage into focused
  random-fill failure cleanup, random-fill success, constant-time byte
  comparison, and output-token handoff rows.  Focused cargo-backed oracle rows
  now record each mechanism hardening primitive separately.
- Split broad agent server authorization-source ordering coverage into
  focused authorized-keys-before-CA, authorized-keys-before-command,
  authorized-keys-CA-before-command, trusted-CA-before-command,
  principals-file-before-command, and principals-before-local-user rows.
  Focused cargo-backed oracle rows now record each server authorization-source
  ordering behavior separately.
- Split broad agent client-canonicalization-policy coverage into focused
  resolvable, always-mode, max-dots, fallback-local, and CNAME-policy rows.
  Focused cargo-backed oracle rows now record each client canonicalization
  login-policy behavior separately.
- Split broad agent server-context-policy coverage into focused host-key path,
  adapter snapshot, session-id, helper-locale, and connection-token rows.
  Focused cargo-backed oracle rows now record each server typed-context
  boundary behavior separately.
- Split broad agent client-method-policy coverage into focused
  pubkey-isolation, GSSAPI method-gate, direct report, identity report,
  unselected-method rejection, and exported inquiry rows.  Focused
  cargo-backed oracle rows now record each client method-policy initiator
  behavior separately.
- Split broad agent server-method-policy coverage into focused
  pubkey-isolation, GSSAPI method-gate, user-key authorization, direct report,
  and exported inquiry rows.  Focused cargo-backed oracle rows now record each
  server method-policy acceptor behavior separately.
- Split broad agent server-account-decision coverage into focused file-backed
  user, command user, command group, command certificate, and file-backed group
  rows.  Focused cargo-backed oracle rows now record each account allow/deny
  acceptor decision separately.
- Split broad agent server-security-key-decision coverage into focused
  file-backed, command-key, command-certificate, and touch-override rows.
  Focused cargo-backed oracle rows now record each server security-key
  acceptor decision separately.
- Split broad agent server-authorized-keys-decision coverage into focused
  source-restriction, expiry, session-restriction, and certificate-authority
  rows.  Focused cargo-backed oracle rows now record each
  `AuthorizedKeysFile` acceptor decision separately.
- Split broad agent identity-metadata coverage into focused certificate
  metadata, subject-key fingerprint, authorization-report principal, and
  exported-name-token rows.  Focused cargo-backed oracle rows now record each
  source identity metadata behavior separately.
- Split broad agent destination-policy coverage into focused verified-context,
  no-context fallback, same-identity fallback, and fail-closed rows.  Focused
  cargo-backed oracle rows now record each destination-constrained login path
  separately.
- Split broad agent confirmation-policy coverage into focused continue,
  fail-closed, local-fallback, and same-identity fallback rows.  Focused
  cargo-backed oracle rows now record each confirmation-denial login path
  separately.
- Split broad agent transcript-binding coverage into focused requested-user
  and key, verified-host-key, and session-identity rows.  Focused
  cargo-backed oracle rows now record each login transcript binding separately.
- Split broad client default-policy coverage into focused method, prompt,
  agent-add, identity-file, provider, public-key algorithm, host-key
  algorithm, and CA-signature algorithm rows.  Focused `ssh -G` coverage now
  records each empty-config default separately.
- Split broad client canonicalization coverage into focused canonicalization
  knobs, permitted-CNAMEs, resolved-hostname, final-match,
  canonical-match, fallback-identity, and always-mode rows.  Focused `ssh -G`
  coverage now records each canonicalization and `Match` effect separately.
- Split broad client hash/context token coverage into focused
  `IdentityAgent`, `UserKnownHostsFile`, `RevokedHostKeys`, literal
  `HostKeyAlias`, literal `IdentityFile`, and literal `CertificateFile` rows.
  Focused `ssh -G` coverage now records each expanded context token and
  literal file-identity behavior separately.
- Split broad client nested `Include`/`Match` scope coverage into focused
  outer-host user, hostname, identity-order, matched identity/certificate, and
  direct-host fallback/absence rows.  Focused `ssh -G` coverage now records
  each inherited-scope and nonleakage result separately.
- Split broad client command-line override coverage into focused target,
  method, identity, and certificate rows.  Focused `ssh -G` coverage now
  records each command-line override and retained file/fallback value
  separately.
- Split broad client host-trust environment path coverage into focused
  `UserKnownHostsFile`, `RevokedHostKeys`, and `GlobalKnownHostsFile` rows.
  Focused `ssh -G` coverage now records each directive-specific host-trust
  path expansion result separately.
- Split broad client `Include` environment and nested-glob coverage into
  focused included-user, included-identity, and fallback-identity rows.  The
  `ssh -G` oracle now records each included login directive and later fallback
  identity result separately for both include path sources.
- Split broad client proxy-precedence token coverage into focused selected
  proxy value, suppressed later proxy value, and percent-j expansion rows for
  both `ProxyCommand`-first and `ProxyJump`-first precedence.
- Split broad client case-sensitive `Include` glob coverage into focused
  lower-case included user, lower-case included identity, fallback identity,
  upper-case fallback user, and absent upper-case identity rows.
- Split broad client command-line tag coverage into focused tag visibility,
  fallback user, original target hostname, matched identity, and fallback
  identity rows.
- Split broad client `Match localnetwork` coverage into focused matched user,
  matched identity, negated-match identity, and fallback identity rows.
- Split broad client tilde-user path coverage into focused `IdentityAgent`,
  `UserKnownHostsFile`, `RevokedHostKeys`, literal `IdentityFile`, and literal
  `CertificateFile` rows.
- Split broad client conditional `Include` scope coverage into focused
  matching-host user and identity-order rows plus unrelated-host fallback and
  no-included-identity rows.
- Split broad client path-token coverage into focused resolved target,
  expanded agent and host-trust path, and literal identity/certificate/global
  known-hosts rows.
- Split broad client positive `Match` criteria coverage into focused matched
  target, originalhost, host, localuser, exec, negated exec, negated host,
  user-list, and fallback identity rows.
- Split broad client host-port rows into focused resolved-hostname,
  resolved-port, and no-synthetic-`HostKeyAlias none` rows for both default
  and non-standard ports.  Focused `ssh -G` coverage now records each
  host-trust naming input separately.
- Split broad client `IdentityFile none` coverage into focused
  `IdentitiesOnly`, `IdentityFile none` sentinel, and default-identity absence
  rows.  Focused `ssh -G` coverage now records each file identity default
  suppression outcome separately.
- Split broad client `HostKeyAlias` rows into focused resolved-hostname,
  resolved-port, and alias-value rows for both explicit aliases and the
  literal `none` alias.  Focused `ssh -G` coverage now records each
  host-trust naming input separately.
- Split broad client duplicate identity and certificate file rows into focused
  first-path collapse, later unique-path retention, and nonconfigured-path
  absence rows.  Focused `ssh -G` coverage now records each identity and
  certificate duplicate-resolution outcome separately.
- Split broad client `IgnoreUnknown` coverage into focused first-host and
  later-host user-policy rows.  Focused `ssh -G` coverage now records ignored
  unknown directives separately for the first matching host block and a later
  matching host block.
- Split broad invalid client `Match localnetwork` coverage into focused
  missing-argument and invalid-CIDR prefix rows.  Focused `ssh -G` coverage
  now records each malformed network-dependent match form as its own
  fail-closed login-policy oracle row.
- Split broad client command-line `none` identity and certificate rows into
  focused sentinel and retained-config rows.  Focused `ssh -G` coverage now
  records command-line `IdentityFile none` and `CertificateFile none`
  separately from the config-file identity and certificate entries that remain
  visible.
- Split broad client algorithm-removal oracle rows into focused
  `PubkeyAcceptedAlgorithms`, `HostKeyAlgorithms`, and
  `CASignatureAlgorithms` rows.  Each new `ssh -G` fixture now records one
  observable removal or retained-algorithm outcome for login key, host-trust,
  or CA trust policy.
- Split the broad server nested-`Match` include-scope row into focused
  parent-matched fallback, pre-nested include override, following parent
  override, nested-user fallback, and unrelated-user fallback rows.  Focused
  `sshd -T` coverage now proves nested `Match` blocks inside included files do
  not leak into the parent file or into users outside the parent `Match`.
- Split the broad server `Include`-inside-`Match` scope row into focused
  included public-key, password, and keyboard-interactive override and fallback
  rows, plus following hostbased override and fallback rows.  Focused
  `sshd -T` coverage now proves included login directives inherit the active
  `Match User` scope without changing unmatched users, and following matched
  directives stay in that scope.
- Split the broad server `Match RDomain` empty-pattern row into focused
  leading-empty override, leading-empty fallback, trailing-empty override,
  trailing-empty fallback, and all-empty fallback rows.  Focused `sshd -T`
  coverage now proves empty routing-domain pattern segments preserve real
  routing-domain matches while all-empty lists leave login policy unchanged.
- Split the broad server `Match Host` empty-pattern row into focused
  leading-empty override, leading-empty fallback, trailing-empty override,
  trailing-empty fallback, and all-empty fallback rows.  Focused `sshd -T`
  coverage now proves empty host-pattern segments preserve real host matches
  while all-empty host-pattern lists leave login policy unchanged.
- Split the broad server `Match Group` negated-pattern row into focused
  explicit positive-group override, positive-group fallback, negated-group
  fallback, and wildcard nonmatching-user fallback rows.  Focused `sshd -T`
  coverage now proves group negation excludes only the negated account group
  while preserving explicit positive matches and nonmatching login policy.
- Split the broad server `Match Group` empty-pattern row into focused
  leading-empty override, trailing-empty override, and all-empty fallback rows.
  Focused `sshd -T` coverage now proves empty group-pattern segments preserve
  real wildcard group matches while an all-empty group list leaves login policy
  unchanged.
- Split the broad server `Match RDomain` negated-pattern row into focused
  wildcard override, negated-routing-domain fallback, and unrelated
  routing-domain fallback rows.  Focused `sshd -T` coverage now proves
  routing-domain negation only excludes the negated domain while preserving
  the wildcard match and unrelated fallback.
- Split the broad server `Match LocalAddress` negated-wildcard row into
  focused positive-wildcard override, negated-local fallback, and
  unrelated-local fallback rows.  Focused `sshd -T` coverage now proves
  local-address wildcard negation only excludes the negated address while
  preserving the wildcard match and unrelated fallback.
- Split the broad server `Match Address` negated-wildcard row into focused
  positive-wildcard override, negated-peer fallback, and unrelated-peer
  fallback rows.  Focused `sshd -T` coverage now proves peer-address wildcard
  negation only excludes the negated address while preserving the wildcard
  match and unrelated fallback.
- Split the broad server `Match LocalAddress` negated-CIDR row into focused
  positive-range override, negated-local fallback, and unrelated-local fallback
  rows.  Focused `sshd -T` coverage now proves local-address CIDR negation only
  excludes the negated address while preserving the CIDR match and unrelated
  fallback.
- Split the broad server `Match Address` negated-CIDR row into focused
  positive-range override, negated-peer fallback, and unrelated-peer fallback
  rows.  Focused `sshd -T` coverage now proves peer-address CIDR negation only
  excludes the negated address while preserving the CIDR match and unrelated
  fallback.
- Split the broad server `Match Host` negated-pattern row into focused
  wildcard override, negated-host fallback, and unrelated-host fallback rows.
  Focused `sshd -T` coverage now proves host negation only excludes the
  negated canonical host while preserving the wildcard match and unrelated
  fallback.
- Split the broad server `Match User` negated-pattern row into focused
  wildcard override, negated-user fallback, and unrelated-user fallback rows.
  Focused `sshd -T` coverage now proves user negation only excludes the
  negated login user while preserving the wildcard match and unrelated
  fallback.
- Split the broad server `AuthorizedPrincipalsCommand` quoted-argument row
  into focused helper argv parsing and helper user identity rows.  Focused
  `sshd -T` coverage now proves quoted and escaped principals-helper arguments
  separately from the required `AuthorizedPrincipalsCommandUser` identity.
- Split the broad server `AuthorizedKeysCommand` quoted-argument row into
  focused helper argv parsing and helper user identity rows.  Focused
  `sshd -T` coverage now proves quoted and escaped helper arguments separately
  from the required `AuthorizedKeysCommandUser` identity.
- Split the broad server `AuthorizedPrincipalsCommand none` no-user row into
  focused helper-disable and implicit helper-user sentinel rows.  Focused
  `sshd -T` coverage now proves the principals helper is disabled separately
  from the resolved `AuthorizedPrincipalsCommandUser none` sentinel.
- Split the broad server `AuthorizedKeysCommand none` no-user row into focused
  helper-disable and implicit helper-user sentinel rows.  Focused `sshd -T`
  coverage now proves the authorization helper is disabled separately from the
  resolved `AuthorizedKeysCommandUser none` sentinel.
- Split the broad server `Match Host` trailing-comma row into focused matching
  override and nonmatching fallback rows.  Focused `sshd -T` coverage now
  proves a trailing host-pattern comma preserves the real host match without
  changing unrelated hosts.
- Split the broad server `Match User` empty-pattern row into focused matching
  override and nonmatching fallback rows.  Focused `sshd -T` coverage now
  proves empty user-pattern segments preserve real login user matches without
  changing unrelated users.
- Split the broad server `PermitRootLogin forced-commands-only` row into
  focused global forced-command-only and `Match Address` root-login override
  rows.  Focused `sshd -T` coverage now proves the distinct root-login account
  policies separately.
- Split the broad server `ChallengeResponseAuthentication` alias row into
  focused global alias and `Match`-scoped alias override rows.  Focused
  `sshd -T` coverage now proves each keyboard-interactive login-method alias
  decision separately.
- Split the broad server `Match All` `PubkeyAuthOptions` row into focused
  ordinary-context security-key options, prior `Match User` public-key
  override, and post-user-match security-key option rows.  Focused `sshd -T`
  coverage now proves each matched public-key login decision separately.
- Split the broad server principals-command `Match` row into focused
  `AuthorizedPrincipalsFile none` and `AuthorizedPrincipalsCommand none`
  rows.  Focused `sshd -T` coverage now proves file and helper-command
  sentinels separately before certificate login authorization consumes them.
- Split the broad server `Match` certificate-source row into focused
  `TrustedUserCAKeys none`, `AuthorizedPrincipalsFile` override, and
  `AuthorizedPrincipalsFile none` rows.  Focused `sshd -T` coverage now
  proves each matched certificate authorization-source decision separately
  before login authorization consumes it.
- Split the broad server `Match` `AuthorizedKeysFile` row into focused
  matching override, nonmatching fallback, and `none` sentinel rows.  Focused
  `sshd -T` coverage now proves each matched authorized-key file-list
  decision separately before login authorization consumes it.
- Split the broad server mixed-case scalar `Match` row into focused
  `PermitEmptyPasswords` toggle and mixed-case `PubkeyAuthentication`,
  `GSSAPIAuthentication`, `HostbasedAuthentication`,
  `PasswordAuthentication`, `KbdInteractiveAuthentication`,
  `PermitRootLogin`, and `PermitEmptyPasswords` normalization rows.  Focused
  `sshd -T` coverage now proves each matched scalar normalization separately
  before login policy is consumed.
- Split the broad server `Match` authentication-toggle row into focused
  `HostbasedAuthentication`, `PasswordAuthentication`, and
  `KbdInteractiveAuthentication` rows.  Focused `sshd -T` coverage now proves
  each match-scoped login method toggle separately.
- Split the broad server local-context `Match` row into focused
  `LocalAddress` and `RDomain` public-key override rows.  Focused
  `Match LocalPort` rows keep the single local-port criterion pinned, so local
  address, local port, and routing-domain policy are now covered without one
  row hiding all three context inputs.
- Split the broad server `Match User`/`Host` method row into focused matching
  user public-key override, negated-user fallback, and matching host
  public-key override rows.  Focused `sshd -T` coverage now proves user and
  host match criteria separately before login method policy is consumed.
- Split the broad server `Match Address` method row into focused nonmatching
  public-key fallback, matching public-key override, and matching root-login
  override rows.  Focused `sshd -T` coverage now proves address matching and
  each login-policy override separately.
- Split the broad server global key-policy row into focused
  `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms`, `RequiredRSASize`,
  `FingerprintHash`, and `PubkeyAuthOptions` rows.  Focused `sshd -T`
  coverage now proves each global key, fingerprint, and security-key policy
  value separately before login authorization can consume it.
- Split the broad server global account row into focused `PermitRootLogin`,
  `PermitEmptyPasswords`, `UsePAM`, local-user `AllowUsers`, host-pattern
  `AllowUsers`, `DenyUsers`, `AllowGroups`, and `DenyGroups` rows.  Focused
  `sshd -T` coverage now proves each global account-policy input separately
  before login authorization can consume it.
- Split the broad server global authorization-source row into focused
  `AuthorizedKeysFile`, `AuthorizedKeysCommand`,
  `AuthorizedKeysCommandUser`, `TrustedUserCAKeys`,
  `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`,
  `AuthorizedPrincipalsCommandUser`, and `RevokedKeys` rows.  Focused
  `sshd -T` coverage now proves each global authorization source separately
  before login authorization can consume it.
- Split the broad server global method row into focused `StrictModes`,
  public-key, GSSAPI, hostbased, authentication-method list, password,
  keyboard-interactive, retry-limit, and login-grace-time rows.  Focused
  `sshd -T` coverage now proves each login method or preauth timing value
  separately, and the old listener `Port` assertion is no longer represented
  as login-compatibility coverage.
- Split the broad server top-level `Include` row into focused global
  `StrictModes`, global `DenyUsers`, nested `DenyUsers`, lower-case `Match`,
  and skipped upper-case `Match` rows.  Focused `sshd -T` coverage now proves
  included login policy separately from nested glob expansion and
  case-sensitive include path matching.
- Split the broad client `Include` glob row into focused later-file user,
  later-file hostname, included port, included identity, and `Host *` fallback
  identity rows.  Focused `ssh -G` coverage now proves globbed include
  expansion separately from later file and catch-all identity policy.
- Split the broad client negated `Host` pattern row into focused fallback
  login user, hostname, port, identity-agent, host-trust scalar,
  prompt/method scalar, fallback identity, and excluded wildcard identity
  rows.  Focused `ssh -G` coverage now proves negated host-pattern exclusion
  separately from each fallback login-policy value.
- Split the broad client wildcard `Host` pattern row into focused login user,
  hostname, port, identity, `Host *` agent fallback, and `Host *` identity
  fallback rows.  Focused `ssh -G` coverage now proves wildcard host-pattern
  selection separately from later catch-all identity-source fallback policy.
- Split the broad client `Tag` directive row into focused host-user,
  hostname, host-identity, `Match tagged` identity, and `Host *` fallback
  identity rows.  Focused `ssh -G` coverage now proves tagged-match identity
  policy separately from ordinary host-block and fallback identity policy.
- Split the broad client identity-file precedence row into focused
  `IdentitiesOnly`, explicit Ed25519 `IdentityFile`, explicit RSA
  `IdentityFile`, and `Host *` identity-file fallback rows.  Focused `ssh -G`
  coverage now proves each identity-selection value separately before login
  identity use.
- Split the remaining broad client proxy `none` sentinel rows into focused
  omission and fallback-suppression rows for `ProxyJump` and `ProxyCommand`.
  Focused `ssh -G` coverage now proves exact `none` values disappear from
  proxy routing output separately from suppressing later `Host *` fallback
  proxy routing.
- Split the broad client host-trust `none` sentinel rows into focused
  omission and fallback-suppression rows for `KnownHostsCommand` and
  `RevokedHostKeys`.  Focused `ssh -G` coverage now proves exact `none`
  values disable their host-trust helper or revocation file output separately
  from suppressing later `Host *` fallback policy.
- Split the broad client invalid percent-token row into focused `User`,
  `HostName`, `IdentityAgent`, `UserKnownHostsFile`, `RevokedHostKeys`, and
  `RemoteCommand` failure rows.  Focused `ssh -G` coverage now proves each
  unsupported token expansion fails closed separately before the corresponding
  configured value can influence login or command policy.
- Split the broad client `ProxyJump none` row into focused sentinel and
  fallback rows.  Focused `ssh -G` coverage now proves the `none` sentinel
  suppresses later `Host *` proxy routing separately from catch-all
  `ProxyJump` fallback routing.
- Split the broad client public-key and hostbased algorithm modifier rows into
  focused removal, prepend, and legacy-alias rows.  Focused `ssh -G` coverage
  now proves `PubkeyAcceptedAlgorithms` removal and prepend behavior,
  `PubkeyAcceptedKeyTypes` aliasing, `HostbasedAcceptedAlgorithms` prepend
  behavior, and `HostbasedKeyTypes` aliasing separately before login key
  policy.
- Split the broad client `BindAddress` and `BindInterface` source-routing rows
  into focused explicit value, `none` sentinel, and default-absence rows.
  Focused `ssh -G` coverage now proves source address/device selection
  separately from disabled and default routing behavior.
- Split the broad client `AddressFamily` rows into focused `any`, `inet`,
  `inet6`, mixed-case, first-value, and `Host *` default rows.  Focused
  `ssh -G` coverage now proves each source-routing address-family behavior
  separately before host trust.
- Split the broad client proxy precedence/token row into focused
  `ProxyCommand`-first and `ProxyJump`-first rows.  Focused `ssh -G` coverage
  now proves each first-value direction separately, including its `%j` token
  result.
- Split the broad client `ProxyCommand` policy row into focused explicit
  command and `none` sentinel rows.  Existing `ProxyJump none` coverage keeps
  `Host *` fallback routing behavior pinned, while focused `ssh -G` rows prove
  `ProxyCommand` command values separately from disabled-proxy sentinels.
- Split the broad client `ProxyJump` syntax row into focused single-hop,
  comma-chain, URI, trailing empty port, and bracketed IPv6 hop rows.  Focused
  `ssh -G` coverage now proves each accepted jump syntax separately before
  login routing.
- Split the broad client mixed-case authentication method row into focused
  `HostbasedAuthentication`, `EnableSSHKeysign`, `PasswordAuthentication`, and
  `KbdInteractiveAuthentication` rows.  Existing focused rows keep mixed-case
  `GSSAPIAuthentication` and `PubkeyAuthentication` coverage.
- Split the broad client `ChallengeResponseAuthentication` alias row into
  focused alias yes/no and alias/canonical first-value precedence rows.
  Focused `ssh -G` coverage now proves the legacy alias maps to
  `KbdInteractiveAuthentication` and shares its first-value policy.
- Split the historical off-scope client password/keyboard-interactive method
  row into focused `PasswordAuthentication` yes/no,
  `KbdInteractiveAuthentication` yes/no, and `KbdInteractiveDevices` rows.
  The rows are retained only as parser and method-selection inventory; they do
  not add those methods to the roadmap.
- Split the historical off-scope client hostbased/keysign method row into
  focused `HostbasedAuthentication` yes/no and `EnableSSHKeysign` yes/no
  rows.  The rows are retained only as parser and method-selection inventory;
  they do not add hostbased authentication to the roadmap.
- Split the broad client GSSAPI method row into focused
  `GSSAPIKeyExchange`, `GSSAPIDelegateCredentials`, `GSSAPITrustDNS`,
  `GSSAPIRenewalForcesRekey`, and `GSSAPIKexAlgorithms` rows.  The existing
  `gssapiauthentication-explicit` row keeps method enablement coverage, while
  the new focused `ssh -G` rows prove each remaining GSSAPI method option
  separately.
- Split the broad client `PubkeyAuthentication` method row into focused
  `yes`, `no`, `unbound`, and `host-bound` rows.  Focused `ssh -G` coverage
  now proves each public-key method mode separately.
- Split the broad client legacy algorithm append row into focused
  `PubkeyAcceptedAlgorithms`, `HostbasedAcceptedAlgorithms`,
  `HostKeyAlgorithms`, and `CASignatureAlgorithms` rows.  Focused `ssh -G`
  coverage now proves each legacy RSA append modifier separately.
- Split the broad client host-key update row into focused `UpdateHostKeys`
  yes/no/ask, `HashKnownHosts` yes/no, and `CheckHostIP` yes/no rows.
  Focused `ssh -G` coverage now proves host-key update, known-host hashing,
  and host-address trust policy separately.
- Split the broad client mixed-case scalar row into focused `BatchMode`,
  `GSSAPIAuthentication`, `PubkeyAuthentication`, `VerifyHostKeyDNS`,
  `StrictHostKeyChecking`, `FingerprintHash`, `UpdateHostKeys`,
  `HashKnownHosts`, `CheckHostIP`, and `AddKeysToAgent` rows.  Focused
  `ssh -G` coverage now proves each mixed-case login-policy scalar
  separately.
- Split the broad client `AddKeysToAgent` mode row into focused `yes`, `no`,
  `ask`, duration, and confirm-duration rows.  The existing
  `addkeystoagent-confirm` row keeps plain confirmation coverage, while the
  new focused `ssh -G` rows prove each remaining agent-add mode separately.
- Split the broad client preferred-auth method row into focused explicit
  `GSSAPIAuthentication`, `Host *` `GSSAPIAuthentication`, explicit
  `PubkeyAuthentication no`, and `PreferredAuthentications` rows.  Focused
  `ssh -G` coverage now proves GSSAPI method enablement, fallback disablement,
  public-key method disablement, and method ordering separately.
- Split the broad client signing-prompt row into focused `AddKeysToAgent`,
  explicit `BatchMode`, `Host *` `BatchMode`, explicit
  `NumberOfPasswordPrompts`, and `Host *` `NumberOfPasswordPrompts` rows.
  Focused `ssh -G` coverage now proves signing, non-interactive, and prompt
  count policy separately.
- Split the broad client identity-source row into focused `IdentityAgent`,
  `PKCS11Provider`, and `SecurityKeyProvider` rows.  Focused `ssh -G`
  coverage now proves explicit agent socket, PKCS#11 provider, and
  security-key provider policy separately.
- Split the broad client target row into focused target-user,
  target-hostname, and target-port rows.  Focused `ssh -G` coverage now proves
  requested login user, resolved hostname, and resolved port policy
  separately.
- Split the broad client known-hosts token row into focused `%h`, `%n`, and
  `%p` path-token rows.  Focused `ssh -G` coverage now proves resolved-host,
  original-host, and resolved-port known-hosts token expansion separately.
- Split compact client host-trust scalar rows into focused `HostKeyAlias`,
  `StrictHostKeyChecking`, and `VerifyHostKeyDNS` rows.  Focused `ssh -G`
  coverage now proves explicit and literal-`none` host-key aliases, each
  strict host-key checking mode, and DNS SSHFP host-key trust ask/no modes
  separately.
- Split the broad client command-line identity `none` row into focused
  command-line `IdentityFile none` and `CertificateFile none` rows.  Focused
  `ssh -G` coverage now proves command-line private-key identity sentinels
  separately from command-line certificate identity sentinels.
- Split the broad client tilde-path row into focused `IdentityAgent`,
  `IdentityFile`, `CertificateFile`, `UserKnownHostsFile`, and
  `RevokedHostKeys` tilde-path rows.  Focused `ssh -G` coverage now proves
  agent socket, identity, certificate, host-trust, and host-key revocation
  path handling separately.
- Split the broad client duplicate identity row into focused duplicate
  `IdentityFile` and duplicate `CertificateFile` rows.  Focused `ssh -G`
  coverage now proves private-key identity de-duplication separately from
  certificate identity de-duplication.
- Split the broad client known-hosts file `none` row into focused
  `UserKnownHostsFile none` and `GlobalKnownHostsFile none` rows.  Focused
  `ssh -G` coverage now proves user and global host-trust path default
  suppression separately.
- Split the broad client identity `none` row into focused `IdentityFile none`
  and `CertificateFile none` rows.  Focused `ssh -G` coverage now proves
  identity-file default suppression separately from certificate-file default
  suppression.
- Split the broad client `NoHostAuthenticationForLocalhost` row into focused
  enabled and disabled rows.  Focused `ssh -G` coverage now proves localhost
  host-trust suppression separately from explicit localhost host-trust use.
- Split the broad client `KnownHostsCommand none` row into focused exact
  sentinel and non-exact literal-command rows.  Focused `ssh -G` coverage now
  proves host-trust helper disabling separately from literal helper command
  configuration.
- Split the broad client host-trust strict/DNS row into focused
  `StrictHostKeyChecking` mode and `VerifyHostKeyDNS` mode rows.  Focused
  `ssh -G` coverage now proves strict host-key modes separately from DNS SSHFP
  trust policy modes.
- Split the broad client host-port row into focused non-standard-port and
  default-port rows.  Focused `ssh -G` coverage now proves host-trust name
  resolution for explicit non-standard ports separately from the default SSH
  port.
- Split the broad client host-key alias row into focused literal-alias and
  known-hosts token-expansion rows.  Focused `ssh -G` coverage now proves
  ordinary `HostKeyAlias` values and literal `HostKeyAlias none` separately
  from `%h`/`%n`/`%p` expansion in `UserKnownHostsFile`.
- Split the broad client host-pattern row into focused wildcard and negated
  `Host` pattern rows.  Focused `ssh -G` coverage now proves wildcard host
  selection separately from negated-pattern exclusion and fallback login
  policy.
- Split the broad client env-path expansion row into focused unbraced
  `IdentityAgent`, braced `IdentityAgent`, and host-trust path rows.  Focused
  `ssh -G` coverage now proves literal unbraced agent environment tokens,
  braced agent socket expansion, and directive-specific host-trust path
  expansion as separate OpenSSH-visible login-policy behaviors.
- Split the broad client target/identity precedence row into focused target
  user/host/port, identity-file ordering, and explicit certificate-file rows.
  Focused `ssh -G` coverage now proves target login names, hostnames, ports,
  explicit and default `IdentityFile` order, `IdentitiesOnly`, and
  `CertificateFile` paths as separate OpenSSH-visible login-policy behaviors.
- Split the broad client provider/prompt/preferred-auth row into focused
  identity-source, signing-prompt, and preferred-auth method rows.  Focused
  `ssh -G` coverage now proves explicit agent sockets, PKCS11 and security-key
  provider paths, `AddKeysToAgent`, `BatchMode`,
  `NumberOfPasswordPrompts`, `GSSAPIAuthentication`,
  `PubkeyAuthentication`, and `PreferredAuthentications` as separate
  OpenSSH-visible login-policy behaviors.
- Split the broad client source-routing rows into focused `AddressFamily`,
  `BindAddress`, and `BindInterface` rows.  Focused `ssh -G` coverage now
  proves accepted address families, mixed-case normalization, first-value
  precedence, default routing, bind-address values, bind-address `none`,
  bind-interface values, and bind-interface `none` as separate
  OpenSSH-visible login-routing behaviors.
- Split the broad client proxy-routing row into focused `ProxyJump`,
  `ProxyJump none`, `ProxyCommand`, and proxy precedence/token rows.  Focused
  `ssh -G` coverage now proves single-hop, jump-chain, URI, trailing-port, and
  IPv6 jump normalization, explicit proxy-jump disablement, proxy-command
  values and `none`, and first-value precedence feeding `%j` token expansion as
  separate OpenSSH-visible login-routing behaviors.
- Split the broad server match-authorization row into focused authorized-key
  file, certificate source, authorized-keys helper, principals helper, and
  revocation rows.  Focused `sshd -T` coverage now proves match-scoped
  `AuthorizedKeysFile` overrides and `none`, trusted-CA/principals-file
  policy, `AuthorizedKeysCommand none`, principals command/file `none`, and
  `RevokedKeys none` as separate OpenSSH-visible login-authorization
  behaviors.
- Split the broad server match-method row into focused address, user/host,
  local-context, invalid-user, retry, authentication-toggle, and mixed-case
  scalar rows.  Focused `sshd -T` coverage now proves `Match Address`
  method/root overrides, `Match User` negation and `Match Host` selection,
  local-address/port/routing-domain matching, `Match Invalid-User`,
  match-scoped `MaxAuthTries`, hostbased/password/keyboard-interactive
  toggles, and mixed-case scalar normalization as separate OpenSSH-visible
  login-policy behaviors.
- Split the broad client token-expansion row into focused basic path-token,
  connection-hash/context-token, and tilde-user rows.  Focused `ssh -G`
  coverage now proves `%r`/`%u`/`%h`/`%n`/`%p` path token behavior,
  `%d`/`%i`/`%l`/`%L`/`%j`/`%k`/`%C` context-token behavior, and
  `~user` agent, identity, certificate, known-hosts, and revocation paths as
  separate OpenSSH-visible login-policy behaviors.
- Split the broad client algorithm-modifier row into focused public-key,
  host-key, CA-signature, and hostbased algorithm rows.  Focused `ssh -G`
  coverage now proves public-key algorithm removal and prepend modifiers,
  `PubkeyAcceptedKeyTypes` alias removal, `HostKeyAlgorithms` removal,
  `CASignatureAlgorithms` removal, and hostbased algorithm and keytype alias
  prepend modifiers as separate OpenSSH-visible login-policy behaviors.
- Split the broad server basic row into focused global method, authorization
  source, account, key-policy, include, `Match`, authorization-sentinel, and
  `Match All` rows.  Focused `sshd -T` coverage now proves global login
  method and timing policy, authorization files and helpers, CA/principals and
  revocation policy, account and group policy, key algorithm and security-key
  policy, include-driven policy, match-scoped method overrides, match-scoped
  `none` sentinels, and `Match All` `PubkeyAuthOptions` as separate
  OpenSSH-visible login-policy behaviors.
- Split the broad client basic row into focused target, provider, environment,
  helper-argv, and host-pattern rows.  Focused `ssh -G` coverage now proves
  login target and identity precedence, provider and prompt policy, preferred
  authentication lists, environment-expanded agent and host-trust paths,
  quoted `KnownHostsCommand` arguments, and wildcard or negated `Host` pattern
  selection as separate OpenSSH-visible login-policy behaviors.
- Split the broad client identity-edge row into focused identity, agent, path,
  and command-line rows.  Focused `ssh -G` coverage now proves
  `IdentityFile none`/`CertificateFile none`, known-hosts file `none`
  sentinels, `IdentityAgent none`, duplicate identity and certificate paths,
  tilde paths, and command-line identity `none` sentinels as separate
  OpenSSH-visible login-policy behaviors.
- Split the broad client host-name row into focused host-alias and port-name
  rows.  Focused `ssh -G` coverage now proves `HostKeyAlias` and
  `UserKnownHostsFile` token expansion separately from non-standard and
  default port handling for host-trust names.
- Split the broad client host-trust row into focused resolved-config rows.
  Focused `ssh -G` coverage now proves `StrictHostKeyChecking` and
  `VerifyHostKeyDNS` modes, `NoHostAuthenticationForLocalhost` enabled and
  disabled behavior, `KnownHostsCommand none` sentinel and literal helper
  command behavior, and `RevokedHostKeys none` as separate
  OpenSSH-visible host-trust policy behaviors before login signatures.
- Split the broad client key-policy row into focused host-trust, signing, and
  algorithm-policy rows.  Focused `ssh -G` coverage now proves
  `UpdateHostKeys`/`HashKnownHosts`/`CheckHostIP` policy, `AddKeysToAgent`
  modes, mixed-case host-trust and signing scalars, legacy RSA algorithm
  append modifiers, and the `HostbasedKeyTypes` alias as separate OpenSSH
  login-policy behaviors.
- Split the broad client authentication-method row into focused method-control
  rows.  Focused `ssh -G` coverage now proves `PubkeyAuthentication` modes,
  GSSAPI method options, hostbased and keysign controls, password and
  keyboard-interactive controls, `ChallengeResponseAuthentication` alias
  behavior, and mixed-case scalar normalization as separate observable
  OpenSSH login-policy behaviors.
- Split the remaining broad client advanced row into named include and
  positive `Match` rows.  Focused `ssh -G` coverage now proves direct include
  globs, environment-expanded include globs, nested include globs,
  case-sensitive include wildcard matching, and positive `Match` criteria
  feed login identity policy as separate observable OpenSSH behaviors.
- Split client file-derived tag and canonicalization coverage out of the broad
  advanced row.  Focused `ssh -G` rows now prove `Tag` directives feed
  `Match tagged` login policy selection, while canonicalization plus final and
  canonical `Match` criteria resolve identity candidates the way OpenSSH does,
  with existing local parser coverage for those same boundaries.
- Split client command-line `IgnoreUnknown` coverage out of the broad advanced
  row.  Focused `ssh -G` rows now prove exact and wildcard
  command-line `IgnoreUnknown` patterns suppress unknown login directives
  before later command-line overrides feed login policy, with existing local
  parser coverage for the same override boundary.
- Split client command-line tag coverage out of the broad advanced row.
  Focused `ssh -G` coverage now proves `ssh -P`-style initial tags select
  `Match tagged` login policy before file-derived identity candidates are
  resolved, with existing local parser coverage for the same initial-tag
  boundary.
- Split client command-line override coverage out of the broad advanced row.
  Focused `ssh -G` coverage now proves `-o` options override target user,
  hostname, port, method controls, identity files, and certificate files before
  matching file values feed login policy, with local parser coverage for the
  same override and append boundary.
- Pin server authorization-file `none` sentinels.  Focused `sshd -T` rows now
  prove `TrustedUserCAKeys none`, `AuthorizedPrincipalsFile none`, and
  `RevokedKeys none` disable their file lookups in resolved OpenSSH login
  policy, with local parser coverage for the same top-level sentinels.
- Pin server authorization-helper quoted argument parsing.  Focused `sshd -T`
  rows now prove quoted and backslash-escaped
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` arguments resolve
  through OpenSSH helper parsing, with local parser coverage for the same argv
  boundary.
- Pin server authorization-helper `none` command-user boundary.  Focused
  `sshd -T` rows now prove `AuthorizedKeysCommand none` and
  `AuthorizedPrincipalsCommand none` disable their helpers without requiring
  command-user directives, with local parser coverage for the same resolved
  config boundary.
- Split server authorization-helper missing-command-user rows.  Focused
  `sshd -T` rows now prove `AuthorizedKeysCommand` and
  `AuthorizedPrincipalsCommand` fail closed when their required command-user
  directives are absent, matching the existing helper authorization tests that
  skip command-sourced key or certificate login without a configured helper
  user.
- Split server authorization-helper relative-command rows.  Focused
  `sshd -T` rows now prove relative `AuthorizedKeysCommand` and
  `AuthorizedPrincipalsCommand` paths fail closed before helper-backed key or
  certificate authorization can influence login, with local parser coverage
  for the same config errors.
- Split server boolean login-policy invalid-value rows.  Focused `sshd -T`
  rows now prove invalid `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, `PermitEmptyPasswords`, `UsePAM`, and
  `StrictModes` values fail closed before method, empty-password, PAM, or
  strict-mode policy can influence login, with local parser coverage for the
  same config errors.
- Reject OpenSSH-invalid server `PubkeyAuthentication` modes.  Focused
  `sshd -T` rows now prove server-side `unbound` and `host-bound` values fail
  closed before public-key method policy can influence login, with local
  parser coverage corrected to match OpenSSH.
- Pin server `ChallengeResponseAuthentication` alias behavior.  Focused
  `sshd -T` rows retain the alias only as an off-scope method-selection
  guardrail, while invalid alias boolean, value, missing-argument, and
  extra-argument forms fail closed before method policy can influence login,
  with local parser coverage for the same config errors.
- Split client transport, connection-setup, and diagnostics extra-argument
  rows.  Focused `ssh -G` rows now prove extra `Ciphers`,
  `KexAlgorithms`, `MACs`, `Compression`, `ConnectionAttempts`,
  `ConnectTimeout`, `ControlMaster`, `ControlPersist`, `IPQoS`,
  `RekeyLimit`, `ServerAliveCountMax`, `ServerAliveInterval`,
  `SyslogFacility`, and `TCPKeepAlive` arguments fail closed before transport
  protection, liveness, or connection setup policy can influence login, with
  local parser coverage for the same config errors.
- Split client canonicalization, config-selection, and key-algorithm
  extra-argument rows.  Focused `ssh -G` rows now prove extra
  `CanonicalizeHostname`, `CanonicalizeFallbackLocal`,
  `CanonicalizeMaxDots`, `IgnoreUnknown`, `Tag`,
  `PubkeyAcceptedAlgorithms`, `PubkeyAcceptedKeyTypes`,
  `HostbasedAcceptedAlgorithms`, `HostbasedKeyTypes`, `HostKeyAlgorithms`,
  and `CASignatureAlgorithms` arguments fail closed before canonical host,
  config selection, or key algorithm policy can influence login, with local
  parser coverage for the same config errors.
- Split client authentication-method extra-argument rows.  Focused `ssh -G`
  rows now prove extra `GSSAPIAuthentication`, `GSSAPIKeyExchange`,
  `GSSAPIDelegateCredentials`, `GSSAPITrustDNS`,
  `GSSAPIRenewalForcesRekey`, `GSSAPIKexAlgorithms`,
  `PubkeyAuthentication`, `HostbasedAuthentication`, `EnableSSHKeysign`,
  `PasswordAuthentication`, `KbdInteractiveAuthentication`,
  `ChallengeResponseAuthentication`, `KbdInteractiveDevices`, and
  `PreferredAuthentications` arguments fail closed before method and
  key-exchange policy can influence login, with local parser coverage for the
  same config errors.
- Split client host-trust extra-argument rows.  Focused `ssh -G` rows now
  prove extra `HostKeyAlias`, `VerifyHostKeyDNS`,
  `StrictHostKeyChecking`, `FingerprintHash`, `RequiredRSASize`,
  `CheckHostIP`, `NoHostAuthenticationForLocalhost`, `UpdateHostKeys`, and
  `HashKnownHosts` arguments fail closed before host-trust policy can
  influence login, with local parser coverage for the same config errors.
- Split client identity and prompt extra-argument rows.  Focused `ssh -G`
  rows now prove extra `IdentitiesOnly`, `IdentityAgent`, `PKCS11Provider`,
  `SecurityKeyProvider`, `AddKeysToAgent`, `BatchMode`, and
  `NumberOfPasswordPrompts` arguments fail closed before identity source,
  agent/provider, or non-interactive prompt policy can influence login, with
  local parser coverage for the same config errors.
- Split client login-target and routing extra-argument rows.  Focused
  `ssh -G` rows now prove extra `User`, `HostName`, `Port`,
  `AddressFamily`, `BindAddress`, and `BindInterface` arguments fail closed
  before target-user, target-host, port, address-family, or source binding
  policy can influence login, with local parser coverage for the same config
  errors.
- Split client path and host-trust invalid rows.  Focused `ssh -G` rows now
  prove extra `IdentityFile`, `CertificateFile`, and `RevokedHostKeys`
  arguments, plus mixed `UserKnownHostsFile none` and
  `GlobalKnownHostsFile none` lists, fail closed before identity selection or
  host-trust policy can influence login, with local parser coverage for the
  same config errors.
- Split client canonicalization value rows.  Focused `ssh -G` rows now prove
  invalid `CanonicalizeHostname`, `CanonicalizeFallbackLocal`,
  `CanonicalizeMaxDots`, `CanonicalDomains`, and
  `CanonicalizePermittedCNAMEs` values fail closed before canonical host and
  match policy can influence login, with local parser coverage for the same
  config errors.
- Split client connection, transport, and diagnostics value rows.  Focused
  `ssh -G` rows now prove invalid `ConnectionAttempts`, `ConnectTimeout`,
  `ControlMaster`, `ControlPersist`, `Compression`, `IPQoS`, `RekeyLimit`,
  `ServerAliveCountMax`, `ServerAliveInterval`, `TCPKeepAlive`, `LogLevel`,
  `LogVerbose`, and `SyslogFacility` values fail closed before connection
  setup, transport/liveness, or diagnostic policy can be used around login, with
  local parser coverage for the same config errors.
- Split client host-trust scalar value rows.  Focused `ssh -G` rows now prove
  invalid `VerifyHostKeyDNS`, `StrictHostKeyChecking`, `RequiredRSASize`,
  `CheckHostIP`, `NoHostAuthenticationForLocalhost`, `UpdateHostKeys`, and
  `HashKnownHosts` values fail closed before host-key trust policy can be used,
  with local parser coverage for the same config errors.
- Split client authentication-method value rows.  Focused `ssh -G` rows now
  prove invalid `GSSAPIAuthentication`, `GSSAPIKeyExchange`,
  `GSSAPIDelegateCredentials`, `GSSAPITrustDNS`,
  `GSSAPIRenewalForcesRekey`, `PubkeyAuthentication`,
  `HostbasedAuthentication`, `EnableSSHKeysign`, `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, and `ChallengeResponseAuthentication` values
  fail closed before login method policy is resolved, with local parser coverage
  for the same config errors.
- Split client login-target and identity value rows.  Focused `ssh -G` rows now
  prove invalid `Port`, `AddressFamily`, `IdentitiesOnly`, `IdentityAgent`,
  `AddKeysToAgent`, `BatchMode`, and `NumberOfPasswordPrompts` values fail
  closed before login routing, identity selection, and signing-prompt policy can
  be used, with local parser coverage for the same config errors.
- Split client diagnostics missing-argument rows.  Focused `ssh -G` rows now
  prove bare `LogLevel`, `LogVerbose`, and `SyslogFacility` directives fail
  closed before client diagnostics policy can be used around login, with local
  parser coverage for the same config errors.
- Split client transport/liveness missing-argument rows.  Focused `ssh -G`
  rows now prove bare `Compression`, `IPQoS`, `RekeyLimit`,
  `ServerAliveCountMax`, and `TCPKeepAlive` directives fail closed before
  transport and keepalive policy can be used around login, with local parser
  coverage for the same config errors.
- Split client connection-setup missing-argument rows.  Focused `ssh -G` rows
  now prove bare `ConnectionAttempts`, `ConnectTimeout`, `ControlPath`, and
  `ControlPersist` directives fail closed before fresh or multiplexed client
  login paths can be used, with local parser coverage for the same config
  errors.
- Split client config-selection missing-argument rows.  Focused `ssh -G` rows
  now prove bare `IgnoreUnknown` and `Tag` directives fail closed before unknown
  directive suppression or `Match tagged` selection can affect login policy,
  with local parser coverage for the same config errors.
- Split client transport-algorithm missing-argument rows.  Focused `ssh -G`
  rows now prove bare `Ciphers`, `KexAlgorithms`, and `MACs` directives fail
  closed before SSH transport protection can be selected, with local parser
  coverage for the same config errors.
- Split client identity-selection missing-argument rows.  Focused `ssh -G`
  rows now prove bare `IdentitiesOnly` and `BatchMode` directives fail closed
  before agent filtering and non-interactive private-key fallback policy can be
  used, with local parser coverage for the same config errors.
- Split client canonicalization missing-argument rows.  Focused `ssh -G` rows
  now prove bare `CanonicalizeHostname`, `CanonicalizeFallbackLocal`,
  `CanonicalizeMaxDots`, `CanonicalDomains`, and
  `CanonicalizePermittedCNAMEs` directives fail closed before canonical host
  and match policy can influence login, with local parser coverage for the same
  config errors.
- Split client auth-adjacent missing-argument rows.  Focused `ssh -G` rows now
  prove bare `GSSAPIDelegateCredentials`, `GSSAPITrustDNS`,
  `GSSAPIRenewalForcesRekey`, `EnableSSHKeysign`,
  `PasswordAuthentication`, `KbdInteractiveAuthentication`,
  `ChallengeResponseAuthentication`, and `KbdInteractiveDevices` directives
  fail closed before login method and helper policy can be used, with local
  parser coverage for the same config errors.
- Split client host-trust scalar missing-argument rows.  Focused `ssh -G`
  rows now prove bare `VerifyHostKeyDNS`, `StrictHostKeyChecking`,
  `FingerprintHash`, `RequiredRSASize`, `CheckHostIP`,
  `NoHostAuthenticationForLocalhost`, `UpdateHostKeys`, and `HashKnownHosts`
  directives fail closed before host-key trust policy can be used, with local
  parser coverage for the same config errors.
- Split client key-algorithm missing-argument rows.  Focused `ssh -G` rows now
  prove bare `GSSAPIKexAlgorithms`, `PubkeyAcceptedAlgorithms`,
  `PubkeyAcceptedKeyTypes`, `HostbasedAcceptedAlgorithms`,
  `HostbasedKeyTypes`, `HostKeyAlgorithms`, and `CASignatureAlgorithms`
  directives fail closed before client key, hostbased, host-key, and CA
  algorithm policy can be used, with local parser coverage for the same config
  errors.
- Split client routing/source missing-argument rows.  Focused `ssh -G` rows now
  prove bare `AddressFamily`, `BindAddress`, `BindInterface`, `ProxyJump`, and
  `ProxyCommand` directives fail closed before login routing and host-context
  policy can be used, with local parser coverage for the same config errors.
- Split client identity-source missing-argument rows.  Focused `ssh -G` rows
  now prove bare `IdentityAgent`, `PKCS11Provider`, `SecurityKeyProvider`,
  `AddKeysToAgent`, and `NumberOfPasswordPrompts` directives fail closed before
  identity source and signing-prompt policy can be used, with local parser
  coverage for the same config errors.
- Split client authentication-method missing-argument rows.  Focused `ssh -G`
  rows now prove bare `GSSAPIAuthentication`, `GSSAPIKeyExchange`,
  `PubkeyAuthentication`, `HostbasedAuthentication`, and
  `PreferredAuthentications` directives fail closed before login method policy
  is resolved, with local parser coverage for the same config errors.
- Split client host-trust missing-argument rows.  Focused `ssh -G` rows now
  prove bare `HostKeyAlias`, `RevokedHostKeys`, `KnownHostsCommand`,
  `UserKnownHostsFile`, and `GlobalKnownHostsFile` directives fail closed
  before host-trust policy can be used, with local parser coverage for the
  same config errors.
- Split client login-target and identity missing-argument rows.  Focused
  `ssh -G` rows now prove bare `User`, `HostName`, `Port`, `IdentityFile`,
  and `CertificateFile` directives fail closed before login policy is
  resolved, with local parser coverage for the same config errors.
- Split client parser-boundary failure rows for `Host` and quoting.  Focused
  `ssh -G` rows now prove a bare `Host` directive and unterminated client
  config quoting fail closed before login policy is resolved, with local parser
  coverage for both config errors.
- Split client `Match localnetwork` invalid-form rows.  Focused `ssh -G` rows
  now prove out-of-range CIDR prefixes and negated CIDR list entries fail
  closed before login policy is resolved, with local parser coverage for the
  same network-list validation failures.
- Split client `Match` missing-criteria rows.  Focused `ssh -G` rows now prove
  missing `host`, `originalhost`, `user`, `localuser`, `localnetwork`, and
  `tagged` criteria fail closed before login policy is resolved, with local
  parser coverage for the same missing-argument classes.
- Split high-risk client `Match` malformed-config rows.  Focused `ssh -G` rows
  now prove empty `Match`, missing `Match exec` command text, unknown
  attributes, and illegal `Match all` combinations fail closed before login
  policy is resolved, with local parser coverage for the same failure classes.
- Pin client `Include` missing-argument failure.  A focused `ssh -G` row now
  proves `Include` without a path fails closed before later login policy can be
  resolved, with local parser coverage for the same config error.
- Pin client `Include` scope after nested included `Match` blocks.  Focused
  `ssh -G` rows now prove a `Match` block inside a conditionally included file
  inherits the active `Host` scope and does not leak into later parent-file
  directives, with local parser coverage for the same identity-selection
  boundary.
- Pin `StrictHostKeyChecking no` against `CheckHostIP` mismatches.  The
  host-trust oracle now explicitly proves that an address-form known-hosts
  mismatch still rejects login host authentication even when
  `StrictHostKeyChecking no` would otherwise allow a changed hostname entry.
- Pin `StrictHostKeyChecking no` against unusable `RevokedHostKeys` files.
  The host-trust oracle now explicitly proves that missing, malformed, and
  invalid-KRL revoked host-key files fail closed even when
  `StrictHostKeyChecking no` would otherwise accept an unknown host.
- Pin `StrictHostKeyChecking no` against `RevokedHostKeys` files.  The
  host-trust oracle now explicitly proves that a configured revoked host-key
  file rejects a key even when `StrictHostKeyChecking no` would otherwise
  accept the same key as an unknown host.
- Pin `KnownHostsCommand` host-CA policy against
  `StrictHostKeyChecking no`.  The host-trust oracle now explicitly proves
  that a `KnownHostsCommand` `@cert-authority` result is not bypassed for raw
  host keys or host certificates signed by an unauthorized CA, even when
  `StrictHostKeyChecking no` would otherwise accept an unknown host key.
- Pin `StrictHostKeyChecking no` against configured host-CA policy.  The
  host-trust oracle now explicitly proves that `StrictHostKeyChecking no` does
  not bypass a matching `@cert-authority` known-hosts policy for either raw
  host keys or host certificates signed by an unauthorized CA.
- Pin `StrictHostKeyChecking no` unknown-host behavior.  The host-trust oracle
  now explicitly proves that `StrictHostKeyChecking no` accepts an unknown host
  key when no revocation, command failure, or other hard host-trust failure
  applies.
- Pin strict-host-key acceptance of matching known-host entries.  The
  host-trust oracle now explicitly proves that `StrictHostKeyChecking ask`,
  `yes`, `accept-new`, and `no` all accept a preexisting matching known-hosts
  entry.
- Pin `StrictHostKeyChecking ask` and `yes` changed-host-key behavior.  The
  host-trust oracle now explicitly proves that mismatched known-host entries
  fail closed when OpenSSH would require prompting or strict matching, while
  `StrictHostKeyChecking no` remains the configured override for mismatches.
- Pin `StrictHostKeyChecking ask` and `yes` unknown-host behavior.  The
  host-trust oracle now explicitly proves that unknown host keys fail closed
  when OpenSSH would require prompting or a preexisting known-hosts entry,
  while `accept-new` remains the non-prompting trust-on-first-use mode.
- Pin ssh-agent non-user certificate identity-list parsing.  The
  failure/fallback oracle now proves that host certificates advertised by
  ssh-agent are skipped at the parser boundary without rejecting later usable
  user identities.
- Pin all-or-nothing ssh-agent identity-list parsing.  The failure/fallback
  oracle now proves that an identities reply with a valid first key and an
  invalid later key is rejected without signing with the valid prefix, while
  userauth can still fall back to a configured unencrypted `IdentityFile`.
- Pin truncated ssh-agent identity-list handling.  The failure/fallback oracle
  now proves that an identities reply ending inside a key entry is rejected
  without a sign request, while userauth can still fall back to a configured
  unencrypted `IdentityFile`.
- Pin trailing-data ssh-agent identity-list handling.  The failure/fallback
  oracle now proves that an identities reply containing a valid key entry plus
  extra trailing bytes is rejected without a sign request, while userauth can
  still fall back to a configured unencrypted `IdentityFile`.
- Pin invalid ssh-agent identity-key handling.  The failure/fallback oracle now
  proves that an identities reply advertising a framed but invalid SSH
  public-key blob is rejected without a sign request, while userauth can still
  fall back to a configured unencrypted `IdentityFile`.
- Pin strict security-key SSH signature blob framing.  The SSHKEY token oracle
  now proves that SK signatures include the required OpenSSH flags and counter
  trailer and reject either missing trailer data or extra trailing bytes.
- Pin trailing-data ssh-agent sign-response handling.  The failure/fallback
  oracle now proves that an agent sign reply containing a valid signature
  string or inner signature blob plus extra trailing bytes is rejected, while
  userauth continues to later identities or falls back to the matching
  unencrypted `IdentityFile` when OpenSSH-style ordering permits it.
- Pin OpenSSH default security-key identity selection through ssh-agent.  The
  client identity-selection oracle now proves that default
  `~/.ssh/id_ecdsa_sk.pub` and `~/.ssh/id_ed25519_sk.pub` sidecars contribute
  configured identities in OpenSSH's default order for `IdentitiesOnly yes`
  and can select a matching ssh-agent security-key identity without requiring
  mechanism-side provider prompting.
- Pin `CertificateFile` implicit-sidecar suppression through ssh-agent.  The
  client identity-selection oracle now proves that both an unusable explicit
  `CertificateFile` and `CertificateFile none` suppress an implicit
  `IdentityFile-cert.pub` sidecar when the encrypted `IdentityFile` must sign
  through a matching raw ssh-agent key.
- Pin `IdentityFile none` through `IdentitiesOnly` agent filtering.  The client
  identity-selection oracle now proves that a resolved `IdentityFile none`
  entry contributes no configured keys and prevents an otherwise available
  ssh-agent key from signing when `IdentitiesOnly yes` is set.
- Pin default agent-backed sidecar certificate source reporting.  The
  identity-ordering oracle now proves that an agent-backed default
  `~/.ssh/id_ed25519-cert.pub` candidate keeps its implicit sidecar source path
  and that the matching raw default identity keeps its `IdentityFile` source.
- Pin default implicit-certificate retry to raw agent keys.  The
  identity-ordering oracle now proves that an encrypted default
  `~/.ssh/id_ed25519` with a default `-cert.pub` sidecar can fail certificate
  signing through ssh-agent and still continue to the matching raw default
  agent key without prompting.
- Pin default identity certificates through agent filtering.  The client
  identity-selection oracle now proves that an encrypted default
  `~/.ssh/id_ed25519` plus default `~/.ssh/id_ed25519-cert.pub` can use a
  matching raw ssh-agent key for `IdentitiesOnly yes` certificate login.
- Pin default identity files through agent filtering.  The client
  identity-selection oracle now proves that OpenSSH's built-in default
  `~/.ssh/id_ed25519` path can constrain an `IdentitiesOnly yes` ssh-agent
  login, so unrelated agent identities are skipped before signing.
- Pin `CertificateFile none` through private fallback signing.  The client
  identity-selection oracle now proves that explicit certificate disablement
  suppresses an implicit `IdentityFile-cert.pub` sidecar even when the matching
  unencrypted `IdentityFile` signs locally.
- Pin explicit `CertificateFile` suppression through private fallback signing.
  The client identity-selection oracle now proves that once any explicit
  certificate file is configured, an implicit `IdentityFile-cert.pub` sidecar is
  ignored even when the explicit certificate path is unusable and the matching
  unencrypted `IdentityFile` signs locally.
- Guard the public v1 context-field header against implementation drift.  The
  source-hygiene oracle now compares `include/gss_sshkey.h` field constants
  with the Rust `CONTEXT_*_FIELD` inventory, so SSH integrations using the C
  helper cannot silently lose or gain unsupported field names.
- Pin the documented v1 context-field inventory at the ABI.  The focused
  context-field oracle rows now prove every documented client, server, and
  mechanism-local role field is accepted by `gss_sshkey_set_context_fields()`,
  while the existing negative tests keep malformed and cross-role fields
  fail-closed.
- Add targeted OpenSSH oracle fixture runs.  `make test-openssh-compat` now
  honors `OPENSSH_COMPAT_KIND` and `OPENSSH_COMPAT_FIXTURE`, so a development
  run can execute one compatibility track or one manifest row while still
  validating the full manifest and audit index.
- Fail filtered OpenSSH oracle runs on selected-fixture skips.  A targeted
  `make test-openssh-compat` invocation now fails if the selected runnable row
  cannot execute because its local tool is unavailable, so a handoff check such
  as `known-hosts-trust-revoke-plain` cannot appear to pass by silently
  skipping `cargo`.
- Align default client identity coverage with OpenSSH 10.2.  The client
  `ssh -G` defaults fixture and local default identity lists no longer expect
  `~/.ssh/id_xmss`, matching the current OpenSSH default identity-file output.
- Refresh client oracle edge cases for the current local OpenSSH baseline.
  Invalid `FingerprintHash` coverage now has its own `ssh -G` row so it is not
  hidden behind earlier fatal KEX parsing, and token-expansion checks no longer
  bake in one local account name for `%u`.
- Make the server OpenSSH oracle runnable as an unprivileged user.  Server
  `sshd -T` fixtures now use a generated temporary host key, materialized
  include paths, and default local connection facts, so they do not depend on
  root-readable system host keys or relative include behavior.
- Align server scalar and `PubkeyAuthOptions` coverage with OpenSSH 10.2.
  Server booleans remain case-insensitive for `yes` and `no`, but no longer
  accept `true` or `false`, and `PubkeyAuthOptions` now uses space-separated
  option tokens instead of comma-separated lists.
- Split high-risk server malformed scalar rows in the OpenSSH oracle.
  Boolean aliases for login-relevant `sshd_config` scalars and
  comma-separated `PubkeyAuthOptions` now have focused `sshd -T` fixtures, so
  OpenSSH 10.2 fail-closed behavior is pinned independently instead of only
  through local parser tests.
- Align server parser edge cases with OpenSSH 10.2 accepted output.
  `MaxAuthTries 0` and mixed `AuthorizedKeysFile none .ssh/authorized_keys`
  lists now have `sshd -T` oracle rows and matching local parser behavior, so
  `none` disables authorized-key files only when it is the sole argument.
- Expand server parser oracle coverage for scalar, account-list, and `Match`
  edge cases.  Focused `sshd -T` rows now pin invalid `MaxAuthTries`,
  `LoginGraceTime`, `PermitRootLogin`, `PubkeyAuthOptions`,
  `PubkeyAcceptedAlgorithms`, `AllowUsers`/`DenyUsers` CIDR prefixes, and
  malformed `Match` attributes, while OpenSSH-accepted non-IP slash host
  patterns are accepted locally for user lists and `Match Address` parsing.
- Pin `RequiredRSASize` malformed argument behavior in the server oracle.
  Focused `sshd -T` rows now prove missing, nonnumeric, and extra
  `RequiredRSASize` arguments fail closed, and the local parser enforces the
  same single-argument rule while preserving OpenSSH's low-value clamp.
- Pin server public-key and CA-signature algorithm name validation.  Focused
  `sshd -T` rows now prove unknown `PubkeyAcceptedAlgorithms` names,
  unmatched append patterns, and invalid, missing, or extra
  `CASignatureAlgorithms` values fail closed.  The local parser now validates
  server algorithm rules against OpenSSH-supported names while still allowing
  explicit legacy `ssh-rsa` where OpenSSH 10.2 accepts it.
- Pin server authorization-source missing and arity failures.  Focused
  `sshd -T` rows now prove missing or extra arguments fail closed for
  login-relevant key, certificate, principal, and revocation source directives
  including `AuthorizedKeysFile`, `AuthorizedKeysCommand(User)`,
  `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`,
  `AuthorizedPrincipalsCommand(User)`, and `RevokedKeys`.
- Pin server authorization command `none` sentinel arity.  Focused `sshd -T`
  rows now prove `AuthorizedKeysCommand none extra` and
  `AuthorizedPrincipalsCommand none extra` fail closed because the command
  path must be absolute unless `none` is the sole disabling argument.
- Pin server authentication and account scalar arity failures.  Focused
  `sshd -T` rows now prove missing or extra arguments fail closed for the
  remaining login-relevant boolean controls: `PubkeyAuthentication`,
  `PasswordAuthentication`, `KbdInteractiveAuthentication`,
  `PermitEmptyPasswords`, `UsePAM`, and `StrictModes`.
- Align server `PubkeyAuthOptions` token-list handling and finish nearby
  scalar arity partners.  Focused `sshd -T` rows now prove space-separated
  `PubkeyAuthOptions` tokens and `none` reset behavior, plus missing or extra
  argument failures for `AuthenticationMethods`, `MaxAuthTries`,
  `LoginGraceTime`, `FingerprintHash`, `PermitRootLogin`, and
  `PubkeyAuthOptions`.  The local parser now accepts multi-token
  `PubkeyAuthOptions` without setting a config error.
- Pin server public-key algorithm alias and malformed argument coverage.
  Focused `sshd -T` rows now prove `PubkeyAcceptedKeyTypes` feeds the same
  resolved `pubkeyacceptedalgorithms` output as its modern alias, while missing,
  extra, unknown-name, and unmatched-pattern forms fail closed for both the
  canonical and legacy directive names.
- Pin server CA-signature algorithm modifier behavior.  Focused `sshd -T`
  rows now prove `CASignatureAlgorithms +ssh-rsa` accepts explicit legacy
  signatures, `CASignatureAlgorithms -rsa-*` removes matching RSA SHA-2 names,
  and unmatched append patterns fail closed.
- Pin server `Match Host` empty-pattern behavior.  Focused `sshd -T` rows now
  prove leading and trailing empty host-pattern segments are ignored while real
  positive host patterns still match, unrelated hosts keep global policy, and
  all-empty host-pattern lists leave login policy unchanged.  The local
  resolver keeps all-empty host-pattern lists from matching.
- Pin server `Match RDomain` empty-pattern behavior.  Focused `sshd -T` rows
  now prove leading and trailing empty routing-domain pattern segments are
  ignored while real positive patterns still match, unrelated routing domains
  keep global policy, and all-empty routing-domain pattern lists leave login
  policy unchanged.  The local resolver keeps all-empty routing-domain pattern
  lists from matching.
- Pin server `Match LocalAddress` empty-pattern failure.  Focused `sshd -T`
  rows now prove empty local-address pattern segments fail closed, matching the
  local parser's `Match LocalAddress` rejection path.
- Pin server `Match Address` invalid-CIDR failure.  Focused `sshd -T` rows now
  prove malformed address CIDR prefixes fail closed, matching the local parser's
  `Match Address` rejection path.
- Pin server `Include` missing-argument failure.  Focused `sshd -T` rows now
  prove missing `Include` arguments fail closed before included login policy can
  be skipped, and the local parser records the same config error before include
  expansion.
- Pin server account-list missing-argument failures.  Focused `sshd -T` rows
  now prove missing `AllowUsers`, `DenyUsers`, `AllowGroups`, and
  `DenyGroups` arguments fail closed before account allow/deny policy can be
  applied.
- Align remaining server authentication-method and `Match` parser edge cases
  with OpenSSH 10.2.  The oracle now pins accepted
  `AuthenticationMethods` device suffixes, empty `Match User` pattern
  segments, trailing-comma `Match Host`, bare-negated `Match Group` and
  `Match RDomain`, plus the matching invalid `AuthenticationMethods`,
  scalar missing-argument, boolean-alias, arity, and `Match` forms.  Local
  parser and authorization tests now treat a mixed `AuthorizedKeysFile none`
  list as ordinary path templates while a sole `none` still disables lookup.
- Expose remaining login-relevant workspace tests in the oracle.  The client
  config parser fixture now runs the test proving ordinary non-login
  `ssh_config` directives remain parseable without becoming authentication
  policy, and the source-hygiene fixture now runs the RSA private-component
  cleanup regression.  The only workspace tests still outside the oracle are
  server post-authentication parser checks that the login roadmap deliberately
  excludes.
- Expose KRL helper process policy in the revocation oracle.  The server
  revocation fixture now runs the existing tests proving KRL helper timeout
  cleanup kills the helper process group and helper execution receives only
  the mechanism's minimal OpenSSH subprocess `PATH`.
- Pin production temp-directory source hygiene.  The source-hygiene oracle now
  rejects production `env::temp_dir()` reads, keeping temporary filesystem
  policy out of login code and inside explicit test helpers or typed/config
  boundaries.
- Pin authorized-principals sources before local-user fallback.  The server
  source-order oracle now proves that configured `AuthorizedPrincipalsFile`
  and `AuthorizedPrincipalsCommand` misses suppress implicit local-user
  principal fallback, while disabling those sources still allows the
  certificate's local-user principal to authorize login.
- Pin `AuthorizedPrincipalsFile` non-login stop before command fallback.  The
  server source-order oracle now proves that a matching principals-file entry
  carrying a session restriction fails closed instead of falling through to
  `AuthorizedPrincipalsCommand`, while a non-matching principals-file entry
  still allows command fallback.
- Pin server certificate algorithm policy for command-sourced CAs.  The
  key-algorithm oracle now proves that `CASignatureAlgorithms` and
  certificate-subject `RequiredRSASize` gate certificates authorized through
  `AuthorizedKeysCommand` `cert-authority` output.
- Pin server revocation policy for command-sourced keys and certificates.  The
  revocation oracle now proves that `RevokedKeys` denies a key returned by
  `AuthorizedKeysCommand`, denies certificates authorized through command
  `cert-authority` output when the subject key or CA key is revoked, and lets
  the same command source authorize login when `RevokedKeys none` is set.
- Pin server algorithm policy for command-sourced keys.  The key-algorithm
  oracle now proves that `PubkeyAcceptedAlgorithms` and `RequiredRSASize`
  gate keys returned by `AuthorizedKeysCommand`.
- Pin server security-key policy for command-sourced keys and certificates.
  The server security-key oracle now proves that `PubkeyAuthOptions` gates
  user-presence and user-verification checks for security keys returned by
  `AuthorizedKeysCommand` and certificates authorized through command
  `cert-authority` output.
- Pin account policy for command-sourced authorized keys and certificates.
  The server account-decision oracle now proves that `DenyUsers` and
  `DenyGroups` reject keys and certificates authorized through
  `AuthorizedKeysCommand`, while allowed users and groups can still log in
  through that command source.
- Pin `AuthorizedKeysFile` non-login stop before command fallback.  The
  server source-order oracle now proves that matching authorized-key and
  certificate-authority file entries carrying session restrictions fail closed
  instead of falling through to `AuthorizedKeysCommand`, while non-matching
  file entries still allow command fallback.
- Pin later agent-certificate fallback after RSA-size filtering.  The
  key-algorithm oracle now proves that an agent-listed user certificate whose
  RSA subject key is rejected by the effective client `RequiredRSASize` floor
  does not block a later agent-listed user certificate from signing.
- Pin later configured-agent-certificate fallback after RSA-size filtering.
  The key-algorithm oracle now proves that a configured certificate backed only
  by ssh-agent whose RSA subject key is rejected by the effective client
  `RequiredRSASize` floor does not block a later configured agent-backed
  certificate from signing.
- Pin later private-certificate fallback after RSA-size filtering.  The
  key-algorithm oracle now proves that a configured private certificate whose
  RSA subject key is rejected by the effective client `RequiredRSASize` floor
  does not block a later configured private certificate from signing.
- Pin later configured-agent-certificate fallback after key-type filtering.
  The key-algorithm oracle now proves that a configured certificate backed only
  by ssh-agent and rejected by resolved `PubkeyAcceptedAlgorithms` does not
  block a later configured agent-backed certificate from signing.
- Pin later configured-agent-certificate fallback after CA-signature filtering.
  The key-algorithm oracle now proves that a configured certificate backed only
  by ssh-agent and rejected by resolved `CASignatureAlgorithms` does not block
  a later configured agent-backed certificate from signing.
- Pin later private-certificate fallback after CA-signature filtering.  The
  key-algorithm oracle now proves that a configured private certificate
  rejected by resolved `CASignatureAlgorithms` does not block a later
  configured private certificate from signing before raw private-key fallback.
- Pin later agent-certificate fallback after CA-signature filtering.  The
  key-algorithm oracle now proves that an agent-listed user certificate
  rejected by resolved `CASignatureAlgorithms` does not block a later
  agent-listed user certificate from signing.
- Pin later agent-certificate fallback after key-type filtering.  The
  key-algorithm oracle now proves that an agent-listed user certificate
  rejected by resolved `PubkeyAcceptedAlgorithms` does not block a later
  agent-listed user certificate from signing.
- Pin fallback between agent-listed certificate identities.  The
  identity-ordering oracle now proves that when one agent-listed user
  certificate fails to sign, userauth continues to a later agent-listed user
  certificate instead of failing before the rest of the agent list is tried.
- Pin later private-certificate fallback after key-type filtering.  The
  identity-ordering oracle now proves that when an earlier configured private
  certificate is rejected by resolved `PubkeyAcceptedAlgorithms`, userauth
  continues to a later configured private certificate before raw private-key
  fallback.
- Pin raw-agent fallback after agent-listed certificate signing failure.  The
  identity-ordering oracle now proves that when ssh-agent lists both a user
  certificate and its matching raw key, a failed certificate signature attempt
  does not block the raw key from signing the same configured identity.
- Pin encrypted implicit-certificate failure fallback to raw agent keys.  The
  identity-ordering oracle now proves that an encrypted `IdentityFile` with an
  implicit `IdentityFile-cert.pub` sidecar can fail certificate signing
  through ssh-agent and still continue to the matching raw agent key without
  prompting.
- Pin encrypted configured-certificate failure fallback to raw agent keys.  The
  identity-ordering oracle now proves that an encrypted `IdentityFile` with a
  configured certificate can fail the certificate signing attempt through
  ssh-agent and still continue to the matching raw agent key without prompting.
- Pin retry across configured certificates backed by one raw agent key.  The
  identity-ordering oracle now proves that when one configured certificate
  backed by a raw ssh-agent key fails to sign, userauth can continue to a
  later configured certificate backed by that same raw agent key.
- Pin configured-certificate raw-agent failure fallback.  The identity-ordering
  oracle now proves that when a raw ssh-agent key backing a configured
  certificate fails to sign, userauth continues to a later configured
  certificate backed by a different raw agent key.
- Pin configured-certificate CA filtering with raw-agent fallback.  The
  key-algorithm oracle now proves that a configured user certificate rejected
  by resolved `CASignatureAlgorithms` does not prevent its matching raw
  agent key from signing the same configured identity.
- Pin same-key raw-agent fallback after certificate key-type filtering.  The
  key-algorithm oracle now proves that an agent-listed user certificate
  rejected by resolved `PubkeyAcceptedAlgorithms` does not consume the
  matching raw agent key for the same configured identity.
- Pin same-key raw-agent fallback after certificate CA-signature filtering.
  The key-algorithm oracle now proves that an agent-listed user certificate
  rejected by resolved `CASignatureAlgorithms` does not consume the matching
  raw agent key for the same configured identity.
- Pin local host-bound signing when agent binding lacks a session signature.
  The session-binding oracle now proves that missing session-bind signature
  context skips ssh-agent without dropping a configured unencrypted
  `IdentityFile` fallback, and that the local signature still binds the
  verified host key and SSH session id.
- Pin local session binding when agent binding lacks a verified host key.  The
  session-binding oracle now proves that missing verified host-key context
  skips ssh-agent without dropping a configured unencrypted `IdentityFile`
  fallback, and that the local signature still binds the supplied SSH session
  id.
- Pin same-identity fallback for destination-constrained agent keys without
  peer context.  The focused destination same-identity row now proves that when
  a
  destination-constrained agent key refuses a non-host-bound signature, the
  same configured unencrypted `IdentityFile` key can still sign locally.
- Pin same-identity fallback after confirmation denial.  The focused
  confirmation-denial same-identity row now proves that when ssh-agent reports
  denial for a
  confirmation-required key, the same configured unencrypted `IdentityFile`
  key can still sign locally under the host-bound transcript.
- Pin private fallback after mismatched agent signature algorithms.  The
  failure/fallback oracle now proves that an ssh-agent response carrying the
  wrong SSH signature algorithm does not block the same configured RSA
  identity's unencrypted private-key fallback with the requested RSA SHA-2
  algorithm.
- Pin private fallback after unverifiable agent signatures.  The
  failure/fallback oracle now proves that a wrong-key ssh-agent signature for
  a configured identity does not block that same identity's unencrypted
  private-key fallback.
- Pin private fallback after agent-certificate signing failure.  The
  identity-ordering oracle now proves that an agent-listed user certificate
  matching a configured raw `IdentityFile` can fail to sign without blocking
  the later unencrypted private-key fallback for that same identity.
- Pin agent fallback after certificate CA-signature filtering.  The
  key-algorithm oracle now proves that an agent-listed user certificate
  rejected by resolved `CASignatureAlgorithms` does not block a later
  configured raw agent key from signing.
- Pin raw-key fallback after certificate CA-signature filtering.  The
  key-algorithm oracle now proves that explicit and implicit user certificates
  rejected by resolved `CASignatureAlgorithms` do not suppress a valid
  unencrypted `IdentityFile` raw-key fallback.
- Pin non-user certificate fallback behavior.  The private-key fallback oracle
  now proves that host certificates found through either an implicit
  `IdentityFile-cert.pub` sidecar or an explicit `CertificateFile` are skipped
  without suppressing a valid unencrypted `IdentityFile` raw-key fallback.
- Pin symlinked implicit `IdentityFile-cert.pub` sidecar behavior.  The
  private-key fallback oracle now proves that an implicit certificate sidecar
  may be a symlink whose resolved target is a valid user certificate, while
  the signer remains the matching unencrypted `IdentityFile` private key.
- Pin unusable implicit `IdentityFile-cert.pub` fallback behavior.  The
  private-key fallback oracle now proves that malformed, directory, and
  dangling implicit certificate sidecars are skipped without suppressing a
  valid unencrypted `IdentityFile` raw-key fallback.
- Pin unusable `IdentityFile.pub` sidecar fallback for valid identities.  The
  private-key fallback oracle now proves that dangling symlink and directory
  public-key sidecars are ignored when the configured private `IdentityFile` is
  a valid unencrypted OpenSSH key, leaving the embedded public key and local
  fallback signer usable.
- Pin malformed `IdentityFile.pub` sidecar rejection for malformed identities.
  The identity-ordering oracle now proves that a malformed configured
  private-key file with a malformed `IdentityFile.pub` sidecar contributes no
  configured key, so `IdentitiesOnly` prevents an otherwise available agent key
  from signing.
- Pin non-regular `IdentityFile.pub` sidecar rejection.  The
  identity-ordering oracle now proves that a malformed configured private-key
  file with an `IdentityFile.pub` directory contributes no configured key, so
  `IdentitiesOnly` prevents an otherwise available agent key from signing.
- Pin broken `IdentityFile.pub` symlink sidecar rejection.  The
  identity-ordering oracle now proves that a malformed configured private-key
  file with a dangling `IdentityFile.pub` symlink contributes no configured
  key, so `IdentitiesOnly` prevents an otherwise available agent key from
  signing.
- Pin symlinked `IdentityFile.pub` sidecar discovery.  The identity-ordering
  oracle now proves that a malformed configured private-key file can still
  contribute a symlinked `IdentityFile.pub` public key for `IdentitiesOnly`
  agent filtering, while contributing no local private-key fallback signer.
- Pin malformed `IdentityFile.pub` sidecar fallback behavior.  The
  private-key fallback oracle now proves that a malformed public-key sidecar is
  ignored when the configured private `IdentityFile` itself is a valid
  unencrypted OpenSSH key, so the embedded public key and local fallback signer
  remain usable.
- Pin `.pub` sidecar use for malformed `IdentityFile` entries.  The
  identity-ordering oracle now proves that a malformed configured private-key
  file can still contribute its `IdentityFile.pub` public key for
  `IdentitiesOnly` agent filtering, while contributing no local private-key
  fallback signer.
- Pin malformed `CertificateFile` fallback behavior.  The private-key fallback
  oracle now proves that a regular explicit certificate file whose contents do
  not parse as an OpenSSH user certificate is skipped without suppressing a
  valid unencrypted `IdentityFile` raw-key fallback.
- Pin broken `CertificateFile` symlink fallback behavior.  The private-key
  fallback oracle now proves that an explicit certificate path whose symlink
  target is missing is skipped without suppressing a valid unencrypted
  `IdentityFile` raw-key fallback.
- Pin symlinked `CertificateFile` target rejection.  The private-key fallback
  oracle now proves that an explicit certificate path whose symlink target is
  not a regular certificate is skipped without suppressing a valid unencrypted
  `IdentityFile` raw-key fallback.
- Pin symlinked `CertificateFile` fallback behavior.  The private-key fallback
  oracle now proves that an explicit certificate path may be a symlink whose
  resolved target is a valid user certificate, while the signer remains the
  matching unencrypted `IdentityFile` private key.
- Pin non-regular `CertificateFile` fallback behavior.  The private-key
  fallback oracle now proves that a non-regular explicit certificate path is
  skipped before parsing while a valid unencrypted `IdentityFile` still
  contributes the raw key and signs.
- Pin private implicit sidecar certificate source reporting.  The
  identity-ordering oracle now proves that when an unencrypted `IdentityFile`
  backs an implicit `IdentityFile-cert.pub` certificate, the private
  certificate candidate reports both the sidecar source path and the private
  identity-file path.
- Pin private `CertificateFile` source reporting for unencrypted fallback.
  The identity-ordering oracle now proves that when an unencrypted
  `IdentityFile` backs an explicit configured certificate, the private
  certificate candidate reports both the `CertificateFile` source path and the
  private identity-file path.
- Pin implicit sidecar certificate source reporting for agent-backed
  certificates.  The identity-ordering oracle now proves that when a raw
  ssh-agent key backs an implicit `IdentityFile-cert.pub` certificate, the
  candidate still reports the sidecar source path instead of losing that
  OpenSSH origin.
- Pin explicit `CertificateFile` source reporting for agent-backed
  certificates.  The identity-ordering oracle now proves that when a raw
  ssh-agent key backs a configured certificate, the candidate still reports
  the configured `CertificateFile` source path instead of losing that OpenSSH
  origin.
- Pin non-interactive encrypted `IdentityFile` behavior without an agent.  The
  identity-ordering oracle now proves that an encrypted configured identity can
  contribute its public key for policy, but with `IdentityAgent none` it
  produces no private fallback signature even when `BatchMode no` and
  `NumberOfPasswordPrompts` would allow prompting in a normal SSH client.
- Record provider-backed identity loading as explicit live oracle gaps.  The
  manifest and audit now track PKCS#11 and security-key provider identities as
  non-runnable live-login gaps until a harness can supply provider-backed
  credentials through the SSH transport path.
- Record known-hosts update writes as explicit live oracle gaps.  The manifest
  and audit now track `UpdateHostKeys` writes and `HashKnownHosts` update
  hashing as non-runnable live-login gaps until an SSH integration can apply
  OpenSSH-compatible known-hosts updates after host-key verification.
- Record PAM and platform account checks as explicit live oracle gaps.  The
  manifest and audit now track PAM and platform account policy as non-runnable
  live-login gaps until a harness can supply the account-management context
  that `sshd` uses before public-key login succeeds.
- Pin signing-path deduplication for agent-listed certificates.  The
  identity-ordering oracle now proves that if an agent-listed certificate
  matches both a configured certificate and the raw configured key, the
  initiator does not retry that same certificate through the raw-key alias
  before moving to the next agent identity.
- Deduplicate agent-listed certificates that also match raw configured keys.
  The identity-ordering oracle now proves that an agent-listed certificate is
  not offered twice when policy contains both the configured certificate and
  its matching raw `IdentityFile` key, while `IdentitiesOnly` still keeps the
  certificate usable through the configured key set.
- Pin `KnownHostsCommand` revocation precedence.  The host-trust oracle now
  proves that a helper-emitted `@revoked` entry rejects a host key even when a
  configured known-hosts file trusts the same key and `StrictHostKeyChecking`
  is `no`.
- Pin literal `GlobalKnownHostsFile` paths in host trust.  The host-trust edge
  oracle now proves that a global known-hosts path containing `%h` is used
  literally, while the would-be expanded path is ignored.
- Pin `CheckHostIP` IPv6 non-standard-port address lookup.  The host-trust
  edge oracle now proves that a supplied IPv6 peer address uses the
  `[addr]:port` known-hosts spelling when `CheckHostIP` is enabled and the
  SSH target uses a non-standard port.
- Pin agent-listed certificate source reporting for configured raw identities.
  The identity-ordering oracle now proves that an `IdentitiesOnly` agent
  certificate accepted through a matching raw `IdentityFile` reports that raw
  identity-file source in the candidate plan.
- Pin sparse default identity ordering at the initiator policy layer.  The
  client identity-selection oracle now proves that OpenSSH's built-in default
  path list skips absent files, preserves `id_rsa`, `id_ecdsa`, and
  `id_ed25519` order, and inserts an implicit `id_ed25519-cert.pub` sidecar
  before the matching raw default key.
- Pin default `IdentityFile` certificate sidecar loading at the initiator
  policy layer.  The client identity-selection oracle now proves that
  OpenSSH's default `~/.ssh/id_ed25519-cert.pub`, resolved through the typed
  home context, is ordered before the matching raw default key and drives the
  first non-agent signature.
- Pin default `IdentityFile` loading at the initiator policy layer.  The client
  identity-selection oracle now proves that OpenSSH's default
  `~/.ssh/id_ed25519` path, resolved through the typed home context, contributes
  a public identity key, configured identity record, private fallback identity,
  and non-agent signature.
- Pin `IdentityFile none` at the initiator policy layer.  The client
  identity-selection oracle now proves a resolved `IdentityFile none` entry
  contributes no public identity keys, configured identity records, private
  fallback identities, or non-agent signature.
- Pin broken helper safe-path symlink rejection.  The server authorization
  helper oracle now proves that a configured helper symlink with no resolvable
  canonical target fails closed before any helper command can run.
- Pin helper safe-path non-regular target rejection.  The server authorization
  helper oracle now pairs canonical helper-target acceptance with a fail-closed
  case proving that a configured helper symlink whose resolved target is a
  directory cannot run.
- Pin non-regular private `IdentityFile` symlink-target rejection.  The
  private-key fallback oracle now proves that a configured identity symlink
  resolving to a directory yields no public key, no private fallback identity,
  and no non-agent signature.
- Pin broken private `IdentityFile` symlink rejection.  The private-key fallback
  oracle now proves a dangling configured identity symlink yields no public key,
  no private fallback identity, and no non-agent signature.
- Pin OpenSSH server login-method scalar parity.  The `sshd -T` oracle now
  covers global, `Match`, and mixed-case `PasswordAuthentication` and
  `KbdInteractiveAuthentication` handling alongside the local parser's
  login-scalar assertions.
- Pin symlinked private `IdentityFile` target-mode rejection.  The private-key
  fallback oracle rows now pair the accepted symlink case with a
  fail-closed case proving that mode checks apply to the resolved target before
  private fallback signing can use the key.
- Pin symlinked private `IdentityFile` fallback behavior.  The private-key
  fallback oracle rows now prove that a configured identity path may
  be a symlink when its resolved target is a regular private-key file that
  passes the same owner-sensitive mode checks used for direct files.
- Pin missing `KnownHostsCommand` helper fail-closed behavior.  The host-trust
  oracle now proves that a configured known-hosts helper that cannot be
  spawned is treated as a host-trust failure rather than an unknown-host
  fallback.
- Pin KRL helper unavailability fail-closed behavior.  The server revocation
  oracle now proves that OpenSSH KRL revocation checks fail closed when the
  configured `ssh-keygen -Q` helper cannot be spawned.
- Pin helper safe-path canonical-target behavior.  The server authorization
  helper oracle now proves that helper program safety follows OpenSSH's
  canonical target check: a symlink in an unsafe directory is accepted when it
  resolves to a safe system-owned executable.
- Pin unavailable `IdentityAgent` socket behavior in the oracle.  The
  failure/fallback fixture now proves that an unconnectable agent socket skips
  agent signing, then either falls back to a configured unencrypted
  `IdentityFile` or fails closed when no later credential is available.
- Pin explicit `CertificateFile` suppression of implicit sidecars.  The
  client identity-selection oracle now proves that configuring any explicit
  certificate path suppresses the implicit `IdentityFile-cert.pub` sidecar,
  even when the explicit certificate cannot be loaded, matching OpenSSH's
  identity-loading rule.
- Expand private IdentityFile mode coverage in the oracle.  The private-key
  fallback oracle rows now pin rejection of current-user private keys with
  group-readable, group-writable, or other-accessible mode bits before private
  fallback signing, while proving that restoring `0600` re-enables the
  unencrypted-key fallback path.
- Pin authorized-principals option edge cases in the oracle.  The certificate
  authorization rows now run exact tests proving authorized-principals entries
  require OpenSSH-style quoted values and reject duplicate exclusive `from` and
  `command` options, matching the local authorized-keys option parser used for
  file and command principal sources.
- Timeout-bound OpenSSH KRL helper queries.  `RevokedHostKeys` and
  `RevokedKeys` KRL checks now run `ssh-keygen -Q` in a helper process group
  with a fixed timeout and constrained OpenSSH subprocess `PATH`, remove the
  temporary query file, and fail closed while killing helper descendants if the
  query does not complete.
- Discover standard OpenSSH oracle tool paths before `PATH` fallback.  The
  compatibility runner now finds common absolute `ssh`, `sshd`, and
  `ssh-keygen` locations, including `/usr/sbin/sshd`, while still honoring
  explicit `SSH_BIN`, `SSHD_BIN`, and `SSH_KEYGEN_BIN` overrides.
- Terminate helper process groups on stdout setup and poll failures.
  `KnownHostsCommand`, `AuthorizedKeysCommand`, and
  `AuthorizedPrincipalsCommand` now kill the helper process group if stdout is
  unexpectedly missing, nonblocking setup fails, child-status polling fails, or
  stdout polling fails before the bounded reader can complete.
- Wipe partial RSA private-key conversion temporaries.  Legacy RSA signing now
  zeroizes cloned private exponent and prime-factor `BigUint` values if a later
  RSA private component cannot be decoded before the `rsa` crate takes
  ownership, with source-hygiene coverage pinning that failure cleanup.
- Kill helper process groups on stdout timeout or reader failure.  OpenSSH-style
  `KnownHostsCommand`, `AuthorizedKeysCommand`, and
  `AuthorizedPrincipalsCommand` helpers now run in their own process group, so
  timeout, excessive-output, and stdout-read failure paths terminate helper
  descendants as well as the direct child.
- Enforce authorization-helper stdout timeouts after direct child exit.
  `KnownHostsCommand`, `AuthorizedKeysCommand`, and
  `AuthorizedPrincipalsCommand` output collection now uses timeout-aware
  nonblocking reads, so a helper descendant that keeps the stdout pipe open
  cannot make the mechanism wait past the configured helper timeout.
- Fail closed on non-root helper command gid mismatch.  Authorized-keys and
  authorized-principals helpers now run only when a non-root mechanism process
  already has both the configured command user's uid and gid; otherwise helper
  execution fails closed instead of running with the wrong group identity.
- Fail closed on malformed helper command-user names.  Authorized-keys and
  authorized-principals helper setup now rejects command-user records whose
  names cannot be passed to POSIX group setup, instead of spawning a helper
  without a valid identity-change hook.
- Pin authorized-key forced-command behavior under root forced-commands-only.
  The login-boundary oracle now proves that an authorized-key forced command
  does not satisfy `PermitRootLogin forced-commands-only` inside the GSS
  mechanism, because command enforcement is outside the plain login decision.
- Expose the authorized_keys parser path for root forced-commands-only.  The
  login-boundary oracle now also runs the test that parses plain and
  command-restricted authorized_keys entries and proves neither satisfies
  `PermitRootLogin forced-commands-only` at the GSS layer.
- Pin certificate forced-command behavior under root forced-commands-only.
  The login-boundary oracle now proves that a user-certificate forced command
  also does not satisfy `PermitRootLogin forced-commands-only`, keeping
  certificate critical-option command enforcement outside the GSS login grant.
- Pin OpenSSH's resolved root forced-commands-only policy.  A focused
  `sshd -T` row now proves `PermitRootLogin forced-commands-only` remains
  distinct from `yes` outside matching overrides, with local resolver coverage
  for the same root-login policy value.
- Make the OpenSSH oracle audit index two-way.  The compatibility runner now
  rejects stale `AUDIT.md` `kind/name` index entries after fixture rows are
  removed or renamed, in addition to rejecting manifest rows that are missing
  from the audit index.
- Tighten OpenSSH oracle audit-index membership.  Manifest rows are now checked
  against the checked-in `## Manifest Row Index` entries themselves, not
  against incidental mentions elsewhere in `AUDIT.md`.
- Add MIT krb5 loader coverage.  `sshkey.so` now exports a MIT
  `gss_mech_initialize` dispatch table, `make install
  GSS_MECH_CONFIG_FORMAT=mit` emits the MIT-parsed `name oid library`
  mechanism line, and `tests/gss-token/run.sh` compiles and runs a MIT krb5
  loader smoke phase through a temporary `GSS_MECH_CONFIG` file when
  `mit-krb5-gssapi` is available through `pkg-config`.
- Refresh the architecture server-policy status.  `ARCHITECTURE.md` no longer
  describes server policy as covering only an early `sshd_config` subset; it
  now summarizes the current login-relevant server configuration,
  authorization-helper, certificate, account, and fail-closed post-auth
  boundary coverage while keeping native KRL parsing, PAM, and live transport
  gaps explicit.
- Discover OpenSSH oracle `gss-token` helpers on `PATH`.  The compatibility
  runner now keeps `/usr/local/bin/gss-token` as the preferred default, then
  falls back to the first `gss-token` on `PATH`, so future live-login and
  loader rows do not remain skipped only because a distribution installs the
  helper somewhere else.
- Discover GSS smoke-test helper tools on `PATH`.  The `gss-token` runner now
  still prefers `/usr/local/bin/gss-token` and `/usr/local/bin/knc`, but falls
  back to `PATH` for explicit helper names and default discovery, allowing the
  external `knc` wrap smoke to run on hosts where `knc` is installed under
  `/usr/bin`.
- Strengthen the installed context-helper header smoke.  The
  `make test-context-helper` target now compiles `gss_sshkey.h` with
  `-Wall -Wextra -Werror`, checks every v1 client, server, local, and
  `env:NAME` field exposed by the public header, and type-checks the public
  setter and clearer helper calls using a per-run temporary object file.
- Make GSS smoke-test phase reporting explicit.  `tests/gss-token/run.sh` now
  labels Heimdal loader, direct `.so` interposition, `gss-token`, and `knc`
  phases separately, validates `COUNT`, repeats the direct interposition phase
  under the same count as the loader loop, and reports how many phases ran
  when local tools are skipped.
- Expose client `ssh_config` parser policy in the oracle.  A new cargo-backed
  compatibility fixture now runs exact parser tests for login-relevant global,
  `Host`, and `Match` client policy, including include files, overrides,
  identity and certificate files, agent selection, host trust,
  canonicalization, algorithm rules, method controls, token expansion, routing
  context, and unknown-directive handling.  Broad post-login directive arity
  coverage remains outside this parser-policy row.
- Expose server `sshd_config` parser policy in the oracle.  A new cargo-backed
  compatibility fixture now runs exact parser tests for login-relevant global
  and `Match` server policy, including include files, overrides, method
  controls, account lists, root policy, strict modes, PAM, revocation,
  authorized-key sources, certificate trust, algorithm rules, and invalid
  login arguments, while leaving post-login session controls out of the row.
- Expose source-hygiene hardening checks in the oracle.  A new cargo-backed
  compatibility fixture now runs the integration tests that keep direct
  process-environment reads inside the adapter boundary and protect
  login-sensitive private-key, config, context, transcript, agent, helper,
  authorization, fingerprint, replay-cache, and random buffers with zeroizing
  storage or cleanup checks.
- Expose remaining in-scope typed-context and identity metadata tests in the
  oracle.  Existing cargo-backed fixtures now also run exact tests proving
  malformed agent-session context fails closed before client login policy, and
  exported source names wrap the authenticated SSH key fingerprint in a GSS
  exported-name token.
- Extend server login edge coverage in the oracle.  Existing cargo-backed
  fixtures now also run exact tests proving authorized-principals `#` comment
  handling feeds certificate authorization, KRL helper scratch files stay under
  the mechanism scratch directory, and empty passwd shells default to
  OpenSSH's Bourne-shell path for account policy.
- Expose mechanism hardening primitives in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests proving random-fill failures wipe
  partial output, successful random fills preserve generated bytes,
  login-sensitive byte comparisons reject mismatches and length differences,
  and GSS output-token handoff copies bytes before local cleanup.
- Expose SSHKEY token-protocol coverage in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests proving initial KEX tokens carry
  public-key, nonce, and algorithm fields, framed initial-token payloads remain
  valid after local DER cleanup, signature-retry tokens carry retry
  algorithms, acceptor KEX tokens are not parsed as retry requests, SSH
  signature blobs reject tampering, and certificate identity blobs verify.
- Expose RFC4121 CFX per-message coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving established
  SSH-key contexts support sealed wrap, signed wrap tamper rejection, MIC
  replay rejection, split IOV wrap, and sign-only IOV authentication.
- Expose signed-ECDH protocol coverage in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests proving X25519 exchange, SP800-108
  session-key derivation, Finished MAC binding, key confirmation, KEX algorithm
  negotiation, malformed KEX rejection, Ed25519 and RSA transcript signing, and
  sealed userauth state support the SSH-key login model.
- Extend client host-trust oracle coverage.  Existing cargo-backed fixtures now
  also run exact tests proving `UpdateHostKeys ask` is preserved, malformed
  host-address and known-hosts context overrides fail closed, hashed host
  patterns match OpenSSH HMAC-SHA1 form, and generated fingerprints match
  OpenSSH SHA256, SHA1, and MD5 formats.
- Extend authorized-keys parser and matcher oracle coverage.  The existing
  cargo-backed compatibility fixture now also runs exact tests proving plain
  key grants, certificate-authority grants, option case-insensitivity, `#`
  handling inside entries, expiry and unknown-option rejection, and malformed
  or host-based `from` patterns feed login authorization.
- Extend ssh-agent identity-list parser oracle coverage.  The existing
  failure/fallback compatibility fixture now also runs exact tests proving
  ssh-agent identity replies parse both public-key and certificate entries
  before later login policy and signing-order decisions.
- Extend method-policy oracle coverage.  The existing client and server
  cargo-backed compatibility fixtures now also run exact tests proving
  unselected client GSSAPI methods fail before token emission,
  `PubkeyAuthentication no` does not suppress internal GSS-SSHKEY key policy,
  and exported client and server policy inquiries report resolved login
  controls.
- Expose client identity-selection coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving implicit
  certificates, explicit certificate preference, non-user certificate
  filtering, `CertificateFile none`, `IdentitiesOnly`, and configured
  agent-certificate pairing feed login policy.
- Expose client path and environment expansion coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving identity,
  certificate, agent, host-trust, include, tilde, and context-captured
  environment expansions feed login policy, while missing required environment
  or tilde values and OpenSSH argument errors fail closed.
- Expose host-trust edge coverage in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests proving user-only known-host path
  token expansion, literal `HostKeyAlias none`, non-standard port fallback,
  resolved-host `KnownHostsCommand` lookups, disabled commands, command stderr
  handling, and `CheckHostIP` address lookups feed known-host decisions.
- Expose client canonicalization coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving hostname
  canonicalization
  feeds resolved login policy, including canonical and final match passes,
  always-on canonicalization, max-dot blocking, fallback-local failure, and
  permitted-CNAME filtering.
- Expose server typed-context policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving host-key,
  session-id, authorized-key override, peer connection, routing-domain, and
  helper-locale context inputs feed acceptor login policy and authorization
  helpers or fail closed at the typed boundary.
- Expose client typed-context policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving client
  target, config-path, local-user, home, agent-socket, host-key,
  session-binding, and inline-config context inputs feed initiator login policy
  or fail closed at the typed boundary.
- Expose source identity metadata coverage in the oracle.  Focused
  cargo-backed rows now run exact tests proving GSS source identities stay tied
  to the authenticated SSH key, with user certificates using the subject key
  fingerprint and carrying serial, key id, principals, and CA fingerprint as
  authorization metadata.
- Expose server authorization-source ordering coverage in the oracle.
  Focused cargo-backed compatibility rows now run exact tests proving acceptor
  authorization sources are tried in OpenSSH login order, including
  authorized-keys before trusted-CA and trusted-CA before
  `AuthorizedKeysCommand`.
- Expose server security-key decision coverage in the oracle.  Focused
  cargo-backed rows now run exact tests proving resolved
  server `PubkeyAuthOptions` gates final acceptor login decisions for
  security-key signatures, including `touch-required` overriding an
  authorized-key `no-touch-required` entry.
- Expose server account-decision coverage in the oracle.  Focused
  cargo-backed rows now run exact tests proving resolved `AllowUsers`,
  `DenyUsers`, `AllowGroups`, and `DenyGroups` policy gates the final acceptor
  login decision after key authorization succeeds.
- Expose server authorized-keys decision coverage in the oracle.  Focused
  cargo-backed rows now run exact tests proving
  `AuthorizedKeysFile` entries feed the acceptor login decision for source
  restrictions, expiry, fail-closed session restrictions,
  and certificate-authority entries.
- Expose server config and `Match` integration coverage in the oracle.  A new
  cargo-backed compatibility fixture now runs exact tests proving typed server
  context, inline server config options, config-path overrides, `Include`, and
  `Match` criteria feed the acceptor login decision or fail closed at the
  boundary.
- Expose server authorization-file coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for `AuthorizedKeysFile`,
  `TrustedUserCAKeys`, and `AuthorizedPrincipalsFile` path expansion, `none`,
  glob handling, tilde-home behavior, and strict-mode policy.
- Expose login-only boundary coverage in the oracle.  A new cargo-backed
  compatibility fixture now runs exact tests proving server post-authentication
  controls are not converted into GSS login grants, while authorization
  sources carrying session restrictions fail closed unless an SSH layer can
  enforce them.
- Expose security-key login-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for user-presence and
  user-verification requirements from server `PubkeyAuthOptions`,
  authorized-key options, authorized-principals options, and user-certificate
  critical options.
- Expose server revocation-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for `RevokedKeys`
  denial of user keys and certificates, including plain key files, KRLs,
  `none`, tilde-home expansion, malformed files, invalid KRLs, and certificate
  subject or CA-key revocation.
- Expose server authorization-helper coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for
  `AuthorizedKeysCommand`, `AuthorizedPrincipalsCommand`, command-user
  requirements, token expansion, safe program checks, stdout limits, invalid
  UTF-8, timeouts, and helper environment.
- Expose key-algorithm policy coverage in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests for client and server algorithm
  defaults, unsupported algorithm filtering, RSA-size floors, CA signature
  filters, and host-key algorithm ordering from known-host inputs.
- Expose client host-trust policy coverage in the oracle.  A new cargo-backed
  compatibility fixture now runs exact tests for known-hosts files, hashed
  names, host-certificate CAs, verified transport host keys, revocation files,
  `KnownHostsCommand`, localhost bypass, `CheckHostIP`, strict-host-key modes,
  and DNS SSHFP record matching.
- Expose server continuation-state coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving replay-id
  derivation, context-key validation and generation, local mechanism adapter
  parsing, continuation-state sealing, `LoginGraceTime` expiry, and replay
  rejection in-process or through the optional shared replay directory.
- Expose server account-policy coverage in the oracle.  Focused cargo-backed
  compatibility rows now run exact tests for root login policy, account allow
  and deny policy, locked or expired accounts, login-shell checks, and
  fail-closed PAM account policy.
- Expose GSS local-name login-authorization coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests proving
  `gss_localname()`, `gss_authorize_localname()`, and authorization inquiry
  reports use matched SSH authorization data and reject denied login results.
- Expose user-certificate login-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for trusted-CA
  authorization, CA signature filtering, revoked certificate keys,
  source-address critical options, authorized-principals files and commands,
  and fail-closed non-login certificate restrictions.
- Expose authorized-keys login-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact tests for `from`,
  `expiry-time`, security-key requirements, certificate-authority principals,
  quoted value syntax, and fail-closed non-login restrictions.
- Expose client GSSAPI method-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run the exact tests proving
  `GSSAPIAuthentication` and `PreferredAuthentications` gate mechanism
  selection while `PubkeyAuthentication no` does not suppress internal
  GSS-SSHKEY user-key signatures.
- Expose server GSSAPI method-policy coverage in the oracle.  Focused
  cargo-backed compatibility rows now run the exact tests proving
  `GSSAPIAuthentication` and `AuthenticationMethods` gate login authorization
  and policy reporting.
- Expose login transcript-binding coverage in the oracle.  Focused
  cargo-backed compatibility rows now run the exact tests proving userauth
  signature inputs bind the requested user, offered key, verified host key,
  and SSH transport session identity.
- Expose client mixed-case authentication scalar coverage in the oracle.
  Focused client fixtures now pin OpenSSH `ssh -G` behavior for mixed-case
  `PubkeyAuthentication`, `GSSAPIAuthentication`, `HostbasedAuthentication`,
  `EnableSSHKeysign`, password, and keyboard-interactive values, matching the
  existing resolver coverage.
- Honor case-insensitive server login scalar values.  The server parser now
  accepts OpenSSH-style mixed-case boolean authentication settings,
  `PubkeyAuthentication` modes, and `PermitRootLogin` values, with resolver
  tests and server oracle coverage.
- Expose explicit SSH context-boundary coverage in the oracle.  Focused
  cargo-backed compatibility rows now run exact v1 context-field tests for
  client, server, local, and login-exchange inputs, including fail-closed
  malformed context cases.
- Extend fake-agent failure oracle coverage.  The failure/fallback fixture now
  runs the exact fail-closed test for agent signatures whose embedded SSH
  signature algorithm does not match the requested signing algorithm.
- Add private-key fallback oracle coverage.  Focused exact-test compatibility
  rows now pin private identity-file fallback signing for ECDSA and
  explicitly enabled DSA keys, RSA-size filtering, OpenSSH-style
  owner-sensitive exposed-key checks, and non-regular identity-file rejection.
- Extend fake-agent signing-algorithm oracle coverage.  Focused retry/RSA
  rows now run exact tests for OpenSSH RSA SHA-2 flag values, acceptor
  signature algorithm filtering, RSA-size filtering, legacy `ssh-rsa`
  fallback, and security-key agent signatures.
- Extend fake-agent identity-ordering oracle coverage.  The agent
  identity-ordering fixture now also runs exact tests for encrypted configured
  certificates backed by ssh-agent, unencrypted private-key and configured
  certificate fallback, private-certificate preference over agent-only keys,
  private-certificate algorithm filtering, and exclusion of raw private-key
  fallback from the agent candidate stage.
- Validate client forwarding and tunnel syntax.  The client config parser now
  accepts ordinary `DynamicForward`, `LocalForward`, `RemoteForward`,
  `PermitRemoteOpen`, `Tunnel`, and `TunnelDevice` directives without applying
  mechanism-side forwarding or tunnel policy from them, while still matching
  OpenSSH's fatal missing, extra, missing target, malformed forwarding, bad
  permit-open port, and malformed tunnel-device behavior.
- Validate client stream-local binding directives.  The client config parser
  now accepts ordinary `StreamLocalBindMask` and `StreamLocalBindUnlink`
  directives without applying mechanism-side stream-local forwarding policy
  from them, while still matching OpenSSH's fatal missing, extra, malformed
  mask, and malformed boolean behavior.
- Validate client gateway-port directives.  The client config parser now
  accepts ordinary `GatewayPorts` directives without applying mechanism-side
  forwarding policy from them, while still matching OpenSSH's fatal missing,
  extra, and malformed boolean behavior.
- Validate client channel timeout directives.  The client config parser now
  accepts ordinary `ChannelTimeout` directives without applying
  mechanism-side session timeout policy from them, while still matching
  OpenSSH's fatal missing, mixed-`none`, and malformed timeout behavior.
- Validate client command directives.  The client config parser now accepts
  ordinary `LocalCommand` and `RemoteCommand` directives without applying
  mechanism-side command or session policy from them, while still matching
  OpenSSH's fatal missing command text and malformed `RemoteCommand` percent
  token behavior.
- Validate client environment-passing directives.  The client config parser now
  accepts ordinary `SendEnv` and `SetEnv` directives without applying
  mechanism-side session environment policy from them, while still matching
  OpenSSH's fatal missing or malformed argument behavior.
- Validate client diagnostic and timing directives.  The client config parser
  now accepts ordinary `LogVerbose` and `ObscureKeystrokeTiming` directives
  without applying mechanism-side authentication policy from them, while still
  matching OpenSSH's fatal missing, mixed-`none`, extra, or malformed argument
  behavior.
- Validate client SSH transport algorithm directives.  The client config parser
  now accepts ordinary `Ciphers`, `MACs`, and `KexAlgorithms` directives
  without applying mechanism-side authentication policy from them, while still
  matching OpenSSH's fatal missing, extra, or malformed algorithm-list
  behavior.
- Validate ancillary client GSSAPI directives.  The client config parser now
  accepts ordinary `GSSAPIKeyExchange`, `GSSAPIDelegateCredentials`,
  `GSSAPITrustDNS`, `GSSAPIRenewalForcesRekey`, and
  `GSSAPIKexAlgorithms` directives, while still matching OpenSSH's fatal
  missing, extra, or malformed argument behavior.
- Validate ignored client diagnostic and transport-tuning directives.  The
  client config parser now accepts ordinary `ControlPersist`,
  `EnableEscapeCommandline`, `EscapeChar`, `IPQoS`, `RekeyLimit`, and
  `SyslogFacility` directives without applying authentication policy from
  them, while still matching OpenSSH's fatal missing, extra, or malformed
  argument behavior.
- Validate ignored client session-control directives.  The client config
  parser now accepts ordinary `ClearAllForwardings`, `ExitOnForwardFailure`,
  `ForkAfterAuthentication`, `PermitLocalCommand`, `ProxyUseFdpass`,
  `RequestTTY`, `SessionType`, `StdinNull`, and `VisualHostKey` directives
  without modeling their post-login effects, while still matching OpenSSH's
  fatal missing, extra, or malformed argument behavior.
- Validate ignored client connection directives.  The client config parser now
  accepts ordinary `Compression`, `ConnectionAttempts`, `ConnectTimeout`,
  `ServerAliveCountMax`, and `TCPKeepAlive` directives without applying
  authentication policy from them, while still matching OpenSSH's fatal
  missing, extra, or malformed argument behavior.
- Validate values for common ignored client directives.  The client config
  parser now rejects OpenSSH-fatal malformed `ControlMaster`, `LogLevel`, and
  `ServerAliveInterval` values without treating those directives as
  mechanism-side authentication policy.
- Validate arity for common ignored client directives.  The client config
  parser now accepts ordinary non-login OpenSSH directives such as
  `ControlMaster`, `ControlPath`, `ForwardAgent`, `ServerAliveInterval`, and
  `LogLevel` without applying authentication policy from them, while still
  failing closed on missing or extra scalar arguments.
- Reject `Match`-scoped OpenSSH global-only server directives.  The
  `sshd_config` parser now treats `UsePAM`, `LoginGraceTime`, `StrictModes`,
  and `FingerprintHash` as global-only, matching OpenSSH directive scope and
  failing closed when any appears inside a `Match` block.
- Honor server `FingerprintHash` for authorization helpers.  The acceptor now
  parses global `sshd_config` `FingerprintHash` and uses it for
  `AuthorizedKeysCommand` `%f` and `AuthorizedPrincipalsCommand` `%f`/`%F`,
  with `%f` for principals helpers matching OpenSSH's certificate-key
  fingerprint rather than the certificate subject-key fingerprint.
- Treat empty user-certificate `force-command` as non-login policy.  The
  certificate authorization path now matches OpenSSH's acceptance of an empty
  forced-command string and carries it as a session restriction that fails
  closed for login, including through trusted-CA authorization.
- Tighten authorized-key option parsing against OpenSSH auth-options syntax.
  Value-bearing authorized-key and authorized-principals options now require
  quoted values, reject duplicate exclusive `from` and `command` clauses,
  stop `cert-authority` `principals` matching at the first empty list entry,
  validate `environment`, `permitopen`, `permitlisten`, and `tunnel` session
  values before fail-closed classification, preserve OpenSSH slash-delimited
  and empty-host permit syntax, and treat empty `command=""` as a valid
  non-login session restriction.
- Enforce OpenSSH-style login-shell account policy.  Server authorization now
  rejects target users whose resolved login shell is missing, not a regular
  file, or has no execute bits, with regressions for executable, non-executable,
  directory, and missing shell paths.
- Drop authorization-helper real, effective, and saved ids on Linux.  The
  shared `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` runner now
  uses `setresgid()` and `setresuid()` after `initgroups()` when executing as
  root, with a source-hygiene regression that keeps saved-id cleanup in place.
- Match OpenSSH `AuthorizedPrincipalsCommand` no-argument behavior.  The
  principals helper no longer inherits the `AuthorizedKeysCommand` legacy
  default username argument; it now executes exactly the configured argv when
  no command arguments are present, with separate regressions for the keys and
  principals helpers.
- Align server authorization-helper environment with OpenSSH.  The shared
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` runner now clears
  inherited process variables and supplies only `PATH`, `USER`, `LOGNAME`,
  `HOME`, and inherited `LANG`, with regressions proving that `SHELL` and
  arbitrary `LC_*` values are not propagated.
- Record implicit-certificate fallback as a live OpenSSH oracle gap.  The
  manifest and audit now track OpenSSH's raw-key rejection followed by
  implicit `IdentityFile` `-cert.pub` retry as a transport-dependent live
  login gap, and the README plus architecture notes no longer overstate
  current candidate-ordering parity.
- Cover encrypted `IdentityFile` backed certificate signing through ssh-agent.
  Client regressions now pin that an encrypted configured private key can
  contribute public identity material for explicit `CertificateFile` pairing,
  remains excluded from unencrypted private-key fallback, and signs by asking
  ssh-agent for the matching raw key.
- Expand `StrictModes` directory coverage.  Local `authorized_keys` and
  authorized-principals regression tests now pin that unsafe home and
  containing directories are rejected for login under `StrictModes yes`, while
  `StrictModes no` bypasses those path-mode checks.
- Pin server `UsePAM` in the OpenSSH oracle.  The `sshd -T` server baseline
  fixture now sets and expects `usepam yes`, and the oracle audit records that
  the basic server row covers `UsePAM` account policy.
- Fail closed on server `UsePAM` account policy.  Resolved `UsePAM yes` now
  prevents mechanism-side user-key authorization until a real PAM
  account-management integration exists, with focused account-policy and
  resolved `sshd_config` authorization coverage plus README and architecture
  documentation.
- Record the OpenSSH oracle host baseline.  The compatibility runner now
  prints the host operating system and kernel before tool paths and OpenSSH
  versions, and the oracle README plus manifest audit describe OS/kernel data
  as part of the version-sensitive compatibility baseline.
- Guard the private state-protector boundary.  Source-hygiene coverage now
  rejects direct production calls to the raw private seal/open helpers outside
  `SshKeyPrivateStateProtector`, keeping encrypted userauth state and server
  continuation state on the builder `ContinuationProtector` boundary.
- Add staged mechanism-install coverage.  `make test-install` now stages both
  Heimdal and MIT krb5 mechanism-fragment installs under temporary `DESTDIR`
  roots, verifies the shared object, public header, and config fragment, checks
  that fragments contain runtime library paths rather than staging paths, and
  verifies staged uninstall cleanup.
- Add initial release tarball packaging.  `make package` now creates an
  installable tarball from the same staged install tree as `make install`,
  with overridable package path and GSS mechanism-registration format, and
  `make test-package` verifies temporary Heimdal and MIT krb5 tarball contents
  without leaving package files in the worktree.
- Tighten malformed ssh-agent identity cleanup.  The identity-list parser now
  explicitly clears any already parsed identities before rejecting malformed
  trailing data or later malformed entries, and the fake-agent failure oracle
  includes a direct trailing-data parser regression.
- Remove the deterministic local context-key fallback.  When `ctx-key` is not
  provided, the mechanism now generates the process-local continuation-state
  key from OS randomness and fails closed if that randomness is unavailable,
  instead of falling back to a fixed key.
- Wipe partial random buffers on RNG failure.  The shared random-fill helper
  now zeroizes the target buffer when OS randomness cannot be obtained, with
  direct regression coverage for both failure cleanup and successful fills.
- Route X25519 private scalar generation through random cleanup.  The
  ephemeral keypair path now uses the shared random-fill helper, so partial
  private scalar bytes are wiped on OS randomness failure before login
  establishment fails closed.
- Guard direct OS randomness reads.  Source-hygiene coverage now rejects
  direct `getrandom()` calls outside the shared random-fill helper, keeping
  future nonce, context-key, and ephemeral-key paths behind wipe-on-failure
  cleanup.
- Use constant-time byte comparison for host-authentication digests.  Finished
  MAC verification, hashed known-host HMACs, DNS SSHFP digests, and
  transport-verified host-key comparisons now share one constant-time byte
  comparison helper, with direct mismatch and digest-length coverage.
- Use the shared byte comparison helper for login key-blob matching.  Client
  private-key and agent identity pairing, known-host plain-key and revocation
  checks, server `authorized_keys` matching, and public-key list lookup now
  route SSH public-key blob comparisons through the shared comparison helper.
- Guard production SSH key-blob comparisons.  Source-hygiene coverage now
  rejects direct production equality checks for login-critical SSH public-key
  blobs, keeping future client identity, host-trust, revocation, and
  `authorized_keys` matching behind the shared comparison helper.
- Wipe encoded output-token buffers after GSS buffer handoff.  The mechanism
  now zeroizes local DER token bytes after `set_buffer_bytes()` copies them to
  the caller-visible GSS output buffer, with focused coverage that the output
  buffer still owns the copied token data.
- Wipe exported-name and localname handoff buffers.  `gss_export_name()` now
  zeroizes the locally constructed exported-name token after copying it to
  GSS-owned output storage, and `gss_localname()` wipes its local-user buffer
  after `set_buffer_bytes()` returns.
- Guard GSS buffer handoff cleanup.  Source-hygiene coverage now pins
  zeroization after output-token, exported-name, local-name, and authorization
  report buffers are copied to caller-owned GSS storage.
- Wipe initial-token inner DER after encapsulation.  Client initial-token
  construction now zeroizes the inner mechanism DER once it has been copied
  into the GSS initial-token wrapper, with coverage that the framed payload
  still decodes correctly.
- Wipe replay-id digest temporaries.  The acceptor replay-cache marker
  derivation now zeroizes the SHA-256 digest temporary after copying it into
  the fixed replay id, with direct deterministic coverage for the derived id.
- Guard token DER and replay-id temporary cleanup.  Source-hygiene coverage now
  pins the initial-token inner DER wipe after encapsulation and the replay-id
  digest wipe after copying the fixed replay-cache id.
- Wipe fingerprint digest and key-copy temporaries.  Client fingerprint
  helpers and SSH identity fingerprint construction now zeroize digest arrays
  and temporary public-key/certificate-subject blobs after formatting
  fingerprints.
- Guard fingerprint temporary cleanup.  Source-hygiene coverage now rejects
  non-zeroizing fingerprint digest and blob-copy patterns and pins cleanup in
  the OpenSSH-format fingerprint helpers.
- Wipe host-trust digest comparison temporaries.  Hashed known-host HMAC
  checks and DNS SSHFP SHA-1/SHA-256 checks now zeroize computed digest bytes
  immediately after capturing the constant-time comparison result.
- Guard host-trust digest comparison cleanup.  Source-hygiene coverage now
  rejects non-zeroizing hashed known-host and SSHFP digest comparison
  temporaries and pins the local cleanup in the matching helpers.
- Wipe establishment transcript-hash locals on all exits.  Initiator and
  acceptor context-establishment paths now wrap computed handshake transcript
  hashes in zeroizing storage so early error returns do not leave the local
  digest copy live until ordinary stack reuse.
- Wipe copied Finished MAC temporaries.  Finished-token construction now
  zeroizes the local HMAC array immediately after copying it into the token
  buffer, while retaining the existing cleanup for Finished keys and inputs.
- Guard copied Finished MAC cleanup.  Source-hygiene coverage now rejects
  plain HMAC array-to-Vec copies and pins that `finished_mac()` zeroizes the
  local MAC array after copying it into the token buffer.
- Guard establishment transcript-hash cleanup.  Source-hygiene coverage now
  rejects context-establishment transcript-hash call sites that do not wrap the
  local digest copy in `Zeroizing` storage before later fallible work.
- Fail closed on malformed server `Match` pattern lists.  The server
  `Match User`, `Match Group`, `Match Host`, `Match Address`,
  `Match LocalAddress`, `Match LocalPort`, and `Match RDomain` parser now
  rejects empty comma-list entries and bare negation entries, and the resolved
  `user_key_authorization()` path refuses login when malformed match policy is
  present.
- Fail closed on malformed `Match Address` CIDR patterns.  The server
  `Match Address` and `Match LocalAddress` parser now rejects invalid
  CIDR-looking patterns, including negated entries, and the resolved
  `user_key_authorization()` path refuses login when malformed match policy is
  present.
- Fail closed on malformed account host CIDR patterns.  The server
  `AllowUsers` and `DenyUsers` parser now rejects invalid CIDR-looking host
  patterns, and the resolved `user_key_authorization()` path refuses login
  when such malformed account policy is present.
- Cover malformed authorized-helper percent tokens.  Direct
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` token-expansion
  tests now pin that unknown `%` tokens and trailing `%` characters fail closed
  before helper execution, alongside the existing missing connection-token
  coverage.
- Fail closed on malformed CIDR entries in `from=` pattern lists.  Local
  `authorized_keys` entries and authorized-principals entries now reject
  invalid IPv4/IPv6 ranges and invalid negated ranges even when another
  wildcard pattern in the same list would otherwise authorize the login.
- Fail closed on malformed `from=` pattern-list entries.  Local
  `authorized_keys` entries and authorized-principals entries now reject empty,
  leading-empty, trailing-empty, doubled-comma, and bare negated `!` `from=`
  lists instead of treating neighboring patterns as an unrestricted login
  grant.
- Accept exact IP entries in user-certificate `source-address` critical
  options.  OpenSSH accepts both exact IPv4/IPv6 addresses and CIDR ranges in
  certificate source-address lists; the acceptor now matches both forms through
  the resolved `user_key_authorization()` path and trusted-CA authorization
  helper, while continuing to fail closed on invalid ranges or unavailable peer
  addresses.
- Honor negated user-certificate `source-address` critical options.  The
  resolved `user_key_authorization()` path and trusted-CA authorization helper
  now deny negated exact-address or CIDR matches regardless of list order,
  require at least one positive match, and fail closed on malformed negated
  entries.
- Align authorized-principals `#` comment handling with OpenSSH.  The
  principals parser now treats the first `#` after leading whitespace as the
  start of a comment, including inside quoted option values or principal names,
  while preserving ordinary full-line and trailing comments.
- Preserve `#` inside `authorized_keys` entries.  The local authorization
  parser now ignores full-line comments without truncating quoted option
  values, so certificate CA entries such as `principals="deploy#prod"` remain
  login-relevant authorization data.  Unit coverage also keeps trailing public
  key comments working; live file-content comparison remains covered by the
  broader live user-certificate login gaps until a real SSH transport runs.
- Cover hashed known-host lookup names for aliases and non-standard ports.
  Host-trust unit coverage now pins OpenSSH-style hashed `[host]:port` lookup
  names and hashed literal `HostKeyAlias` lookup names.  The OpenSSH oracle
  manifest also records explicit live gaps for hashed known-host trust,
  revoked host-key rejection, and DNSSEC SSHFP host-key trust until a real
  SSH transport can exercise those decisions.
- Cover bracketed IPv6 peer addresses in localhost host-auth bypass.  Client
  typed-context parsing now canonicalizes bracketed `SSHKEY_HOST_ADDR` IPv6
  values before policy resolution, and host-trust bypass accepts bracketed
  loopback addresses while rejecting bracketed non-loopback addresses under
  `NoHostAuthenticationForLocalhost`.
- Cover multiple configured certificates backed by one raw agent key.  The
  fake-agent identity-ordering oracle now pins that one agent-listed raw public
  key can back several configured user certificates in configured order, then
  the raw configured key, while `IdentitiesOnly` still suppresses unrelated
  agent identities.
- Cover multiple configured certificates backed by one unencrypted
  `IdentityFile` key.  The identity-ordering oracle now pins that several
  explicit `CertificateFile` certificates backed by the same private key are
  planned in configured order before the raw private-key fallback.
- Guard the typed-context boundary against new direct environment reads.  The
  initiator and acceptor paths now have executable source-hygiene coverage
  that permits process-environment reads only in the compatibility adapter
  snapshot and the optional `SSHKEY_TRACE` diagnostic flag.  The guard covers
  the handwritten Rust mechanism and OpenSSH config parser modules, recording
  the closed Milestone 1 inventory result.
- Report the effective client `RequiredRSASize` floor.  The client resolver
  still preserves OpenSSH's raw resolved `RequiredRSASize` value, including
  values below the default floor, but initiator policy now carries and reports
  the enforced minimum so SSH integration diagnostics match host-key and user
  identity filtering.
- Fail closed on invalid client percent tokens where OpenSSH expands them.
  The client parser now rejects unknown `%` tokens for `User`, `HostName`,
  `IdentityAgent`, `UserKnownHostsFile`, and `RevokedHostKeys`, while leaving
  `IdentityFile`, `CertificateFile`, `GlobalKnownHostsFile`, `HostKeyAlias`,
  and `KnownHostsCommand` literal at `ssh -G` resolution time.  `User` now
  expands the OpenSSH-supported local/path token subset.  The invalid
  `ssh -G` oracle fixture pins the fail-closed cases.
- Validate and normalize client `ProxyJump` syntax like OpenSSH.  The client
  resolver now rejects malformed jump lists, invalid or zero ports, URI paths,
  and unsupported URI IPv6 authorities before login policy is used, while
  preserving OpenSSH normalization for `ssh://user@host:port`, trailing empty
  ports, bracketed direct IPv6 hosts, and comma-separated jump chains.  The
  existing `ssh -G` oracle fixtures now pin both valid normalization and
  fail-closed malformed values.
- Scope conditional client `Include` blocks like OpenSSH.  Includes inside a
  `Host` or `Match` block now split the parent block at the include site,
  parse included files under the enclosing matcher, and then resume the parent
  block, so nested `Host` or `Match` sections from included files cannot leak
  into unrelated hosts.  A new `ssh -G` oracle fixture pins nested `Host`
  scoping and additive identity ordering across the include boundary.
- Isolate OpenSSH oracle output caches per fixture.  The compatibility runner
  now keys cached `ssh -G` and `sshd -T` outputs by fixture name as well as
  subject, so shared subject names such as `other` cannot leak output from an
  earlier fixture into a later expectation check.
- Fail closed on unknown client config directives outside active
  `IgnoreUnknown` coverage.  The client policy resolver now validates ordinary
  `ssh_config` files with OpenSSH-style contextual `IgnoreUnknown` handling:
  the first active ignore list protects later unknown directives, while unknown
  directives before it or behind an inactive ignore fail closed.  New `ssh -G`
  oracle rows pin positive ignored-directive behavior and a fatal unknown
  directive case.
- Honor client `Match localnetwork` for login configuration.  The
  `ssh_config` resolver now validates OpenSSH-style CIDR lists, matches them
  against local interface addresses, supports outer criterion negation, and
  fails closed on missing or malformed local-network criteria.  New `ssh -G`
  oracle rows pin both positive selection and malformed-input behavior.
- Fail closed on fatal OpenSSH `Include` environment syntax.  Client config
  parsing now distinguishes unset `${NAME}` include variables, which remain a
  non-fatal skipped include pattern, from `${}` and unterminated `${...`
  syntax, which match OpenSSH's fatal parser behavior.  Separate `ssh -G`
  oracle rows pin both fatal include expansion forms.
- Reject invalid bare `IdentityAgent` environment references.  The client
  parser now fails closed on OpenSSH-invalid bare `$` forms such as
  `$SSH_AUTH_SOCK/foo` while preserving `SSH_AUTH_SOCK`, `$SSH_AUTH_SOCK`,
  `${SSH_AUTH_SOCK}`, and `${SSH_AUTH_SOCK}/suffix` behavior for agent socket
  selection.  The invalid `ssh -G` oracle fixture now pins this behavior.
- Expand client algorithm-modifier oracle coverage.  The OpenSSH compatibility
  harness now has token-aware negative field assertions and a runnable
  `ssh -G` fixture for `+`, `-`, and `^` behavior across
  `PubkeyAcceptedAlgorithms`, `PubkeyAcceptedKeyTypes`,
  `HostbasedAcceptedAlgorithms`, `HostbasedKeyTypes`, `HostKeyAlgorithms`, and
  `CASignatureAlgorithms`.
- Honor initial client bind-source policy.  The client resolver now parses
  `BindAddress` and `BindInterface`, preserves OpenSSH first-value behavior
  including explicit `none`, carries the values into typed client policy, and
  reports them for SSH integration.  Runnable `ssh -G` oracle coverage now
  pins resolved bind-source output plus malformed missing and extra argument
  failures.
- Honor initial client `AddressFamily` policy.  The client resolver now parses
  `AddressFamily any`, `inet`, and `inet6`, carries the selected value into
  typed client policy, reports it through client-policy inquiry, uses it for
  canonicalization resolver hints, and has runnable `ssh -G` oracle coverage
  plus malformed-value coverage.
- Validate the OpenSSH oracle audit against the fixture manifest.  The
  compatibility runner now verifies that each `fixtures.tsv` row appears in
  the checked-in `AUDIT.md` row index, so new client, server, agent, or gap
  rows cannot silently drift away from the login-compatibility audit.
- Make remaining release dead-code helpers test-only.  Test-only client
  identity projection helpers, signature-aware authorization wrappers, and the
  client identity candidate algorithm assertion field are no longer compiled
  into release builds.
- Make raw process-environment map constructors test-only.  Production code now
  reaches adapter snapshots through role-specific adapter sources, while
  direct `from_process_env_values()` constructors remain available only to the
  compatibility-adapter regression tests.
- Move malformed client policy adapter checks to the typed context boundary.
  Client policy tests now exercise valid `host-addr`, `known-hosts`, and
  SSH transport session facts through explicit `ClientLoginContext` values,
  while malformed `ssh-config`, `host-addr`, `known-hosts`, `session-id`, and
  `session-signature` adapter inputs fail at context construction.
- Move malformed server authorization adapter checks to the typed context
  boundary.  Ordinary server authorization tests now use `ServerLoginContext`
  values for policy decisions and assert malformed `sshd-config`,
  `authorized-keys`, peer, connection, and routing-domain adapter inputs at
  context construction or config resolution.
- Move local context-key parsing behind a typed snapshot accessor.  The shared
  adapter snapshot now validates `ctx-key` as a fixed 32-byte continuation
  state key before `LocalContextKey` consumes it or falls back to a generated
  process-local key.
- Move server peer scalar parsing behind typed snapshot accessors.  The shared
  adapter snapshot now validates `match-host`, `peer-addr`, `connection`, and
  `routing-domain` before `ServerPeerContext` consumes those SSH peer concepts.
- Move client scalar context parsing behind typed snapshot accessors.  The
  shared adapter snapshot now validates `host`, `resolved-host`, `port`,
  `host-addr`, `ssh-config-tags`, and `user` before `ClientTargetContext` and
  `ClientConfigInputContext` consume them.
- Move colon-separated adapter list parsing behind typed snapshot accessors.
  The shared adapter snapshot now parses client `ssh-config` and `known-hosts`
  fields into `Vec<PathBuf>` values and server `authorized-keys` into template
  strings before config sub-context constructors consume them.
- Move server and local adapter paths behind typed snapshot accessors.  The
  shared adapter snapshot now validates `sshd-config`, `host-key`, and
  `ctx-replay-dir` as non-empty `PathBuf` values before server and
  mechanism-local sub-context constructors consume them, keeping raw path
  adapter strings at the compatibility boundary.
- Make client agent socket selection a typed local-context field.  The client
  adapter now parses `agent-sock` or legacy `SSH_AUTH_SOCK` into
  `ClientLocalContext.agent_sock`, and `IdentityAgent SSH_AUTH_SOCK` consumes
  that typed path while captured environment values remain available for
  OpenSSH-style `$VAR` socket references.
- Pin session-id-only fallback userauth transcript binding.  A direct unit test
  now verifies that when a client supplies an SSH transport session id without a
  verified host key, the GSS-specific fallback userauth signature transcript
  still binds that session id and rejects replay under a different session id.
- Expose positive destination-constrained agent context coverage in the oracle.
  The focused `destination-verified-context` row now runs the v1 context-field
  login exchange that supplies verified host key and SSH session identity to a
  destination-constrained agent key, alongside the no-context focused rows.
- Hide prototype adapter names behind SSH-concept snapshot accessors.  Client,
  server, and mechanism-local typed context constructors now obtain context
  inputs through concept-level `AdapterContextSnapshot` methods, keeping direct
  `SSHKEY_*` lookup names inside the compatibility-adapter layer.
- Zeroize raw RSA signing buffers.  Private-key fallback signing now wipes the
  raw PKCS#1 signature bytes after wrapping them in SSH signature blobs for
  `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512`.
- Zeroize partial hostauth signing metadata.  The shared SSH signing helper now
  wipes key type, signature type, and public-key blob buffers if hostauth
  signing succeeds but a later metadata encoding step fails.
- Make GSS smoke-test tooling gaps explicit.  `tests/gss-token/run.sh` now runs
  each available smoke phase independently and reports missing local
  compiler, Heimdal header, `unshare`, GSS library, `gss-token`, or `knc`
  prerequisites as visible skips instead of failing before other available
  smoke coverage can run.
- Move MIT krb5 loader coverage out of the OpenSSH compatibility manifest.
  The manifest previously carried a non-runnable `mit-krb5-loader` row; direct
  MIT mechglue coverage now lives in `make test-gss-token` when MIT krb5
  development files are installed.
- Zeroize encrypted userauth local identity buffers.  The initiator now wipes
  the cloned selected username used across encrypted userauth candidate stages,
  and wipes the agent path's local key-type clone on success, failure, and
  transcript-construction failure.
- Zeroize SSH signature parser and userauth signature buffers.  Agent sign
  replies now wipe parsed signature blobs when later framing checks fail,
  legacy RSA and security-key signature parsers wipe SSH-string temporaries,
  and agent/private userauth signing loops wipe local signature blobs after
  retry, verification, and sealing decisions.
- Guard ssh-agent and signature-buffer cleanup.  Source-hygiene coverage now
  pins cleanup for agent request/reply buffers, malformed agent signatures,
  parsed RSA signature strings, and agent/private userauth transcript and
  signature buffers.
- Zeroize ssh-agent identity parser temporaries.  Identity-list parsing now
  wipes per-entry comments, skipped non-user certificate keys, and partially
  parsed key/key-type buffers before returning malformed-agent failure.
- Guard ssh-agent identity parser cleanup.  Source-hygiene coverage now pins
  drop-time identity cleanup, malformed-list clearing, and zeroization for
  comments, skipped certificate keys, and partial key/key-type parses.
- Zeroize helper-output reader scratch buffers.  The shared bounded stdout
  reader used by `KnownHostsCommand`, `AuthorizedKeysCommand`, and
  `AuthorizedPrincipalsCommand` now wipes its partial output on read errors
  and wipes the stack read buffer on success, over-limit failure, and read
  failure.
- Guard helper-output reader cleanup.  Source-hygiene coverage now pins that
  the shared bounded stdout reader wipes partial helper output and stack
  scratch buffers on read errors, over-limit failure, and success.
- Zeroize raw OpenSSH config file buffers.  Client and server config parsers
  now wrap top-level and included `ssh_config`/`sshd_config` file text in
  drop-time zeroization, matching the existing cleanup for parsed directive
  structures.
- Guard raw OpenSSH config file cleanup.  Source-hygiene coverage now rejects
  unwrapped client/server config file reads and pins drop-time cleanup for
  parsed directive keys and arguments.
- Zeroize shared replay-cache marker buffers.  The acceptor shared
  continuation-state replay cache now wipes the local replay id copy, derived
  marker filename, and marker path buffer after each atomic marker creation
  decision.
- Guard shared replay-cache marker cleanup.  Source-hygiene coverage now pins
  cleanup of the shared replay id, derived marker filename, and marker path
  across success, duplicate-marker, and marker-creation failure paths.
- Zeroize inquiry report buffers.  Mechanism-specific authorization, client
  policy, and server policy inquiry helpers now wipe their internal report
  strings after copying to the caller's GSS buffer, and report-generation
  helpers wipe temporary hex encodings and identity-fingerprint strings.
- Guard inquiry report cleanup.  Source-hygiene coverage now pins temporary
  hex-string and identity-fingerprint cleanup and verifies the authorization,
  client-policy, and server-policy inquiry entrypoints all use the zeroizing
  report handoff.
- Zeroize revocation candidate buffers.  Client `RevokedHostKeys` and server
  `RevokedKeys` checks now wipe candidate public-key blobs, OpenSSH query
  lines, plain-text revocation file contents, temporary KRL helper inputs, and
  parsed authorized-key entries after each revocation decision.
- Guard revocation candidate cleanup.  Source-hygiene coverage now pins
  cleanup for known-host revocation matching, client and server revocation
  files, KRL helper query lines, and partial certificate-candidate construction
  failures.
- Zeroize client host-trust text buffers.  Known-hosts files,
  `KnownHostsCommand` stdout, expanded helper argv vectors, and plain-text
  `RevokedHostKeys` files now use drop-time zeroization, including invalid
  helper stdout and command failure paths.
- Guard client host-trust text cleanup.  `KnownHostsCommand` timeout handling
  now wipes any captured stdout before failing, `%K` expansion keeps the
  OpenSSH public-key string in zeroizing storage, and source-hygiene coverage
  pins known-hosts file text, helper stdout, expanded argv, and ORDER lookup
  cleanup.
- Zeroize server authorization text buffers.  Authorized-key files,
  authorized-principals files, trusted-user CA files, authorization-helper
  stdout, and expanded helper argv vectors now use drop-time zeroization for
  their owned text buffers, including invalid helper stdout and excessive
  output failure paths.
- Guard server authorization text cleanup.  Authorization-helper timeout
  handling now wipes captured stdout before failing, helper argv expansion
  failures wipe partially expanded arguments, and source-hygiene coverage pins
  authorized-key, authorized-principals, trusted-CA, helper stdout, and helper
  argv text cleanup.
- Zeroize server account and helper-context buffers.  Passwd-derived account
  records now wipe usernames, home paths, and shell paths when dropped; DNS
  SSHFP records wipe parsed digests; and authorized-key/principals command
  contexts wipe owned key, certificate, and CA description strings after
  helper expansion.
- Guard server account and helper-context cleanup.  Source-hygiene coverage
  now pins passwd account, SSHFP digest, authorized-key helper context, and
  authorized-principals helper context cleanup, including zeroizing certificate
  and CA helper-description strings borrowed during command expansion.
- Zeroize parsed OpenSSH config buffers.  Parsed client and server config
  objects now wipe raw directive keywords, arguments, match criteria, parser
  errors, and authentication-method lists when the parser and oracle fixtures
  drop their intermediate config state.
- Guard parsed OpenSSH config cleanup.  Source-hygiene coverage now pins
  drop-time cleanup for client and server parser errors, raw directive keys
  and arguments, match patterns and criteria, and server authentication-method
  lists.
- Zeroize authorization result buffers.  Completed SSH authorization records
  now wipe authenticated key metadata, certificate key ids, CA fingerprints,
  certificate principal lists, and mapped local-user strings when GSS names or
  completed contexts release their cloned authorization data.
- Guard authorization result cleanup.  Source-hygiene coverage now pins
  authenticated key metadata cleanup, certificate authorization metadata
  cleanup, mapped local-user cleanup, and explicit cloned-authorization drops
  from released GSS names and deleted GSS contexts.
- Zeroize typed server login-context buffers.  The acceptor transport, peer,
  config-input, and local context structs now wipe owned session-id, peer
  address, match host, routing-domain, configured path, override,
  authorized-key template, home, and helper-locale buffers when dropped.
- Guard typed server login-context cleanup.  Source-hygiene coverage now pins
  drop-time cleanup for server transport session ids, peer match/address and
  routing-domain strings, connection address strings, server config paths and
  overrides, authorized-key templates, home paths, and helper-locale values.
- Zeroize typed client login-context buffers.  The client target, config-input,
  local, and SSH transport context structs now wipe owned host, user, path,
  override, helper-environment, session-binding, and verified host-key buffers
  when a resolved context drops.
- Guard typed client login-context cleanup.  Source-hygiene coverage now pins
  drop-time cleanup for client target host and address strings, config paths
  and overrides, known-host paths, tags, configured user strings, local user,
  home and agent paths, captured helper environment, transport session
  binding, and verified host keys.
- Zeroize client policy-owned login buffers.  `ClientPolicy` now wipes
  selected user, host, identity, algorithm, SSH transport binding, verified
  host-key, helper-environment, and local path buffers when an initiator policy
  drops, and configured identity records wipe duplicated key blobs and paths.
- Guard client policy-owned login cleanup.  Source-hygiene coverage now pins
  cleanup for client policy users, hosts, paths, proxy/authentication helper
  strings, configured identity blobs and paths, algorithm lists, known-host
  command and path buffers, captured environment, SSH transport bindings, and
  verified host keys.
- Zeroize client identity candidate buffers.  Private-key fallback identities,
  agent identities, and ordered userauth candidates now wipe duplicated key
  blobs, key-type strings, agent sign-key blobs, and local identity paths when
  candidate lists are dropped; underlying private key material remains covered
  by the `ssh-key` and `rsa` crates' drop-time zeroization.
- Guard client identity candidate cleanup.  Source-hygiene coverage now pins
  cleanup for private-identity key/keytype/path copies, agent listed-key,
  keytype, and sign-key copies, ordered candidate offered-key/keytype/source
  buffers, configured source drops, and client policy private-identity lists.
- Zeroize mechanism context-owned buffers on drop.  `SshKeyCtx` now wipes
  stored handshake public-key arrays, mechanism signature lists, sealed server
  context bytes, display/target names, handshake nonces, and agent host-key
  context when `gss_delete_sec_context()` releases the context, extending the
  existing completed session-key cleanup.
- Guard mechanism context-owned cleanup.  Source-hygiene coverage now pins
  drop-time cleanup for context ECDH keys, handshake public-key arrays, session
  keys, signature lists, sealed server contexts, display/target names,
  handshake nonces, agent host-key context, cloned client policy records, and
  cloned authorization records when `gss_delete_sec_context()` releases a
  context.
- Zeroize adapter snapshot context values.  Dropped
  `AdapterContextSnapshot` values now wipe their owned Unix byte buffers,
  skipped typed context fields are wiped during client captured-environment
  extraction, and local `ctx-key` parsing wipes the cloned hex string after
  decoding.
- Zeroize decoded context-key hex buffers.  The local `ctx-key` parser now
  guards the temporary decoded key with `Zeroizing` after copying into the
  fixed-size local context key, and generic hex decoding wipes partial output
  before returning parse failure.
- Guard adapter snapshot and context-key cleanup.  Source-hygiene coverage now
  pins drop-time cleanup for adapter snapshot context maps, skipped typed
  context values, captured-environment partial failure state, cloned local
  `ctx-key` hex strings, decoded context-key bytes, and partial generic hex
  decoder output.
- Guard raw OpenSSH private-key file buffers with drop-time zeroization.  The
  shared private-key parser wraps PEM bytes in `Zeroizing`, and
  source-hygiene coverage now rejects direct production private-key parsing
  outside that helper while pinning client identity public-key extraction,
  private-key fallback loading, and acceptor host-key loading through it.
- Zeroize ssh-agent reply buffers.  Agent replies now wipe partially read
  buffers on transport failure, wipe explicit failure replies before dropping
  them, and wipe identity-list replies after parsing, matching the existing
  sign-reply cleanup path.
- Guard ssh-agent reply cleanup.  Source-hygiene coverage now pins
  `AgentConnection::request()` cleanup for partial transport reads and explicit
  agent failure replies, plus session-bind, identity-list, and sign-reply
  cleanup after parsing.
- Settle weak-algorithm default policy.  Client and server default algorithm
  policy now follows OpenSSH's SHA-2 RSA defaults while leaving legacy
  `ssh-rsa` and `ssh-dss` disabled unless resolved OpenSSH configuration
  explicitly enables them, with unit coverage pinning both client and server
  defaults.
- Zeroize anonymous-session KDF work buffers.  The SAnon session-key derivation
  now wipes the assembled KDF context and each SP800-108 block input, and it
  clears any partial output if block derivation fails.
- Guard anonymous-session KDF cleanup.  Source-hygiene coverage now pins
  cleanup for the assembled SAnon KDF context, each SP800-108 per-block input,
  partial output on HMAC failure, and copied HMAC block temporaries.
- Zeroize DER plaintext buffers for sealed context data.  Userauth and
  acceptor continuation-state DER plaintexts are now wiped after encryption
  and after decryption plus decode, covering both successful and failed
  decode/seal outcomes.
- Guard DER plaintext cleanup for sealed context data.  Source-hygiene
  coverage now pins userauth and server continuation-state DER plaintext
  cleanup after seal attempts and after decrypt/decode attempts.
- Zeroize handshake and verification transcript buffers.  Hostauth and
  userauth transcript builders now wipe partial buffers on construction
  failure, handshake transcript hashing and Finished MAC inputs are wiped after
  use, and hostauth plus acceptor-side userauth verification wipe the local
  signature transcript after verification.
- Guard handshake and verification transcript cleanup.  Source-hygiene
  coverage now pins zeroizing transcript builders, handshake transcript-hash
  input cleanup, Finished MAC input and key cleanup, hostauth signing input
  cleanup, and hostauth/userauth verification input cleanup.
- Zeroize ssh-agent request and userauth transcript buffers.  Agent
  session-bind and sign-request payloads now wipe their local request buffers
  after use, and client userauth signing attempts wipe the generated signature
  transcript input before retrying another candidate or returning success.
- Guard ssh-agent request and userauth transcript cleanup.  Source-hygiene
  coverage now pins session-bind and sign-request payload cleanup after
  construction failure and after agent use, plus agent-backed and private-key
  userauth transcript cleanup before retry or return.
- Zeroize raw OpenSSH private-key file buffers.  Production private-key reads
  now parse through a shared helper that wipes the PEM bytes after parsing,
  covering client identity public-key extraction, private-key fallback loading,
  and acceptor host-key loading.
- Add initial secret-buffer zeroization.  The crate now directly depends on
  `zeroize`, enables `x25519-dalek` zeroization support, zeroizes
  mechanism-owned X25519 private scalars, completed-context session keys,
  local continuation-state keys, raw shared secrets after session-key
  derivation, and short-lived KDF, Finished MAC, and sealing key buffers.
  Finished MAC verification now uses a constant-time comparison.
- Zeroize serialized acceptor X25519 private-scalar copies.  Server-first
  acceptor continuation-state creation and final-token restoration now hold
  serialized acceptor private scalars in `Zeroizing` storage while copying them
  into or out of encrypted continuation state, with source-hygiene coverage
  pinning both paths.
- Zeroize temporary session-key copies.  Initiator retry and context-finish
  paths, acceptor continuation-state paths, and per-message RFC4121 profile
  construction now hold local session-key copies in `Zeroizing` storage while
  preserving context-owned session keys for established security contexts.
- Zeroize acceptor source-name handoff buffers.  Final acceptor processing now
  wipes the local display-name buffer after cloning it into the completed
  context and optional returned GSS name, including the returned-name failure
  path.
- Zeroize released GSS name buffers.  `gss_release_name()` now wipes the
  mechanism-owned copied name bytes before freeing them, covering imported,
  duplicated, inquired, and acceptor-returned GSS names.
- Zeroize released GSS output buffers.  The sibling `gss-mech-builder`
  `gss_release_buffer()` helper now wipes copied caller-visible GSS buffers
  before freeing them, covering mechanism output tokens, local names, exported
  names, status strings, and inquiry reports released through the shared ABI.
- Zeroize released GSS IOV buffers.  The sibling `gss-mech-builder`
  `gss_release_iov_buffer()` path and IOV reallocation path now wipe allocated
  header, trailer, padding, stream, and data buffers before freeing them.
- Zeroize RFC4121 profile and crypto temporaries.  The sibling `rfc4121` crate
  now wipes owned AES profile session keys on drop, derived keys after
  HMAC/encrypt/decrypt operations, seal/open/sign transcript and plaintext
  buffers, KDF inputs and blocks, and AES-CTS plaintext-derived working blocks.
- Zeroize signed-ECDH builder buffers.  The sibling `gss-mech-builder`
  signed-ECDH scaffold now wipes owned algorithm, identity, auth input,
  signature, Finished input, and Finished MAC buffers on drop, and clears
  local auth and Finished transcript buffers after signing or verification.
- Add a canonical signed-ECDH exchange transcript helper.  The sibling
  `gss-mech-builder` signed-ECDH scaffold now constructs a role-validated
  initiator-plus-acceptor exchange transcript from the two signed auth
  messages, binding the auth transcripts and signatures before Finished MAC
  construction while wiping intermediate auth transcript buffers.
- Add role-aware signed-ECDH Finished input construction.  The sibling
  `gss-mech-builder` scaffold now derives Finished input directly from the
  canonical exchange transcript, ordering local and peer nonces by initiator
  or acceptor role and rejecting swapped signed-auth roles.
- Add signed-ECDH algorithm negotiation.  The sibling `gss-mech-builder`
  scaffold now produces a role-validated negotiated algorithm set from the two
  signed auth messages, choosing KEX and enctype in initiator preference order
  and preserving the signature algorithms bound into each signed auth message.
- Add signed-ECDH established-exchange construction.  The sibling
  `gss-mech-builder` scaffold now validates the local role and ECDH public key,
  produces the negotiated algorithm set and canonical exchange transcript, and
  returns the role-local shared secret with drop-time cleanup.
- Add signed-ECDH Finished helpers over established exchanges.  The sibling
  `gss-mech-builder` scaffold now carries role-local nonces in the established
  exchange, projects canonical Finished input, and makes or verifies
  protocol-label-bound Finished proofs through the key-confirmation trait.
- Add signed-ECDH session-key derivation hooks.  The sibling
  `gss-mech-builder` scaffold now builds canonical session-key derivation
  input from an established exchange and caller context, invokes a reusable
  derivation trait with the raw shared secret, rejects empty derived keys, and
  stores the resulting session key with drop-time cleanup.
- Add mechanism adapters for signed-ECDH key schedule integration.  The
  ssh-key mechanism now implements the builder session-derivation and
  key-confirmation traits over its existing SP800-108/HMAC-SHA256 key schedule,
  routes current Finished MAC construction through that key-confirmation
  adapter, and keeps source-hygiene coverage on the moved cleanup.
- Add a mechanism X25519 adapter for signed-ECDH exchange integration.  The
  ssh-key mechanism now exposes its X25519 keypair through the builder
  `EcdhExchange` trait, routes current shared-secret derivation through that
  adapter, rejects malformed peer public keys, and wipes temporary shared-secret
  buffers after copying the fixed-size secret.
- Add mechanism SSH signature adapters for signed-ECDH transcript integration.
  The ssh-key mechanism now exposes private-key signing and public-key or
  certificate verification through the builder transcript signer and verifier
  traits, routes private-identity userauth signing and public signature
  verification through those adapters, and keeps source-hygiene coverage on the
  production bridge.
- Add signed-ECDH algorithm-suite negotiation to mechanism KEX validation.  The
  ssh-key mechanism now parses KEX and enctype algorithm lists into the builder
  `AlgorithmSuite`, uses builder negotiation to validate initiator, acceptor,
  and signature-retry KEX tokens, accepts compatible peer lists only when the
  selected algorithms match the negotiated local choices, and rejects malformed
  algorithm lists.
- Add a mechanism continuation-state protector for signed-ECDH integration.
  The ssh-key mechanism now implements the builder `ContinuationProtector`
  trait over its existing server-context seal/open format, routes
  continuation-state sealing and opening through that adapter, and keeps the
  existing DER plaintext cleanup guarded by source-hygiene coverage.
- Route encrypted userauth state through the builder private-state protector.
  The ssh-key mechanism now uses the same `ContinuationProtector` adapter for
  encrypted userauth seal/open state as for server continuation state, while
  preserving the existing labels and private seal/open format and guarding the
  derived userauth key cleanup.
- Remove the remaining non-reentrant client `~user` lookup.  The
  `ssh_config` tilde expansion helper now uses the same `getpwnam_r()`-backed
  account lookup as the rest of client login path expansion, and the
  tilde-user include-path regression now derives the current account through
  the reentrant uid lookup helper.
- Extend host-certificate revocation coverage.  Plain-text `RevokedHostKeys`
  now rejects host certificates when the file contains either the certificate
  subject key or signing CA key, matching known-hosts `@revoked` handling.
  Unit tests also pin `@revoked` known-hosts entries for certificate subject
  keys and CA keys, including revocation overriding a trusted CA entry.
- Record live OpenSSH oracle gaps for host-certificate CA trust.  The
  compatibility manifest and audit now track positive `@cert-authority`
  host-certificate trust and negative unauthorized-CA rejection as explicit
  non-runnable live-login gaps until `ssh`/`sshd` plus SSH transport context
  can make those rows executable.
- Add host-certificate `known_hosts` CA trust.  Hostauth now accepts OpenSSH
  host certificates signed by matching `@cert-authority` entries in
  known-hosts file or `KnownHostsCommand` output, validates the certificate
  signature, CA fingerprint, validity window, and host principal, rejects
  host-certificate critical options, and does not let
  `StrictHostKeyChecking no` bypass a configured CA policy for raw or
  unauthorized host keys.
- Add ssh-agent sign-reply framing failure coverage.  Fake-agent tests now
  verify that zero-length and oversized replies to sign requests are treated
  as failed identity candidates, with fallback to an unencrypted
  `IdentityFile` when configured and fail-closed completion otherwise.
- Add authorization-helper invalid UTF-8 stdout coverage.  Unit tests now
  verify that the shared `AuthorizedKeysCommand` and
  `AuthorizedPrincipalsCommand` runner rejects non-UTF-8 stdout before either
  helper can parse output as login authorization data.
- Add `KnownHostsCommand` stderr and UTF-8 failure coverage.  Unit tests now
  verify that known-hosts helper stderr is discarded while stdout remains the
  only trust input, and that invalid UTF-8 stdout fails closed even when
  `StrictHostKeyChecking no` would otherwise accept an unknown host.
- Add wrong-type ssh-agent sign-reply coverage.  Fake-agent tests now verify
  that a sign request receiving a validly framed non-sign-response message type
  is treated as a failed identity candidate, allowing a later agent identity or
  unencrypted `IdentityFile` fallback where available and failing closed
  otherwise.
- Add DSA private identity fallback coverage.  The encrypted userauth tests now
  drive an unencrypted `IdentityFile` containing an `ssh-dss` key through
  private-key fallback only when `PubkeyAcceptedAlgorithms ssh-dss` explicitly
  enables that legacy key type, then verify the emitted userauth signature.
- Add authorization-helper stderr coverage.  The shared
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` runner now has
  regression coverage proving stderr is discarded and only stdout plus a
  successful exit status contribute authorization data.
- Add ECDSA private identity fallback coverage.  The encrypted userauth tests
  now drive an unencrypted `IdentityFile` containing an
  `ecdsa-sha2-nistp256` key through the private-key fallback signer and verify
  the emitted SSH userauth signature.
- Add excessive ssh-agent identity-count coverage.  Fake-agent tests now verify
  that an identity-list answer advertising more entries than the bounded parser
  accepts is treated as an unusable agent reply, falling back to a later
  unencrypted identity when one exists and failing closed otherwise.
- Add wrong-type ssh-agent identity-list reply coverage.  Fake-agent tests now
  verify that an identity-list request receiving a validly framed non-identity
  message type is treated as an unusable agent reply, falling back to a later
  unencrypted identity when one exists and failing closed otherwise.
- Add end-to-end certificate local-name/exported-name mapping coverage.  A
  typed context-field login exchange now verifies that a trusted-CA user
  certificate returns the certificate subject key fingerprint as the GSS
  display/exported source name, while `gss_authorize_localname()` and
  `gss_localname()` map the key identity to the requested local account through
  `AuthorizedPrincipalsFile` authorization.
- Add ssh-agent reply-framing failure coverage.  Fake-agent tests now verify
  that zero-length and oversized identity-list replies are treated as unusable
  agent failures, either falling back to a configured unencrypted identity or
  failing closed when no later credential exists.
- Add malformed ssh-agent session-bind reply coverage.  Fake-agent tests now
  verify that malformed `session-bind@openssh.com` replies do not authorize
  agent-backed login, either falling back to a configured unencrypted identity
  or failing closed when no later credential exists.
- Retain historical off-scope client `KbdInteractiveDevices`
  method-control parser inventory.  The existing rows record resolved output
  and fail-closed arity behavior, but do not add keyboard-interactive
  authentication to the roadmap.
- Pin typed server helper-locale context-field coverage.  The direct
  `gss_sshkey_set_context_fields()` server feeder test now verifies that both
  the typed `lang` field and `env:LANG` helper-environment escape reach
  `ServerLocalContext`.
- Rename client and server local process sub-contexts.  `ClientLoginContext`
  and `ServerLoginContext` now expose local process facts through `local`
  subcontexts, with `ClientLocalContext` and `ServerLocalContext` replacing
  the older environment-shaped names while keeping captured expansion
  environment and helper-command locale explicit.
- Report resolved client identity-selection details.  Client policy inquiry
  now reports each configured identity source and each local private-key
  candidate with source kind, path, key type, and identity fingerprint, while
  leaving agent-only candidates as runtime ssh-agent state.
- Keep raw private-key fallback out of the agent candidate stage.  Userauth now
  attempts private-certificate candidates first, agent-backed identities
  second, and raw unencrypted `IdentityFile` candidates only in the final
  fallback stage, with unit coverage for the staged candidate helper.
- Reject non-regular client identity material for private-key fallback.
  Configured identity, certificate, and private-key fallback reads now require
  regular files before parsing key material, with regression coverage for
  directory inputs.
- Publish a C test and integration helper for explicit SSH context facts.  The
  installable `include/gss_sshkey.h` header now exposes the context role
  constants, field-name constants, `gss_sshkey_context_field`, ABI prototypes,
  and inline helpers for building string and byte fields.  `make install`
  installs the header and `make test-context-helper` compile-checks it.  Normal
  deployment policy still comes from OpenSSH-compatible configuration files.
- Honor initial client `ProxyCommand` routing context.  The client resolver now
  parses `ProxyCommand`, treats `ProxyCommand none` as an explicit disabled
  proxy command, preserves OpenSSH's first-value interaction with `ProxyJump`,
  and reports resolved proxy-command arguments through client policy inquiry.
  Focused OpenSSH oracle fixtures now pin `ProxyCommand`, `ProxyCommand none`,
  `ProxyCommand` before `ProxyJump`, `ProxyJump` before `ProxyCommand`, and
  `%j` expansion in both precedence cases.
- Add SSH agent signing.  Client-side user authentication uses
  `SSH_AUTH_SOCK` for agent-backed user signatures.
- Add host key trust policy.  Initiator hostauth verification now checks
  OpenSSH `known_hosts` files, including hashed hostnames and revoked entries,
  and DNSSEC-validated SSHFP records.
- Honor initial client known-hosts configuration.  The client resolver now
  parses `HostKeyAlias`, `UserKnownHostsFile`, and `GlobalKnownHostsFile`;
  hostauth verification uses the configured lookup alias and known-hosts file
  set, with token expansion only where OpenSSH applies it.
- Fail closed on malformed explicit known-hosts path overrides.  A supplied
  `SSHKEY_KNOWN_HOSTS` value must now contain at least one non-empty path and
  no empty colon-list elements, instead of silently dropping empty entries.
- Honor initial `VerifyHostKeyDNS` client host-trust policy.  DNSSEC-validated
  SSHFP records are now used for implicit host trust only when resolved client
  configuration sets `VerifyHostKeyDNS yes`; `ask` and `no` do not auto-trust
  inside the non-interactive mechanism.
- Honor initial client `RevokedHostKeys` policy.  The client resolver now
  parses `RevokedHostKeys`; hostauth verification rejects matching host public
  keys from plain OpenSSH and KRL revocation files and fails closed when a
  configured revocation file is missing, unreadable, or malformed.
- Add client `RevokedHostKeys none` coverage.  Resolver, host-trust, and
  `ssh -G` oracle tests now pin that exact `none` disables the host revocation
  source and suppresses later fallback values.
- Add `RevokedHostKeys` malformed-file coverage.  Unit tests now verify that
  malformed plain revocation files and KRL-like files that cannot be queried
  fail closed even when the same host key is otherwise trusted.
- Honor initial `StrictHostKeyChecking` client policy.  The client resolver
  now parses `yes`, `ask`, `accept-new`, `no`, and `off`; hostauth accepts
  unknown hosts for `accept-new` and accepts unknown or changed host keys for
  `no`/`off`, while `ask` behaves like fail-closed because the mechanism
  cannot prompt.
- Expand strict-host-key OpenSSH oracle coverage.  The host-trust fixture now
  pins `StrictHostKeyChecking accept-new` alongside `yes`, `ask`, `no`, and
  `off`, so the strict-mode login policy matrix is visible in one oracle row.
- Honor initial `KnownHostsCommand` client policy.  The client resolver now
  parses `KnownHostsCommand`; hostauth runs the command for hostname lookup,
  expands host, user, local-host, and host-key tokens, merges stdout as
  OpenSSH `known_hosts` data, and fails closed on command failure.
- Honor OpenSSH `KnownHostsCommand none`.  The client resolver now treats an
  exact single `none` argument as an explicit disabled helper, preserving
  first-value-wins behavior while leaving `none extra` as a literal command.
- Honor case-insensitive `none` disabling in login policy.  Known-hosts
  helpers, configured authorized-key files, `AuthorizedKeysCommand`, and
  `AuthorizedPrincipalsCommand` now treat exact single `none` values as
  disabled regardless of ASCII case.
- Apply exact `KnownHostsCommand none` semantics in host trust.  Host-key trust
  and `KnownHostsCommand ORDER` now disable the helper only for an empty command
  or exact single `none`; `none extra` is treated as a literal command and
  fails closed if it cannot run.
- Treat forced-command key and certificate options as post-authentication
  conditions.  `command=` authorized-key options and `force-command`
  certificate critical options now fail closed in the login-only path instead
  of being modeled as mechanism-side permissions.
- Honor case-insensitive authorized-key option keywords.  Local
  `authorized_keys` and authorized-principals parsing now recognizes supported
  OpenSSH option names regardless of ASCII case while preserving option values.
- Align `KnownHostsCommand` command-path expansion with OpenSSH.  The client
  now keeps the configured program path literal and expands `%` tokens only in
  command arguments after argv[0], with regression coverage for a command path
  containing `%H`.
- Honor OpenSSH-style environment expansion in `KnownHostsCommand` arguments.
  Arguments after argv[0] now expand `${VAR}` references alongside `%` tokens
  and fail closed when a referenced variable is unset.
- Run `KnownHostsCommand` with captured client environment.  The helper child
  now clears the mechanism process environment and receives only values carried
  in `ClientPolicy.captured_env`, so typed SSH context controls helper
  execution without ambient environment leakage.
- Fail closed on invalid SSH config quoting.  The client and server resolvers
  now reject unterminated quoted arguments before login policy is used, with
  OpenSSH oracle coverage for malformed `KnownHostsCommand` and
  `AuthorizedKeysCommand` directives.
- Honor OpenSSH quoted SSH config arguments.  Client and server config parsing
  now accepts single-quoted, double-quoted, and unquoted backslash-space
  arguments before resolving login policy, with OpenSSH oracle coverage for
  quoted `KnownHostsCommand` input.
- Align `KnownHostsCommand` `%C` with OpenSSH's connection hash inputs.  The
  helper token now includes the effective `ProxyJump` value alongside the local
  host, resolved host, port, and remote user.
- Honor initial client `FingerprintHash` policy for host-key helper
  fingerprints.  The client resolver now parses `FingerprintHash md5` and
  `sha256`, and `KnownHostsCommand` `%f` emits the configured OpenSSH-style
  MD5 or SHA256 public-key fingerprint.
- Honor OpenSSH client `FingerprintHash sha1` and case-insensitive scalar
  values.  Client fixtures and local tests now pin SHA1 `%f` fingerprint
  formatting plus mixed-case login-policy option values.
- Add OpenSSH oracle coverage for client `FingerprintHash` resolution.
  Compatibility fixtures now verify that `ssh -G` reports explicit MD5 and
  fallback SHA256 fingerprint-hash policy.
- Add OpenSSH fingerprint-format coverage for helper fingerprints.  Unit tests
  now compare the mechanism's MD5 and SHA256 public-key fingerprint formatting
  against `ssh-keygen -l -E`.
- Add `KnownHostsCommand` timeout coverage.  Unit tests now verify that an
  overlong known-hosts helper is killed and treated as command failure before
  host trust can succeed.
- Add `KnownHostsCommand` excessive-output coverage.  Unit tests now verify
  that helper output beyond the configured bound fails closed even when
  `StrictHostKeyChecking no` would otherwise accept an unknown host.
- Honor initial `CheckHostIP` client policy.  The client resolver now parses
  `CheckHostIP`; when enabled and the integration supplies `SSHKEY_HOST_ADDR`,
  hostauth checks known-hosts address entries and runs `KnownHostsCommand` with
  the `ADDRESS` reason, rejecting revoked or changed address keys.
- Add `CheckHostIP` address-command failure coverage.  Unit tests now verify
  that a trusted hostname result is still rejected when the address-form
  `KnownHostsCommand` invocation fails.
- Fail closed on malformed client host-address context.  A supplied
  `SSHKEY_HOST_ADDR` must now be a valid IPv4 or IPv6 address; invalid values
  become client configuration errors instead of silently disabling
  `CheckHostIP` address lookups.
- Cover typed `CheckHostIP` host-address integration.  A
  `gss_sshkey_set_context_fields()` test now proves that the v1 client
  `host-addr` field feeds resolved client policy and address-form known-hosts
  trust without using prototype environment variables.
- Honor initial `NoHostAuthenticationForLocalhost` client policy.  The client
  resolver now parses the option, the initiator hostauth trust path skips
  known-hosts and helper lookups for loopback hosts when it is enabled, and
  local and `ssh -G` oracle tests pin valid and invalid option forms.  A
  loopback `HostKeyAlias` by itself does not trigger the bypass for a
  non-loopback resolved target.
- Honor initial `KnownHostsCommand ORDER` host-key algorithm ordering.  Client
  policy now runs `KnownHostsCommand` with `%I=ORDER`, treats key-dependent
  tokens as `NONE`, and prefers host-key algorithms matching known host key
  types for the default OpenSSH host-key algorithm list.
- Honor OpenSSH known-hosts names for non-standard ports.  Host trust now
  looks up `[host]:port` and `[addr]:port` names when the resolved port is not
  22, falls back to bare host/address entries only when the port-qualified
  lookup is new, and preserves literal `HostKeyAlias` behavior.
- Use the resolved client hostname for host-trust lookups.  Host-key trust,
  known-host algorithm ordering, DNS SSHFP lookup, and localhost host-auth
  bypass now use the `HostName`-resolved SSH target unless `HostKeyAlias`
  supplies an explicit lookup name.
- Cover resolved-host `KnownHostsCommand` lookups.  Hostname and ORDER helper
  invocations now have regression tests proving `%H` receives the
  `HostName`-resolved lookup host rather than the original alias.
- Avoid duplicate host-trust decisions when SSH already verified the host key.
  The client context can now carry the SSH transport's verified host public key
  as a raw `host-key` blob.  If it exactly matches the mechanism hostauth key,
  the initiator accepts that SSH host-key decision instead of repeating a
  known-hosts lookup; mismatches fail closed.
- Support environment-adapter verified host-key input.  The typed client
  `host-key` field remains a raw SSH public key blob, while the legacy
  `SSHKEY_VERIFIED_HOST_KEY` adapter value accepts the same blob as hex so
  process environments do not need to carry NUL-containing SSH data.
- Record live oracle coverage for verified transport host-key context.  The
  OpenSSH compatibility manifest now keeps this as an explicit gap until an
  SSH integration can pass the verified host key through the typed client
  context during a live GSSAPI login.
- Add OpenSSH oracle coverage for host-trust path tokens.  Client fixtures and
  policy tests now pin `%r`, `%u`, `%h`, `%n`, and `%p` expansion for
  `UserKnownHostsFile` and `RevokedHostKeys`, while `GlobalKnownHostsFile`
  remains literal.
- Add OpenSSH oracle coverage for host aliases and non-standard ports.  Client
  fixtures now pin literal `HostKeyAlias none`, ordinary host aliases, and
  non-standard resolved ports used by login host-trust policy.
- Add hashed `known_hosts` trust-path coverage.  Unit tests now verify that
  OpenSSH-style hashed host patterns are accepted, revoked, and treated as
  changed-key mismatches by the same host-trust path that authorizes login
  hostauth keys.
- Add SSHFP digest and mismatch coverage.  Unit tests now verify DNSSEC SSHFP
  SHA1 and SHA256 records, AD-bit enforcement, algorithm mismatches, and
  changed-key digest mismatches in the host-trust matcher.
- Add strict-host-key revocation precedence coverage.  Unit tests now verify
  that revoked host entries still fail closed when `StrictHostKeyChecking no`
  would otherwise accept unknown or changed host keys.
- Expand localhost host-auth bypass coverage.  Unit tests now verify that
  `NoHostAuthenticationForLocalhost` follows the resolved loopback target even
  when a non-loopback `HostKeyAlias` would otherwise drive known-hosts lookup,
  and that supplied IPv4 and IPv6 loopback host addresses trigger the bypass.
- Record the live oracle gap for `KnownHostsCommand` `%f` behavior.  The
  compatibility manifest now keeps the live helper-fingerprint comparison
  explicit until a live SSH transport can supply host-key-check context.
- Honor OpenSSH local-context tokens in client login paths.  Client fixtures
  and policy tests now pin `%C`, `%d`, `%i`, `%l`, `%L`, `%j`, and `%k`
  expansion for `IdentityAgent`, `UserKnownHostsFile`, and `RevokedHostKeys`,
  while `IdentityFile` and `CertificateFile` keep OpenSSH's resolved-config
  literal behavior and expand at use time.
- Honor OpenSSH `~user` expansion in client login paths.  Client fixtures and
  resolver tests now pin passwd-backed `~user` expansion for `IdentityAgent`,
  `UserKnownHostsFile`, and `RevokedHostKeys`, fail-closed unknown users for
  those eagerly resolved paths, and use-time `~user` expansion for
  `IdentityFile` and `CertificateFile`.
- Add OpenSSH oracle coverage for disabling known-hosts file lists.  Client
  fixtures now verify `UserKnownHostsFile none` and `GlobalKnownHostsFile none`
  as valid `none`-alone settings.
- Match OpenSSH duplicate identity path resolution.  Client config resolution
  now keeps the first exact `IdentityFile` or `CertificateFile` string and
  ignores later exact duplicates, with `ssh -G` fixture coverage using exact
  line-count checks.
- Reject invalid OpenSSH client argument forms.  Client fixtures and resolver
  tests now fail closed for missing or invalid scalar login-policy arguments,
  extra scalar login-policy arguments, extra `IdentityFile`,
  `CertificateFile`, and `RevokedHostKeys` arguments on one directive, plus
  mixed `none` `UserKnownHostsFile` and `GlobalKnownHostsFile` lists.
- Honor initial client `RequiredRSASize` host-key policy.  The client resolver
  now parses `RequiredRSASize` in first-value-wins order and rejects trusted
  RSA host keys that are smaller than the resolved policy.
- Enforce client `RequiredRSASize` for user identities.  Agent-backed
  identities, unencrypted private-key fallback identities, and user
  certificate subject keys are now filtered through the resolved client RSA
  size floor before userauth signing.
- Honor initial client `HashKnownHosts` policy plumbing.  The client resolver
  now parses `HashKnownHosts`, validates it against `ssh -G`, and carries the
  resolved value into initiator policy for the SSH integration layer that will
  perform known-hosts updates.  The client policy inquiry reports the resolved
  value.
- Preserve client `UpdateHostKeys ask` for SSH integration.  The client
  resolver, initiator policy, and policy inquiry now keep `ask` distinct from
  `no` so an SSH integration layer can decide whether prompt-capable
  known-hosts updates are possible.
- Document known-hosts update ownership.  `UpdateHostKeys` and
  `HashKnownHosts` remain resolved and reported by the mechanism, but actual
  known-hosts file writes and hashing belong to the SSH integration layer that
  owns the transport host-key lifecycle, prompts, file locking, and
  OpenSSH-compatible update semantics.
- Report resolved client host-trust controls for SSH integration.  The client
  policy inquiry now reports `VerifyHostKeyDNS`, `StrictHostKeyChecking`,
  `CheckHostIP`, `NoHostAuthenticationForLocalhost`, `FingerprintHash`, and
  `RequiredRSASize` alongside known-hosts update policy, resolved known-hosts
  files, `KnownHostsCommand`, `RevokedHostKeys`, and the resolved host address
  used by `CheckHostIP`.
- Report resolved client target and identity-selection controls for SSH
  integration.  The client policy inquiry now reports the original and
  resolved host, port, remote and local users, `ProxyJump`, host-key alias,
  agent socket, `IdentitiesOnly`, and configured identity candidate counts.
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
  and MIC token framing, split-token size planning, and a standards-track
  AES-CTS/HMAC profile used by this mechanism.
- Add AES RFC4121 crypto profiles.  The `rfc4121` crate now supports the
  Kerberos AES-CTS/HMAC-SHA1 and AES-CTS/HMAC-SHA2 enctypes.
- Add the signed-ECDH builder API scaffold.  The builder now has canonical
  auth and Finished transcripts, signer/verifier traits, ECDH hooks, and
  continuation-state and key-confirmation traits for higher-level mechanisms.
- Fail closed on malformed explicit continuation-state keys.  A supplied
  `SSHKEY_CTX_KEY` must now be valid hex for exactly 32 bytes instead of being
  silently ignored in favor of a generated local key.
- Bound encrypted acceptor continuation-state age.  `sctx` carries an
  authenticated `issuedAt` Unix time, and the acceptor applies its local
  maximum-age and future-skew policy.  This limits but does not prevent replay;
  the mechanism does not claim process-local or shared single-use enforcement.
- Move handshake KDF/MAC off OpenSSL FFI.  The SAnon-compatible SP800-108
  session-key KDF, Finished MACs, and acceptor continuation-state seal keys now
  use RustCrypto `hmac`/`sha2` instead of OpenSSL `HMAC()`.
- Replace remaining X25519 OpenSSL FFI.  X25519 key generation, private-scalar
  serialization for acceptor continuation state, and shared-secret derivation
  now use `x25519-dalek` instead of OpenSSL EVP calls.
- Move reusable crates to separate repositories.  `gss-sshkey` now consumes
  sibling checkouts of `gss-mech-builder` and `rfc4121` instead of carrying
  in-tree workspace members.
- Add an initial OpenSSH compatibility oracle.  `tests/openssh-compat` now
  records client `ssh -G` and server `sshd -T` fixture expectations for the
  SSH behavior this mechanism needs to match.
- Make OpenSSH oracle environment gaps explicit.  The compatibility runner now
  reports selected `ssh`, `sshd`, `ssh-keygen`, and `gss-token` paths, package
  or version data where available, `sshd -T` availability, and skip reasons
  before running fixtures.
- Add an OpenSSH oracle fixture manifest.  Existing client and server oracle
  fixtures are now listed in `tests/openssh-compat/fixtures.tsv`, including
  scenario name, oracle command, config file, expectation file, optional
  argument file, current implementation status, and a short description.
- Validate OpenSSH oracle fixture metadata.  The compatibility runner now
  rejects manifest rows with missing fields, unsupported oracle commands, or
  unknown implementation-status values before trying to run a fixture.
- Harden OpenSSH oracle manifest validation.  The runner now rejects duplicate
  fixture names within a fixture kind, rejects runnable fixtures marked as
  `gap`, and rejects non-runnable gap records marked as `implemented` or
  `partial`.
- Record the first login-critical OpenSSH oracle gaps.  The manifest now
  carries explicit non-runnable entries for destination-constrained and
  confirmation-required agent identity coverage, live verified transport
  host-key context, live GSSAPI-only SSH login, and unavailable SSH transport
  context coverage.
- Expand live-login oracle gap coverage.  The manifest now records non-runnable
  live-login rows for GSSAPI-only success, denied accounts, revoked user keys,
  expired user certificates, unavailable credentials, missing SSH transport
  context, and verified host-key context, with each row naming the missing
  tool or transport hook needed to make it runnable.
- Split broad live-login oracle gaps into positive and negative partners.  The
  manifest now separately tracks live plain user-key success, user-certificate
  success, host-key policy rejection, and real-agent refusal fallback, while
  keeping each row blocked on the missing SSH, ssh-agent, or transport context
  hook that would make it runnable.
- Validate OpenSSH oracle gap unblockers.  The compatibility runner now rejects
  non-runnable gap rows whose descriptions do not name a concrete missing
  OpenSSH tool, prompt path, or transport context hook.
- Summarize OpenSSH oracle manifest coverage.  The compatibility runner now
  prints runnable fixture counts, local run and skip counts, recorded gap
  counts, and implementation-status counts at the end of each run.
- Report OpenSSH oracle inventory by compatibility track.  The compatibility
  runner now prints manifest rows under client `ssh -G`, server `sshd -T`,
  fake-agent protocol, and live-login gap sections so item (1)'s audit has an
  ordinary run artifact.
- Add a checked-in OpenSSH oracle manifest audit.  `AUDIT.md` now maps
  `fixtures.tsv` rows to the SSH-login compatibility contract, tracks client,
  server, fake-agent, and live-login gap coverage, and records high-risk
  positive and negative pairings for later parser and policy work.
- Report OpenSSH oracle fixture skips per scenario.  When a local tool such as
  `ssh` or `sshd` is unavailable, the runner now prints the skipped fixture
  name, implementation status, and concrete reason instead of relying only on
  aggregate skip counts.
- Add fake-agent protocol rows to the compatibility manifest.  The oracle
  runner now treats grouped exact `cargo test` cases as runnable agent
  fixtures, so session binding, host-bound signing, retry flags,
  destination-constrained behavior, confirmation denial, fallback behavior, and
  identity ordering appear in the same inventory as `ssh -G`, `sshd -T`, and
  non-runnable gap records.
- Expand fake-agent coverage for destination-constrained keys without SSH
  context.  Tests now cover both fallback to another usable identity and
  fail-closed behavior when no fallback credential is available.
- Extend fake-agent oracle coverage for agent certificate identities.  The
  identity-ordering fixture now runs configured certificate pairing, raw-key
  backed certificate pairing, agent certificate key-algorithm filtering, and
  agent certificate CA-signature filtering tests.
- Normalize OpenSSH oracle manifest descriptions around login behavior.
  Fixture rows now describe the login policy, authorization, host-trust, or
  agent-signing behavior being pinned, rather than only naming the directive or
  parser feature being exercised.
- Document the initial OpenSSH oracle baseline policy.  The compatibility
  oracle now treats the operating system plus OpenSSH client and server
  available on development and CI hosts as the initial baseline, prints exact
  tool versions on each run, and requires version-specific fixtures or
  explicit deviations for behavior that differs across supported OpenSSH or
  operating-system versions.
- Expand OpenSSH client oracle coverage for identity edge cases.  The fixture
  corpus now records `IdentityFile none`, `CertificateFile none`, tilde path
  handling, and command-line additive identity and certificate options.
- Add OpenSSH oracle coverage for disabling the agent.  Client fixtures and
  resolver tests now pin `IdentityAgent none` as the OpenSSH spelling that
  disables agent-backed identity use.
- Add OpenSSH oracle coverage for environment-selected agent sockets.  Client
  fixtures and resolver tests now pin that `IdentityAgent $VAR` remains the
  resolved `ssh -G` spelling and is treated as a runtime agent-socket
  reference, while `IdentityAgent ${VAR}` expands during client configuration
  resolution and fails closed when the variable is unset.
- Start an OpenSSH-compatible client configuration resolver.  The internal
  `ssh_config` module now handles the initial oracle-covered behavior:
  `Host`, `Include`, `Match`, negated host patterns, first-value-wins scalar
  resolution, additive identity and certificate files, command-line-style
  overrides, canonicalization knobs, and basic algorithm modifiers.
- Honor OpenSSH environment expansion in client `Include` paths.  Client
  config parsing now expands `${VAR}` in include patterns, leaves `$VAR`
  literal, and ignores unset include variables without making the login
  configuration fatal, with `ssh -G` fixture coverage.
- Expand OpenSSH client `Include` glob parity.  Client config parsing now
  expands case-sensitive wildcard path components such as `conf.d/*/*.conf`
  in sorted order, with local resolver and `ssh -G` fixture coverage.
- Honor additional client canonicalization policy plumbing.  The resolver now
  parses OpenSSH defaults and configured values for `CanonicalizeMaxDots` and
  `CanonicalizePermittedCNAMEs`, with `ssh -G` oracle coverage alongside the
  existing `CanonicalizeHostname`, `CanonicalDomains`, and
  `CanonicalizeFallbackLocal` fixtures.
- Honor OpenSSH `CanonicalizeHostname always` parsing.  The client resolver
  now preserves `always` as a distinct resolved policy value and the OpenSSH
  oracle pins its `ssh -G` normalization.
- Honor initial OpenSSH client config file precedence.  The initiator defaults
  to user config before system config, and `SSHKEY_SSH_CONFIG` supplies an
  explicit ordered override list with regression coverage.
- Fail closed on malformed explicit client config path overrides.  A supplied
  `SSHKEY_SSH_CONFIG` value must now contain at least one non-empty path and no
  empty colon-list elements, instead of silently dropping those elements or
  falling back to default client config files.
- Add initial client command-line-style configuration overrides.  Initiator
  policy now parses newline-separated `ssh_config` directives from
  `SSHKEY_SSH_CONFIG_OPTIONS` before configured files, rejects `Host` and
  `Match` blocks in that override text, and fails closed on malformed
  override options.
- Honor OpenSSH `IgnoreUnknown` in client override parsing.  Unknown
  command-line-style client override directives now fail closed unless the
  first `IgnoreUnknown` pattern list covers them, with wildcard matching and
  known non-login client directives left available for ordinary configs.
- Fail closed on malformed explicit client override environment values.
  `SSHKEY_SSH_CONFIG_OPTIONS`, `SSHKEY_RESOLVED_HOST`, `SSHKEY_PORT`,
  `SSHKEY_SSH_CONFIG_TAGS`, and `SSHKEY_USER` now reject invalid environment
  values instead of treating them as absent.  `SSHKEY_USER` must also be
  non-empty and free of whitespace and control characters.
- Add initial client target-port integration input.  `SSHKEY_PORT` now
  supplies the effective SSH target port for initiator policy, takes
  precedence over configured client files, and fails closed on malformed or
  zero values.
- Add initial client resolved-host integration input.  `SSHKEY_RESOLVED_HOST`
  now supplies the effective SSH destination host for initiator policy, takes
  precedence over configured `HostName`, and fails closed on malformed values.
- Fail closed on malformed client target-host context.  Supplied `SSHKEY_HOST`
  and `SSHKEY_RESOLVED_HOST` values must now be valid host names or IP
  addresses, instead of ignoring bad test overrides or carrying malformed host
  policy into login.
- Add initial client selected-tag integration input.  `SSHKEY_SSH_CONFIG_TAGS`
  now supplies OpenSSH `ssh -P tag`-style initial tags for `Match tagged`
  client config resolution, with matching `ssh -G` oracle coverage.
- Start a typed client login-context boundary.  Initiator policy resolution now
  collects adapter-fed SSH client inputs into a `ClientLoginContext` before
  applying OpenSSH config overrides, known-hosts overrides, host-address
  policy, and SSH session-binding policy.
- Parse client path-list environment inputs at the context boundary.
  `ClientLoginContext` now carries typed OpenSSH client config and known-hosts
  path vectors instead of raw colon-separated environment strings, keeping
  malformed-list failures in the environment adapter.
- Parse the client target-host override at the context boundary.
  `ClientLoginContext` now owns `SSHKEY_HOST` validation and host-name
  normalization, while the GSS target-name helper only decodes the supplied
  target name.
- Use the client context home directory for login path expansion.  Identity,
  user known-hosts, revoked-hosts, `IdentityAgent`, and `KnownHostsCommand %d`
  expansion now consume the `ClientLoginContext` home path instead of rereading
  `HOME` during policy construction.
- Capture the client home directory from the context environment snapshot.
  `ClientLoginContext::from_adapter_sources()` now derives its `HOME` path from
  the same captured environment map carried by the context, instead of
  separately
  rereading process `HOME`.
- Use the client context local user for default account selection.  A missing
  client `User` now falls back to `ClientLoginContext` instead of rereading
  `USER` while building initiator policy.
- Capture the client local user from the context environment snapshot.
  `ClientLoginContext::from_adapter_sources()` now derives its fallback local
  user from the same captured environment map carried by the context, instead
  of separately rereading process `USER`.
- Use the client context for agent-socket environment lookups.  `IdentityAgent`
  `SSH_AUTH_SOCK`, `$VAR`, and `${VAR}` socket references now resolve from
  `ClientLoginContext` instead of rereading process environment during
  initiator policy construction.
- Use the client context for configured path environment expansion.
  `IdentityFile`, `CertificateFile`, `UserKnownHostsFile`, `RevokedHostKeys`,
  and config-time `IdentityAgent ${VAR}` expansion now consume environment
  values captured in `ClientLoginContext` rather than rereading process
  environment during initiator policy construction.
- Use the client context for `KnownHostsCommand` argument environment
  expansion.  Helper argument `${VAR}` expansion now consumes the environment
  values captured in `ClientLoginContext` and carried into `ClientPolicy`,
  instead of rereading process environment during host-trust checks.
- Parse client adapter inputs from a single environment snapshot.
  `ClientLoginContext::from_adapter_sources()` now resolves prototype client
  `SSHKEY_*` variables from one captured environment map, preserving
  fail-closed empty and non-Unicode values while letting tests construct the
  adapter snapshot directly.
- Move client target-host parser tests off process environment mutation.
  Direct tests for `SSHKEY_HOST` normalization and fail-closed invalid values
  now construct `ClientLoginContext` snapshots instead of setting prototype
  environment variables.
- Move client override parser tests off process environment mutation.
  Command-line-style `SSHKEY_SSH_CONFIG_OPTIONS`, resolved host, port, tags,
  and user override tests now construct `ClientLoginContext` snapshots instead
  of setting prototype environment variables.
- Move client policy context tests off process environment mutation.
  Host-address, known-hosts override, malformed config path override, and
  SSH session-binding context tests now construct `ClientLoginContext`
  snapshots instead of setting prototype environment variables.
- Split client policy resolution from the environment adapter.  The
  environment-backed `resolve_client_policy()` now delegates to a
  context-taking resolver, and client path and missing-environment tests use
  captured `ClientLoginContext` values instead of mutating process variables.
- Document the SSH login context boundary.  `ARCHITECTURE.md` now classifies
  client, server, account, transport, and mechanism-local context fields by
  source of truth and records which fields are transcript-bound,
  agent-policy-bound, policy-only, or mechanism-local.
- Use the client context for `ssh_config` parser environment.  Client config
  `Include ${VAR}`, `%d` path expansion, and `Match exec` shell selection now
  consume a `ClientConfigContext` built from `ClientLoginContext`; the mechanism
  path calls context-taking parser and resolver entrypoints, with regression
  coverage for config-file resolution through the captured context.
- Use the server context for `sshd_config` include-home expansion.  Server
  config `Include ~/...` path expansion now consumes a `ServerConfigContext`
  built from `ServerLoginContext.server_home`; the mechanism path calls
  context-taking parser and override entrypoints, with regression coverage for
  resolved server policy through the captured context.
- Add a versioned context-field helper entrypoint.  Tests and SSH stack
  integrations can now call `gss_sshkey_set_context_fields()` with v1 client,
  server, or mechanism-local field lists for already-resolved or
  transport-only facts; the GSS paths prefer the thread-local helper snapshot
  and fall back to the environment adapter only when no snapshot is set.
- Add context-field-driven GSS login exchange coverage.  A unit test now drives
  a successful client-first `gss_init_sec_context()` /
  `gss_accept_sec_context()` exchange using `gss_sshkey_set_context_fields()`
  for client config, server config, host key, authorized keys, SSH session id,
  and local continuation-state inputs instead of process environment.
- Add context-field-driven agent-bound login coverage.  A unit test now drives
  the same client-first GSS exchange with `agent-sock`, SSH session id, and
  session signature supplied through `gss_sshkey_set_context_fields()`,
  verifying that a destination-constrained fake agent sees
  `session-bind@openssh.com` and the OpenSSH host-bound userauth payload.
- Reserve prototype adapter variables from context-field `env:` escapes.  The
  v1 context-field helper now rejects `env:SSHKEY_*` names so callers must use
  typed SSH context field names instead of bypassing the field inventory with
  legacy environment adapter variables.
- Expand malformed context-field ABI coverage.  Unit tests now pin
  fail-closed behavior for unknown fields, invalid or reserved `env:` names,
  null field names, null non-empty values, oversized names and values, null
  field lists, and excessive field counts.
- Use the typed server context for acceptor user authorization.  The final
  acceptor path now passes the already resolved `ServerLoginContext` into
  user-key authorization instead of reconstructing server context from the
  environment adapter, with regression coverage against bad process
  environment values.
- Audit Milestone 1 process-environment reads.  Production login policy paths
  now use typed contexts or the shared adapter snapshot; remaining direct
  `env::var*` reads are the trace flag and the shared snapshot collector used
  by the compatibility adapter.
- Remove ambient temp-directory lookup from KRL helper queries.  KRL
  revocation checks still use the `ssh-keygen -Q` helper, but the temporary
  public-key query file is now created under the mechanism's explicit scratch
  directory instead of consulting `TMPDIR` through `env::temp_dir()`.
- Rename process-environment context constructors as adapter entrypoints.
  `ClientLoginContext`, `ServerLoginContext`, and `LocalMechanismContext` now
  use `from_adapter_sources()` and `from_process_env_values()` for the
  compatibility boundary that feeds typed login context from adapter sources.
- Move client local-user context tests off process environment mutation.  The
  local-user snapshot regression now constructs `ClientLoginContext` from an
  explicit adapter map and verifies resolved client policy keeps that captured
  user.
- Move client configuration resolver tests off ambient environment snapshots.
  The shared test resolver helper now constructs an explicit empty
  `ClientLoginContext`, and the `ssh_config` tilde-user test derives the
  current account from the OS user database instead of `$USER`.
- Move default client test helpers off ambient user and home environment.  The
  default test user now comes from the OS user database instead of `$USER`, and
  the remaining tilde-user assertion uses the explicit home-aware expansion
  helper instead of reading `$HOME`.
- Move authorized-command environment tests off process mutation.  The
  minimal OpenSSH helper environment regression now asks the child process to
  print its exact environment without setting or restoring parent environment
  variables.
- Make test temp directories collision-resistant.  The shared unit-test helper
  now combines a timestamp with an atomic counter and creates a fresh directory
  instead of reusing existing paths, avoiding parallel fake-agent Unix socket
  collisions.
- Add fake-agent coverage for partial session-binding context.  Agent-backed
  userauth now has tests proving a typed policy with an SSH session id but no
  session signature skips ssh-agent without sending requests, then either uses
  a later unencrypted identity or fails closed when no later identity exists.
- Complete the typed agent-policy path for fake-agent coverage.  Agent-backed
  userauth now derives `SshTransportContext` from the typed client policy and
  the verified host key, and runnable fake-agent fixtures cover
  `session-bind@openssh.com`, OpenSSH host-bound userauth payloads,
  destination-constrained refusal without peer context, confirmation-denial
  fallback, and fail-closed no-candidate behavior.  Real agent coverage remains
  tracked as explicit oracle gaps until a live SSH transport can supply peer
  identity.
- Freeze the v1 context-field inventory.  Direct unit coverage now pins every
  client, server, and mechanism-local field accepted by
  `gss_sshkey_set_context_fields()`, and the architecture and README docs list
  the role-specific field names plus the restricted `env:NAME` escape.
- Move userauth transcript construction to typed inputs.  Agent-backed
  signing, unencrypted private-key signing, and acceptor-side verification now
  use `SshTransportContext` plus `UserauthSignatureContext`, architecture docs
  identify transcript-bound and policy-only fields, and direct tests verify
  requested-user and offered-key changes break the signature input.
- Document v1 context-field binding status.  `ARCHITECTURE.md` now classifies
  every client, server, mechanism-local, and `env:NAME` v1 context field as
  transcript-bound, agent-policy-bound, policy-only, or mechanism-local.
- Rename client config expansion environment at the typed boundary.  The
  `ClientConfigContext` now exposes captured expansion variables as
  `captured_env`, keeping `env_values` naming only in adapter parser helpers
  and local test maps that construct prototype environment input.
- Rename server helper-command locale at the typed boundary.  The
  `ServerLoginContext` now exposes captured helper `LANG` values as
  `helper_command_locale`, matching that both authorized-keys and
  authorized-principals helper commands consume the same SSH helper `LANG`.
- Add ABI-level fail-closed coverage for incomplete session context.  A
  `gss_sshkey_set_context_fields()` test now proves that a valid
  `session-signature` field without `session-id` is accepted by the field
  transport but rejected by the typed client context before login policy uses
  it.
- Add ABI-level fail-closed coverage for malformed client policy context.  A
  `gss_sshkey_set_context_fields()` test now proves that a valid `host-addr`
  field transport is rejected by the typed client context when the supplied
  peer address is malformed.
- Expand ABI-level fail-closed coverage for malformed client target context.
  `gss_sshkey_set_context_fields()` tests now prove that valid `port`,
  `resolved-host`, `ssh-config-tags`, and `user` field transport is rejected by
  the typed client context when those SSH target or policy values are
  malformed.
- Add ABI-level fail-closed coverage for malformed client path context.  A
  `gss_sshkey_set_context_fields()` test now proves that valid `ssh-config`
  and `known-hosts` field transport is rejected by the typed client context
  when those path lists contain empty elements.
- Add GSS initiator fail-closed coverage for malformed client context fields.
  `gss_init_sec_context()` now has regression coverage proving that malformed
  typed `host-addr`, `port`, `resolved-host`, `ssh-config`, `known-hosts`,
  `session-signature`, and `host-key` inputs fail before an initial token is
  emitted.
- Add OpenSSH oracle coverage for missing client directive arguments.  The
  invalid client fixture and local resolver test now pin no-argument failures
  across host blocks, required config-composition directives, login-policy
  scalars, method controls, host-trust controls, canonicalization controls,
  path directives, socket directives, tags, and algorithm directives.
- Add OpenSSH oracle coverage for extra client canonicalization and tag
  arguments.  The invalid client fixture and local resolver now reject extra
  arguments for `CanonicalizeHostname`, `CanonicalizeFallbackLocal`,
  `CanonicalizeMaxDots`, `IgnoreUnknown`, and `Tag`.
- Make tilde-user home lookup reentrant.  Client path expansion now resolves
  `~user` through the existing `getpwnam_r()`-backed account lookup instead of
  `getpwnam()` shared static storage, avoiding parallel-test and runtime
  passwd lookup races.
- Add ABI-level fail-closed coverage for malformed server and local context.
  `gss_sshkey_set_context_fields()` tests now prove that valid `host-key` and
  `ctx-key` field transport still fails closed when the typed server or local
  context rejects empty host-key paths, malformed continuation-state keys, or
  empty `ctx-replay-dir` values.  The `gss_accept_sec_context()` server-first
  path now rejects those malformed fields before emitting an acceptor token.
- Add ABI-level fail-closed coverage for malformed server policy context.
  `gss_sshkey_set_context_fields()` tests now prove that valid `session-id`,
  `authorized-keys`, and `match-host` field transport is rejected by the typed
  server context when those SSH policy values are malformed.  The exported
  acceptor path now also covers malformed `sshd-config`, `session-id`,
  `authorized-keys`, `match-host`, `peer-addr`, `connection`, and
  `routing-domain` fields failing closed before a server-first token is
  emitted.
- Add ABI-level fail-closed coverage for malformed config option blocks.
  `gss_sshkey_set_context_fields()` tests now prove that valid
  `ssh-config-options` and `sshd-config-options` field transport is still
  rejected during client and server policy resolution when those OpenSSH
  option blocks are malformed.  The client `gss_init_sec_context()` path now
  rejects malformed `ssh-config-options` before emitting an initial token, and
  the `gss_accept_sec_context()` and resolved server authorization paths now
  cover malformed `sshd-config-options` failing closed even when host key or
  file-backed server config inputs would otherwise allow login.
- Name the compatibility adapter snapshot path explicitly.  The shared helper
  that chooses between pending context fields and the prototype process
  environment is now `adapter_values_for_role()`, and the only process
  snapshot collector is `current_adapter_env_values()`.
- Add ABI-level fail-closed coverage for malformed server transport context.
  `gss_sshkey_set_context_fields()` tests now prove that valid `peer-addr`,
  `connection`, and `routing-domain` field transport is rejected by the typed
  server context when those SSH transport values are malformed.
- Expand ABI-level client context-field coverage.  The direct
  `gss_sshkey_set_context_fields()` client feeder test now proves that valid
  `host`, `host-addr`, `known-hosts`, `ssh-config`, `ssh-config-options`,
  `session-id`, and `session-signature` fields reach the typed
  `ClientLoginContext`.
- Expand ABI-level server and local context-field coverage.  The direct
  `gss_sshkey_set_context_fields()` feeder test now proves that valid
  `sshd-config`, `sshd-config-options`, `host-key`, `session-id`,
  `authorized-keys`, `ctx-key`, and `ctx-replay-dir` fields reach the typed
  server and mechanism-local contexts.
- Rename server transport validation errors at the typed boundary.  The server
  adapter still reads `SSHKEY_PEER_ADDR`, `SSHKEY_CONNECTION`, and
  `SSHKEY_ROUTING_DOMAIN`, while parsed server login context errors now report
  the SSH `peer-addr`, `connection`, and `routing-domain` context fields.
- Rename server session, authorized-key, and match-host validation errors at
  the typed boundary.  The server adapter still reads
  `SSHKEY_SESSION_ID`, `SSHKEY_AUTHORIZED_KEYS`, and `SSHKEY_MATCH_HOST`,
  while parsed server login context errors now report the SSH `session-id`,
  `authorized-keys`, and `match-host` context fields.
- Rename internal host-key errors at the typed boundary.  Host-key path
  validation and hostauth construction now report the SSH `host-key` context
  field after `ServerLoginContext` has parsed the adapter value, leaving
  `SSHKEY_HOST_KEY` names only in the compatibility adapter parser.
- Rename internal server config read errors at the typed boundary.  Empty
  adapter values and missing configured files after `ServerLoginContext`
  parsing now report the SSH `sshd-config` context field.
- Rename internal client path-list errors at the typed boundary.  Low-level
  adapter parser tests still cover `SSHKEY_SSH_CONFIG` and
  `SSHKEY_KNOWN_HOSTS`, while parsed client login context errors now report
  the SSH `ssh-config` and `known-hosts` context fields.
- Rename internal replay-directory errors at the typed boundary.  The local
  adapter still parses `SSHKEY_CTX_REPLAY_DIR`, while shared replay-cache
  runtime failures now report the SSH `ctx-replay-dir` context field.
- Rename local context-key validation errors at the typed boundary.  The local
  adapter still reads `SSHKEY_CTX_KEY`, while parsed mechanism-local context
  errors now report the SSH `ctx-key` context field.
- Rename the client policy environment snapshot at the typed boundary.  The
  client login context and resolved client policy now expose captured
  integration environment as `captured_env`, leaving `env_values` naming in the
  adapter parsing helpers where prototype environment maps are still parsed.
- Rename client SSH session context fields at the typed boundary.  The
  initiator policy now carries the transport session id and host-key signature
  as `transport_session_id` and `transport_session_signature`, reflecting that
  these values bind both ssh-agent requests and non-agent userauth signatures.
- Rename the client-side verified host-key field at the typed boundary.  The
  client login context and initiator policy now carry the SSH transport's
  already-verified server host key as `verified_server_host_key`, leaving the
  legacy `SSHKEY_VERIFIED_HOST_KEY` name at the compatibility adapter.
- Rename client SSH session validation errors at the typed boundary.  The
  client adapter still reads `SSHKEY_SESSION_ID` and
  `SSHKEY_SESSION_SIGNATURE`, while parsed client login context errors now
  report the SSH `session-id` and `session-signature` context fields.
- Rename client target and policy validation errors at the typed boundary.
  Parsed client login context errors now report the SSH `host`, `host-addr`,
  `port`, `resolved-host`, `ssh-config-tags`, and `user` context fields.
  Non-Unicode adapter extraction failures now report the same typed field
  names.
- Rename context validation helpers at the typed boundary.  Internal client
  and server field validators now use `*_context` names instead of `*_env`
  names once their callers pass SSH context field labels, leaving `*_env`
  naming for the compatibility adapter entrypoints and extraction helpers.
- Rename internal typed context-field constants.  SSH context labels such as
  `host`, `session-id`, `host-key`, and `ctx-key` now use `CONTEXT_*_FIELD`
  constants internally, leaving `SSHKEY_*_ENV` names for the compatibility
  adapter variables.
- Rename env-free typed context constructors.  Directly constructed client,
  server, and local mechanism contexts now use `minimal()` constructors instead
  of `without_env()`, so non-adapter tests no longer describe typed context
  setup in terms of absent process environment.
- Name process-env-entry test helpers explicitly.  Client and server test
  helpers that still take prototype `SSHKEY_*` entry lists now use
  `*_process_env_entries` names, keeping the environment-adapter path visibly
  separate from normal typed-context construction.
- Rename adapter snapshot tests at the typed boundary.  Client and server
  context parser tests now use `*_adapter_snapshot` names, keeping explicit
  environment references for the adapter implementation rather than ordinary
  typed-context test names.
- Rename local context key parser tests at the typed boundary.  Direct context
  key parsing now asserts the `ctx-key` field label, while non-Unicode adapter
  extraction remains covered through the legacy `SSHKEY_CTX_KEY` input and
  reports the typed `ctx-key` field name.
- Move ordinary server-config tests off adapter entries.  The shared
  `server_context_for_config()` test helper now builds a typed
  `ServerLoginContext` directly, and the include-home regression sets
  `server_home` on that context instead of passing prototype `HOME` and
  `SSHKEY_SSHD_CONFIG` adapter values.
- Move valid server transport policy tests off adapter entries.  Authorized-key
  `from=`, `AuthorizedKeysCommand` token, `Match Host`, `Match Address`,
  `Match LocalAddress`, `Match LocalPort`, and `Match RDomain` tests now pass
  valid peer and connection context through typed `ServerLoginContext` fields,
  keeping malformed input cases on adapter-entry tests.
- Move valid server override tests off adapter entries.  The successful
  `sshd-config` path override and explicit `authorized-keys` override
  regressions now set typed `ServerLoginContext` fields directly, while
  malformed adapter values remain covered by adapter-entry tests.
- Move valid client override tests off adapter entries.  Command-line-style
  client config overrides, resolved host, port, tags, and remote user
  regressions now set typed `ClientLoginContext` fields directly, while
  malformed prototype values have a separate adapter-value test.
- Move valid client policy context tests off adapter entries.  Host-address,
  known-hosts override, and SSH session-binding regressions now set typed
  `ClientLoginContext` fields directly, while malformed prototype values remain
  covered by adapter-entry tests.
- Add a typed userauth SSH transport context.  Agent session binding, agent
  signatures, unencrypted private-key signatures, and acceptor-side signature
  verification now consume one `SshTransportContext` carrying the verified host
  key, SSH session id, and host-key signature instead of passing those values as
  unrelated optional arguments.
- Add a typed userauth signature context.  Transcript construction, agent-backed
  signing, unencrypted private-key signing, and acceptor-side signature
  verification now consume one `UserauthSignatureContext` carrying the requested
  user, offered key type, offered key blob, and selected signature algorithm.
- Honor initial client `ssh_config` `Match localuser` criteria.  The resolver
  now matches `localuser` against the local account independently from the
  configured remote `User`, with OpenSSH oracle coverage.
- Honor initial client `ssh_config` `Match exec` and criterion negation.  The
  resolver now evaluates `exec` commands through the user's shell, expands the
  supported SSH tokens before execution, and supports negated criteria and
  comma-separated pattern lists for client `Match` conditions.
- Reject malformed OpenSSH client `Match` criteria.  Client fixtures and
  resolver tests now fail closed for empty `Match` directives, missing
  criterion arguments, unsupported attributes, and invalid `all` combinations.
- Honor initial client `ssh_config` tag matching.  The resolver now handles
  `Tag` directives and `Match tagged` criteria, including initial tags supplied
  through command-line-style overrides and OpenSSH's sequential matching
  behavior.
- Honor initial client `ssh_config` `Match final` and `Match canonical`
  criteria.  The resolver now models OpenSSH's ordinary pass followed by
  final/canonical match blocks, preserving additive option ordering for
  identity files; later DNS canonicalization rows cover canonical match state.
- Implement initial client DNS hostname canonicalization.  When
  `CanonicalizeHostname` is enabled, the initiator now tries configured
  `CanonicalDomains` for host names within `CanonicalizeMaxDots`, uses the
  first resolvable candidate as the effective host name, and reruns client
  config resolution with `Match canonical` active.
- Honor initial client `CanonicalizePermittedCNAMEs` enforcement.  When the
  system resolver exposes a distinct canonical name through `AI_CANONNAME`,
  the initiator now follows that rewrite only when a configured source and
  target pattern rule permits it; `none` remains the fail-closed default.
  Later resolver-shim rows pin OpenSSH's source-to-exposed-name behavior.
- Reject invalid OpenSSH client canonicalization list syntax.  Client fixtures
  and resolver tests now fail closed for mixed `none` `CanonicalDomains` and
  `CanonicalizePermittedCNAMEs` lists, invalid canonical-domain names, and
  malformed permitted-CNAME rules.
- Honor initial `CanonicalizeFallbackLocal no` failure behavior.  When
  hostname canonicalization is enabled but no configured canonical-domain
  candidate resolves, the initiator now records a client configuration error,
  disables advertised initiator key algorithms, and fails before emitting a
  GSS token instead of silently falling back to the original host.
- Wire the initial client configuration resolver into initiator userauth
  policy.  The initiator now resolves client config files, honors
  `IdentityAgent`, `IdentitiesOnly`, configured public-key identities, the
  requested user, and advertised public-key algorithm policy for agent-backed
  user authentication.
- Add the first OpenSSH-compatible client token expansion.  The resolver now
  expands `%h`, `%n`, `%p`, `%r`, `%u`, and `%%` for `HostName` and
  `IdentityAgent`, while the initiator expands those tokens when opening
  configured `IdentityFile` paths.
- Honor initial OpenSSH client path environment expansion.  `IdentityFile` and
  `CertificateFile` expand `${VAR}` references at use time, while
  `IdentityAgent`, `UserKnownHostsFile`, and `RevokedHostKeys` follow
  OpenSSH's resolved-config behavior, including fail-closed errors for unset
  variables where OpenSSH rejects the option.
- Add initial local `authorized_keys` authorization.  The acceptor now checks
  plain OpenSSH authorized-key entries for the requested user before marking
  a userauth token authenticated, while option-bearing entries fail closed
  unless their options can be reduced to a login decision.
- Add initial GSS local-name authorization.  Accepted authenticated source
  names now carry an internal authorization marker, `gss_localname()` returns
  the authorized user name, and `gss_authorize_localname()` only succeeds for
  an authenticated exact local-name match.
- Add initial `sshd_config` authorization policy.  The acceptor now resolves
  `PubkeyAuthentication`, `AuthorizedKeysFile`, and `Match User`, `Match Host`,
  and `Match Address` from `SSHKEY_SSHD_CONFIG` or `/etc/ssh/sshd_config`
  before checking authorized-key files.
- Add config-driven `Match Host` and `Match Address` login authorization
  coverage.  Unit tests now verify that resolved match blocks can deny or
  allow an otherwise authorized key in the `user_key_authorization()` path
  based on SSH integration host and peer-address inputs.
- Add config-driven `Match User` login authorization coverage.  Unit tests now
  verify that resolved user match blocks can change the authorized-keys file
  used by the `user_key_authorization()` path.
- Preserve OpenSSH server `PubkeyAuthentication` yes/no policy.  The server
  resolver now tracks enabled and disabled states distinctly, while the GSS
  acceptor treats this as SSH method-control instead of disabling
  GSS-SSHKEY's internal key signatures.
- Add initial server `AuthenticationMethods` parsing.  The server resolver now
  preserves OpenSSH method-list alternatives and `any` so an SSH integration
  layer can make the same method-sequencing login decision as sshd.
- Fail closed on unsupported server authentication-method names.  The server
  resolver now rejects malformed `AuthenticationMethods` lists with unknown
  method names, empty comma elements, or `any` mixed into a list.
- Add initial server `GSSAPIAuthentication` parsing.  The server resolver now
  carries global and `Match`-scoped method availability so an SSH integration
  can decide whether this GSS mechanism is enabled for login.
- Enforce initial server GSSAPI method availability.  The acceptor now
  requires resolved `GSSAPIAuthentication yes` and either unrestricted
  `AuthenticationMethods` or a single-method `gssapi-with-mic` alternative
  before completing a GSS-SSHKEY login.
- Add acceptor-path coverage for GSSAPI-only server method policy.  Unit
  tests now prove that `PubkeyAuthentication no` does not block GSS-SSHKEY
  user-key authorization when `GSSAPIAuthentication yes` and
  `AuthenticationMethods gssapi-with-mic` select the GSS path, while
  multi-method requirements and `GSSAPIAuthentication no` still block
  completion.  A later single-method `gssapi-with-mic` alternative remains
  accepted.
- Expose resolved server method-control policy for SSH integration.  Acceptor
  contexts now retain the resolved `GSSAPIAuthentication`,
  `AuthenticationMethods`, public-key, password, keyboard-interactive,
  empty-password, PAM, retry-limit, grace-period, algorithm, RSA-size,
  strict-modes, security-key public-key option, and account allow/deny
  controls, and
  `gss_sshkey_inquire_context_server_policy()` reports those values.
- Report resolved server authorization inputs for SSH integration.  The server
  policy inquiry now reports `AuthorizedKeysFile`, `AuthorizedKeysCommand`,
  `AuthorizedKeysCommandUser`, `TrustedUserCAKeys`,
  `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`,
  `AuthorizedPrincipalsCommandUser`, and `RevokedKeys`.
- Report resolved `PermitRootLogin` server policy for SSH integration.  The
  server policy inquiry now exposes the resolved mode while preserving the
  login-only boundary where `forced-commands-only` is reported but not treated
  as a mechanism-side login grant.
- Retain historical off-scope server password/keyboard-interactive parser
  inventory.  Existing rows record `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, and the `ChallengeResponseAuthentication`
  alias only as method-selection guardrails.
- Retain historical off-scope server hostbased parser inventory.  Existing
  rows record `HostbasedAuthentication` only so method-selection guardrails can
  keep GSS-SSHKEY gated by `GSSAPIAuthentication` and compatible
  `AuthenticationMethods`.
- Add initial server `PermitEmptyPasswords` policy plumbing.  The server
  resolver now carries OpenSSH's global and `Match`-scoped empty-password
  login policy alongside password authentication availability.
- Add initial server `UsePAM` policy plumbing.  The server resolver now parses
  OpenSSH's global `UsePAM` setting so later account-management integration can
  match sshd's login decision.
- Add initial server `MaxAuthTries` policy plumbing.  The server resolver now
  parses OpenSSH's global and `Match`-scoped authentication-attempt limit so an
  SSH integration can mirror sshd's login retry policy.
- Add initial server `LoginGraceTime` policy plumbing.  The server resolver
  now parses OpenSSH's global pre-authentication login timeout so an SSH
  integration can mirror sshd's authentication grace-period policy.
- Honor initial server public-key algorithm policy.  The acceptor now parses
  `PubkeyAcceptedAlgorithms`, the legacy `PubkeyAcceptedKeyTypes` alias, and
  `CASignatureAlgorithms`; advertised and accepted user signature algorithms
  are filtered through the resolved server policy, with legacy `ssh-rsa` and
  `ssh-dss` disabled by default unless server configuration permits them.  The
  server policy inquiry reports the resolved public-key algorithm list.
- Add `PubkeyAcceptedAlgorithms` login authorization coverage.  Unit tests now
  verify that resolved server public-key algorithm policy can reject or accept
  an otherwise authorized user key in the `user_key_authorization()` path.
- Honor initial server key revocation policy.  The acceptor now parses
  `RevokedKeys` and rejects matching user public keys from plain OpenSSH and
  KRL public-key revocation files, failing closed when a configured revocation
  file cannot be read, parsed, or queried, including through the resolved
  `user_key_authorization()` path.
- Add `RevokedKeys none` authorization coverage.  The server fixture,
  resolver tests, and login authorization-path tests now pin that `none`
  disables the server revocation source.
- Enforce initial server `CASignatureAlgorithms` for user certificates.  The
  acceptor now uses OpenSSH's default CA signature algorithm list and rejects
  `TrustedUserCAKeys` certificates whose CA signature algorithm is not allowed
  by the resolved server policy.  The server policy inquiry reports the
  resolved CA signature algorithm list.
- Add `CASignatureAlgorithms` login authorization coverage.  Unit tests now
  verify that resolved server CA signature policy changes certificate
  acceptance in the `user_key_authorization()` path.
- Enforce the first local `authorized_keys` options.  Plain public-key entries
  with `from` and `expiry-time` restrictions now participate in authorization:
  `from` is checked against `SSHKEY_MATCH_HOST` and `SSHKEY_PEER_ADDR` with
  wildcard, negated, and CIDR patterns, while `expiry-time` rejects expired
  keys.  Unsupported option-bearing entries continue to fail closed.
- Add `authorized_keys from` login authorization coverage.  Unit tests now
  verify that `user_key_authorization()` enforces host, peer-address, and
  negated `from` patterns from the config-selected `AuthorizedKeysFile`.
- Add `authorized_keys expiry-time` login authorization coverage.  Unit tests
  now verify that `user_key_authorization()` rejects expired local
  authorized-key entries and accepts unexpired entries from the
  config-selected `AuthorizedKeysFile`.
- Fail closed on malformed explicit authorized-keys path overrides.  A
  supplied `SSHKEY_AUTHORIZED_KEYS` value must now contain at least one
  non-empty path and no empty colon-list elements, instead of falling back to
  configured `AuthorizedKeysFile` paths.
- Recognize initial security-key presence options in `authorized_keys` and
  authorized-principals files.  `touch-required`, `no-touch-required`,
  `verify-required`, and `no-verify-required` no longer cause otherwise
  matching public-key and certificate-authority entries to be rejected.
- Carry matched security-key touch/verify requirements into signature policy.
  Local `authorized_keys`, `AuthorizedKeysCommand`, authorized-principals
  files, `AuthorizedPrincipalsCommand`, and user-certificate `verify-required`
  and `no-touch-required` options now feed final FIDO/security-key signature
  flag enforcement after a specific authorization source matches, with
  regression coverage for `no-verify-required` overriding an earlier
  `verify-required` on the same authorized-key entry and for OpenSSH-style
  certificate/source merging where `no-touch-required` must be present on both
  sides to suppress touch while `verify-required` from either side requires
  user verification.
- Honor initial server `PubkeyAuthOptions` for FIDO/security-key signatures.
  The acceptor now parses global and `Match`-scoped `PubkeyAuthOptions` and
  enforces `touch-required` and `verify-required` by checking OpenSSH SK
  signature flags after signature verification.  These options have no effect
  on non-SK key types, matching sshd.
- Add initial SK signature algorithm support.  The GSS mechanism now treats
  `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` as
  supported user signature algorithms so agent-backed security keys can reach
  the login authorization policy path.
- Add `PubkeyAuthOptions` login authorization coverage.  Unit tests now verify
  that `user_key_authorization()` enforces configured `verify-required` and
  `touch-required` security-key policy on otherwise authorized SK keys,
  including server `touch-required` overriding a matching
  `no-touch-required` authorized-key entry.
- Honor initial server `RequiredRSASize` policy.  The acceptor now parses
  global and `Match`-scoped `RequiredRSASize` and rejects undersized RSA user
  keys and RSA certificate subject keys, while preserving OpenSSH's 1024-bit
  minimum floor.  The server policy inquiry reports the resolved value.
- Add `RequiredRSASize` login authorization coverage.  Unit tests now verify
  that a resolved `sshd_config` `RequiredRSASize` setting changes the
  `user_key_authorization()` result for otherwise authorized RSA keys and RSA
  certificate subject keys.
- Add initial `AuthorizedKeysCommand` execution.  The acceptor now parses
  `AuthorizedKeysCommand` and `AuthorizedKeysCommandUser`, runs the command
  after local authorized-key files miss, expands `%f`, `%h`, `%k`, `%t`, `%U`,
  `%u`, `%C`, `%D`, and `%%`, bounds stdout and runtime, executes as the
  configured user when privileges allow it, and parses stdout as
  `authorized_keys` data.  `%C` and `%D` are supplied by the integration
  through `SSHKEY_CONNECTION` and `SSHKEY_ROUTING_DOMAIN`.
- Add config-driven `AuthorizedKeysCommand` login authorization coverage.
  Unit tests now verify that resolved `sshd_config` command output can
  authorize an otherwise unavailable user key in the `user_key_authorization()`
  path.
- Add `AuthorizedKeysCommand` token-expansion coverage.  Unit tests now pin
  `%u`, `%h`, `%t`, `%k`, `%f`, `%U`, `%C`, `%D`, and `%%` expansion for
  command arguments.
- Add `AuthorizedKeysCommand` failure-behavior coverage.  Unit tests now
  verify fail-closed handling for nonzero command exits and stdout that exceeds
  the configured output bound, and for `%C` or `%D` token expansion when the
  SSH integration has not supplied connection or routing-domain context.
- Add `AuthorizedKeysCommand none` coverage.  The server fixture, resolver
  tests, and authorization-path tests now pin that `none` disables the command
  authorization source even when `AuthorizedKeysCommandUser` is configured.
- Add authorization command timeout coverage.  Unit tests now verify that the
  shared `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` runner kills
  overlong commands and fails closed instead of using late command output.
- Honor OpenSSH's initial helper-command environment.  The shared
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` runner now clears
  inherited process variables and supplies only the OpenSSH-style `PATH`,
  `USER`, `LOGNAME`, `HOME`, and inherited `LANG` variables to helper
  commands.
- Use the server context for authorization-helper locale inheritance.
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` now receive
  inherited `LANG` from `ServerLoginContext`, instead of rereading process
  environment when the helper command is executed.
- Honor OpenSSH's default helper-command argument.  When
  `AuthorizedKeysCommand` or `AuthorizedPrincipalsCommand` is configured with
  only a program path, the runner now passes the target username as the single
  command argument, with shared unit coverage for both helper types.
- Honor initial command-user `%u` expansion.  `AuthorizedKeysCommandUser` and
  `AuthorizedPrincipalsCommandUser` now expand `%u` to the target user before
  resolving the account to execute as.
- Honor initial `PermitRootLogin` policy for public-key authorization.  Root
  and uid-0 aliases are denied when resolved server policy says
  `PermitRootLogin no`; `yes`, `prohibit-password`, and `without-password`
  permit public-key-style authentication, while `forced-commands-only` is not
  treated as an unrestricted login grant in the login-only path.
- Honor initial user allow/deny account policy.  The acceptor now parses
  cumulative `AllowUsers` and `DenyUsers` directives, including `Match` block
  additions, and enforces user and `user@host` patterns against the requested
  user, `SSHKEY_MATCH_HOST`, and `SSHKEY_PEER_ADDR`.  `DenyUsers` takes
  precedence over `AllowUsers`, matching sshd's authorization order.  The
  server policy inquiry reports the resolved user allow and deny lists.
- Add config-driven `AllowUsers` and `DenyUsers` login authorization coverage.
  Unit tests now verify that resolved server account policy rejects, accepts,
  and then denies an otherwise authorized user key in the
  `user_key_authorization()` path.
- Honor initial group allow/deny account policy.  The acceptor now parses
  cumulative `AllowGroups` and `DenyGroups` directives, including `Match`
  block additions, and enforces them against the target user's primary and
  supplemental groups.  `DenyGroups` takes precedence over `AllowGroups`.
  The server policy inquiry reports the resolved group allow and deny lists.
- Add config-driven `AllowGroups` and `DenyGroups` login authorization
  coverage.  Unit tests now verify that resolved server group policy rejects,
  accepts, and then denies an otherwise authorized user key in the
  `user_key_authorization()` path.
- Add initial server certificate-authorization configuration plumbing.  The
  acceptor now resolves `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`,
  `AuthorizedPrincipalsCommand`, and `AuthorizedPrincipalsCommandUser`, so
  certificate authorization can use the same `sshd_config` policy inputs.
- Add initial client certificate identity selection.  Configured
  `CertificateFile` paths now contribute certificate blobs to
  `IdentitiesOnly` filtering, agent-listed certificate identities are parsed
  enough to choose the underlying signature algorithms, and signature
  verification can use the public key embedded in a certificate blob.
- Ignore non-user client identity certificates.  Configured `CertificateFile`
  entries, implicit `IdentityFile` `-cert.pub` files, and agent-listed
  certificate identities now match OpenSSH userauth by skipping host
  certificates during client identity selection.
- Honor initial implicit client certificate pairing.  When no
  `CertificateFile` is configured, `IdentityFile`-derived `-cert.pub`
  certificates now contribute certificate blobs to agent identity filtering
  and are ordered before the matching raw `IdentityFile` key; explicit
  `CertificateFile` entries are preferred, and `CertificateFile none`
  suppresses implicit certificate discovery.
- Add initial client method-control parsing.  The client resolver now parses
  `AddKeysToAgent`, `PubkeyAuthentication`, and `PreferredAuthentications`
  in first-value-wins OpenSSH order.  `PubkeyAuthentication no` is treated as
  an SSH method-control setting and does not disable GSS-SSHKEY's internal
  key signatures when the mechanism is invoked through GSSAPI.
- Add initial client `GSSAPIAuthentication` policy plumbing.  The client
  resolver now carries OpenSSH's GSSAPI method-control setting so an SSH
  integration can decide whether the GSS-SSHKEY mechanism should be selected
  for login.
- Carry initial client method-control policy into initiator policy.
  `GSSAPIAuthentication`, `PubkeyAuthentication`, and
  `PreferredAuthentications` now survive client config resolution as policy
  inputs for an SSH integration layer, while `PubkeyAuthentication no` still
  does not suppress GSS-SSHKEY's internal user-key signatures after GSSAPI has
  been selected.
- Expose resolved client method-control policy for SSH integration.
  Initiator policy now preserves `AddKeysToAgent` alongside GSSAPI, public-key,
  hostbased, password, keyboard-interactive, keyboard-interactive-device,
  preferred-authentication, batch, prompt-count, host-key-update,
  known-hosts-hashing, and host-trust controls.
  It also preserves resolved target, user, agent, and identity-selection
  inputs.  `gss_sshkey_inquire_context_client_policy()` reports those values
  for an enclosing SSH stack, plus resolved public-key, host-key, and
  CA-signature algorithm policy.
- Enforce initial client GSSAPI method selection.  The initiator now refuses
  to emit GSS tokens when resolved client policy has
  `GSSAPIAuthentication no` or `PreferredAuthentications` does not include
  `gssapi-with-mic`, while still treating `PubkeyAuthentication no` as an SSH
  method-control setting rather than a ban on the mechanism's internal user
  key signatures.
- Honor OpenSSH `AddKeysToAgent confirm` lifetimes.  The client resolver now
  parses `confirm <duration>` distinctly from bare `confirm` and from plain
  lifetime-only settings.
- Honor initial client prompt-control policy plumbing.  The resolver now
  parses `BatchMode` and `NumberOfPasswordPrompts`, validates them against
  `ssh -G`, and carries the resolved values into initiator policy for the
  enclosing SSH layer.
- Report no mechanism-side private-key prompting.  The client policy inquiry
  reports resolved `BatchMode` and `NumberOfPasswordPrompts`, but
  `private-key-prompting` is always `no`: encrypted `IdentityFile` keys must
  be unlocked through `ssh-agent`, not by prompting inside the GSS mechanism.
- Report client SSH transport context presence for SSH integration.  The client
  policy inquiry now reports whether a verified transport host key, SSH
  session id, and SSH session signature are present for host-bound
  ssh-agent signing, without exposing the raw values.
- Report resolved client home directory for SSH integration.  The client
  policy inquiry now reports the typed home directory used for
  OpenSSH-compatible path expansion.
- Report resolved client user-signature algorithm policy for SSH integration.
  The client policy inquiry now reports the signature algorithm names the
  initiator will offer for user authentication.
- Add initial OpenSSH default identity-file enumeration.  When no applicable
  `IdentityFile` is configured, the client resolver now supplies OpenSSH's
  built-in default identity paths; explicit `IdentityFile` entries, including
  `IdentityFile none`, suppress those defaults.
- Honor initial client `CASignatureAlgorithms` policy.  The client resolver
  now parses `CASignatureAlgorithms` with OpenSSH's default CA signature
  algorithm list and `+`, `^`, and `-` modifiers.
- Enforce client `CASignatureAlgorithms` for identity certificates.  Configured
  `CertificateFile` entries, implicit `IdentityFile -cert.pub` sidecars, and
  agent-listed certificate identities are skipped when their CA signature
  algorithm is not allowed by resolved client policy.
- Honor OpenSSH client algorithm wildcard modifiers and invalid-name
  rejection.  Client fixtures and resolver tests now pin wildcard expansion
  for `PubkeyAcceptedAlgorithms`, `HostbasedAcceptedAlgorithms`,
  `HostbasedKeyTypes`, `HostKeyAlgorithms`, and `CASignatureAlgorithms`, plus
  fail-closed unknown algorithm names and extra arguments.
- Align initial client public-key and host-key algorithm defaults with
  OpenSSH.  The resolver now uses OpenSSH's default
  `PubkeyAcceptedAlgorithms`, `HostbasedAcceptedAlgorithms`, and
  `HostKeyAlgorithms` lists, including certificate and security-key
  algorithms, while the GSS-SSHKEY protocol advertises only the signature
  algorithms this implementation supports.
- Enforce initial client `PubkeyAcceptedAlgorithms` key-type policy for
  userauth.  Initiator userauth now skips agent-backed and unencrypted
  `IdentityFile` candidates whose raw key or certificate key type is not
  allowed by resolved client policy.
- Enforce initial `HostKeyAlgorithms` client policy for hostauth.  Initiator
  hostauth verification now rejects host keys whose authenticated key type or
  verified signature type is not permitted by resolved `HostKeyAlgorithms`.
- Honor initial client `UpdateHostKeys` policy plumbing.  The client resolver
  now parses `UpdateHostKeys`, carries `yes`, `no`, and `ask` through
  initiator policy, and reports the value so an SSH integration can decide
  whether it should perform known-hosts updates.  The OpenSSH fixture corpus
  still pins `ssh -G -T` no-TTY normalization separately.
- Honor initial locked-account policy.  Server authorization now rejects
  target users whose passwd or readable shadow password entry begins with an
  OpenSSH-style locked or disabled account marker such as `!` or `*`.
- Honor initial account-expiry policy.  Server authorization now rejects
  target users whose readable shadow account expiration date has passed,
  matching OpenSSH's shadow-day comparison.  If shadow data is unavailable, it
  falls back to passwd lock markers only.
- Enforce initial `AuthorizedKeysCommand` program safety.  The configured
  command must be an absolute, canonical, root-owned program whose file and
  system-owned parent directories are not writable by group or other users
  before it is executed.
- Honor initial `StrictModes` policy for local `authorized_keys` files.  With
  the OpenSSH default of `yes`, local authorized-key files are ignored unless
  the file and checked parent directories are owned by root or the target user
  and are not writable by group or other users; `StrictModes no` disables this
  check.
- Honor OpenSSH `AuthorizedKeysFile` `%U` token expansion.  Local
  authorized-key file paths and the prototype override now expand `%U` to the
  target user's numeric uid, alongside `%u`, `%h`, and `%%`.
- Add server OpenSSH oracle coverage for `AuthorizedKeysFile none`.  The
  fixture and local resolver tests now pin the login-auth behavior where local
  authorized-key files are disabled for a matched user.
- Add `AuthorizedKeysFile none` authorization-path coverage.  Login
  authorization tests now pin that `none` disables local authorized-key files
  even when an otherwise matching configured file exists.
- Add initial `sshd_config` `Include` support.  Server configuration parsing
  now resolves relative includes against the containing file, expands
  case-sensitive wildcard path components in sorted order, and parses included
  global and `Match` directives in place.
- Pin missing-target server `Include` behavior.  A focused `sshd -T` row now
  proves a missing include target is skipped while later login policy still
  applies, with local parser coverage that fixed missing includes and unmatched
  globs do not record errors.
- Pin server `Include` scoping inside `Match` blocks.  Focused `sshd -T` rows
  now prove included login directives inherit the active `Match User` scope,
  unmatched users keep global login policy, and following matched directives
  stay in that scope, with local parser coverage for the same included-file
  boundary.
- Restore server `Include` scope after nested included `Match` blocks.  The
  parser now matches OpenSSH's behavior where a `Match` inside an included file
  does not leak into later parent-file directives or users outside the parent
  match.  Focused `sshd -T` rows pin parent, included, nested-user, and
  unrelated-user match-scope boundaries.
- Honor initial `sshd_config` `Match Group` criteria.  Acceptor
  authorization now resolves server policy with the target user's primary and
  supplemental group names so group-scoped public-key controls apply.
- Honor initial `sshd_config` `Match` local connection criteria.  Acceptor
  policy now uses `SSHKEY_CONNECTION` for `LocalAddress` and `LocalPort` and
  `SSHKEY_ROUTING_DOMAIN` for `RDomain` when resolving server configuration.
- Add config-driven local connection `Match` login authorization coverage.
  Unit tests now verify that resolved `LocalAddress`, `LocalPort`, and
  `RDomain` match criteria can deny or allow an otherwise authorized key in
  the `user_key_authorization()` path.
- Start a typed server login-context boundary.  Acceptor authorization now
  collects adapter-fed server config, `Match` host/address, local connection,
  and routing-domain inputs into a `ServerLoginContext` before resolving
  OpenSSH-compatible login policy.
- Parse server local-connection ports as typed values at the context boundary.
  `ServerLoginContext` now stores `SSHKEY_CONNECTION` client and server ports
  as validated `u16` values, stringifying only for OpenSSH token expansion and
  `sshd_config` `Match LocalPort` pattern comparison.
- Pin server `Match LocalPort` value validation.  Focused `sshd -T` rows now
  prove nonnumeric, out-of-range, and negated `Match LocalPort` patterns fail
  closed, and the local parser rejects the same values before policy
  resolution.
- Pin standalone server `Match LocalPort` selection.  A focused `sshd -T` row
  now proves `Match LocalPort 2222` applies only to the matching local port and
  leaves other local ports at global defaults, with local resolver coverage for
  a standalone local-port criterion separate from the combined
  local-address/RDomain case.
- Pin missing-criteria failures for server `Match` attributes.  Focused
  `sshd -T` rows now prove `Match Group`, `Match Host`, `Match Address`,
  `Match LocalAddress`, `Match LocalPort`, and `Match RDomain` without values
  fail closed, and parser regression covers those errors.
- Pin bare-negation server `Match` pattern behavior.  Focused `sshd -T` rows
  now prove `Match User !` and `Match Host !` are accepted no-match patterns,
  while `Match Address !` and `Match LocalAddress !` fail closed; local parser
  regressions cover the same address-family split.
- Pin valid negated server `Match User` patterns.  A focused `sshd -T` row now
  proves `Match User deploy*,!deployblocked` excludes the negated login user
  from an otherwise matching wildcard, with local resolver coverage for
  positive, negated, and outside users.
- Pin valid negated server `Match Host` patterns.  Focused `sshd -T` rows now
  prove `Match Host *.example,!blocked.example` preserves the wildcard match,
  excludes the negated canonical host, and leaves unrelated hosts unchanged,
  with local resolver coverage for positive, negated, and outside hosts.
- Pin server `Match Group` empty-pattern behavior.  Focused `sshd -T` rows now
  prove leading and trailing empty group-pattern segments are ignored while
  wildcard group patterns still match, and an all-empty group-pattern list
  leaves login policy unchanged.  The local resolver keeps all-empty
  group-pattern lists from matching.
- Pin valid negated server `Match Group` patterns.  Focused `sshd -T` rows now
  prove `Match Group root,!no-such-gss-sshkey-group` matches root and leaves a
  nonmatching login user unchanged, while `Match Group *,!root` excludes root's
  account group from an otherwise matching wildcard and leaves a nonmatching
  login user unchanged.  Local resolver coverage now exercises wildcard group
  negation.
- Pin non-IP slash server address `Match` patterns.  Focused `sshd -T` rows now
  prove `Match Address not-an-address/24` and `Match LocalAddress
  not-an-address/24` are accepted as non-matching address patterns for normal
  IP criteria, and local resolver coverage keeps those forms non-fatal.
- Pin valid negated CIDR server address `Match` patterns.  Focused `sshd -T`
  rows now prove `Match Address 192.0.2.0/24,!192.0.2.13` preserves the CIDR
  match, excludes the negated peer address, and leaves unrelated peer
  addresses unchanged.  Focused rows also prove `Match LocalAddress
  198.51.100.0/24,!198.51.100.13` preserves the local CIDR match, excludes the
  negated local address, and leaves unrelated local addresses unchanged, with
  local resolver coverage for both peer and local address criteria.
- Pin valid negated wildcard server address `Match` patterns.  Focused
  `sshd -T` rows now prove `Match Address 192.0.2.*,!192.0.2.13` preserves
  the wildcard match, excludes the negated peer address, and leaves unrelated
  peer addresses unchanged.  Focused rows also prove `Match LocalAddress
  198.51.100.*,!198.51.100.13` preserves the local wildcard match, excludes
  the negated local address, and leaves unrelated local addresses unchanged,
  with local resolver coverage for both peer and local address criteria.
- Pin valid negated server `Match RDomain` patterns.  Focused `sshd -T` rows
  now prove `Match RDomain rd*,!rdblocked` preserves the wildcard match,
  excludes the negated routing domain, and leaves unrelated routing domains
  unchanged, with local resolver coverage for the same positive and negated
  cases.
- Parse authorized-keys override lists at the server context boundary.
  `ServerLoginContext` now owns `SSHKEY_AUTHORIZED_KEYS` colon-list parsing,
  while per-user path template expansion still happens in the authorization
  path where uid and home directory are known.
- Use the account context for per-user authorized-file tilde expansion.
  `AuthorizedKeysFile` and `AuthorizedPrincipalsFile` bare `~` paths now use
  the target account home already supplied to the template expander, instead of
  rereading process `HOME` through the generic path helper.
- Use the server context for global trust and revocation tilde expansion.
  `RevokedKeys` and `TrustedUserCAKeys` bare `~` paths now use the server home
  captured in `ServerLoginContext`, instead of rereading process `HOME` while
  evaluating login authorization.
- Parse server adapter inputs from a single environment snapshot.
  `ServerLoginContext::from_adapter_sources()` now resolves prototype server
  `SSHKEY_*`, helper locale, and server home values from one captured
  environment map, preserving fail-closed empty and invalid values while
  letting tests construct the adapter snapshot directly.
- Move server context parser tests off process environment mutation.  Direct
  tests for SSH connection tuples, `Match` host context, and routing-domain
  validation now call the typed parser helpers instead of setting prototype
  environment variables.
- Move server host-key context tests off process environment mutation.  The
  explicit host-key path parser test now constructs `ServerLoginContext`
  snapshots directly, preserving fail-closed missing, empty, malformed, and
  valid key-file coverage without mutating process-global state.
- Move server SSH session-id context tests off process environment mutation.
  The acceptor session-id parser test now constructs `ServerLoginContext`
  snapshots directly, preserving absent, valid, and malformed hex coverage
  without mutating process-global state.
- Move server helper-locale context tests off process environment mutation.
  The authorized-command locale snapshot test now constructs
  `ServerLoginContext` snapshots directly and still verifies helper execution
  receives the captured `LANG` value rather than a later local value.
- Move initial server authorization tests off process environment mutation.
  GSSAPI method policy, invalid server config, revocation, authorized-keys
  override, `from`, expiry, command, account allow/deny, and `Match` user,
  host, address, and local-connection policy tests now construct
  `ServerLoginContext` snapshots instead of setting prototype environment
  variables.  Required RSA size, accepted algorithms, security-key
  `PubkeyAuthOptions`, touch-required override, trusted CA, and
  authorized-principals file and command tests use the same context path.  The
  typed-context authorization regression now compares allow and deny server
  contexts directly instead of poisoning process-global server config inputs.
- Use the server context for authorization-helper connection tokens.
  `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` now receive `%C`
  and `%D` values from the already-validated `ServerLoginContext` instead of
  rereading `SSHKEY_CONNECTION` and `SSHKEY_ROUTING_DOMAIN` in the helper
  authorization path.
- Load the acceptor host key at the server context boundary.  Hostauth
  generation and final userauth transcript binding now consume the
  `ServerLoginContext` host key instead of rereading `SSHKEY_HOST_KEY`.
- Parse the acceptor SSH session id at the server context boundary.  Final
  userauth transcript binding now consumes the `ServerLoginContext` session id
  instead of rereading `SSHKEY_SESSION_ID`.
- Fail closed on malformed server address context.  Supplied
  `SSHKEY_PEER_ADDR` and `SSHKEY_CONNECTION` address fields must now be valid
  IPv4 or IPv6 addresses, and `SSHKEY_CONNECTION` ports must be nonzero TCP
  ports; invalid values become server configuration errors instead of being
  treated as missing login context.
- Fail closed on malformed server host and routing-domain context.  Supplied
  `SSHKEY_MATCH_HOST` must now be a valid host name or IP address, and
  `SSHKEY_ROUTING_DOMAIN` must be non-empty and free of whitespace and control
  characters; invalid values become login-denying transport context errors.
- Honor initial `sshd_config` `Match Invalid-User` criteria.  Acceptor
  authorization now resolves server policy with an invalid-user marker when
  the requested local account does not exist, before rejecting that account.
- Expand `authorized_keys` `from` host matching.  Local files and
  `AuthorizedKeysCommand` output now evaluate `from` patterns against the
  supplied peer hostname as well as the peer address, with negation applying
  across both values.
- Honor initial local `authorized_keys` `cert-authority` entries for user
  certificates.  Local authorized-key files can now authorize a user
  certificate through a matching CA public key marked `cert-authority`, with
  `principals`, `from`, and `expiry-time` options enforced alongside
  certificate validity and critical-option checks, including through the
  resolved `user_key_authorization()` path.  Session-restricted CA entries
  fail closed there instead of becoming plain login grants.
- Honor initial `AuthorizedKeysCommand` certificate output.  Command output
  can now authorize user certificates through matching `cert-authority` CA
  entries, and `%f`, `%k`, and `%t` expand from the offered certificate blob
  when the offered key is a certificate.  The resolved
  `user_key_authorization()` path now covers command-output certificate
  authorization and login-relevant restrictions, while session-restricted
  command-output CA entries fail closed.
- Add initial server command-line-style configuration overrides.  Acceptor
  policy now parses newline-separated `sshd_config` directives from
  `SSHKEY_SSHD_CONFIG_OPTIONS` before the configured file, so tests can model
  `sshd -o`-style settings while preserving
  first-value global resolution and later `Match` overrides.  The resolved
  `user_key_authorization()` path now covers both override-enabled login and
  later matching-file denial.
- Fail closed on malformed explicit server config path overrides.  A supplied
  `SSHKEY_SSHD_CONFIG` value must now name a non-empty, readable path, instead
  of falling back to an empty server configuration when the explicit file cannot
  be read.  The authorization adapter path now covers empty and missing
  explicit config paths failing closed before key authorization can succeed.
- Honor initial CIDR matching for server address criteria.  `sshd_config`
  `Match Address` and `Match LocalAddress` now support CIDR ranges in addition
  to wildcards and negated patterns.
- Honor initial client `ProxyJump` token context.  The client resolver now
  parses `ProxyJump` in first-value-wins order with `ProxyCommand`, and
  `KnownHostsCommand` expands `%j` to the configured jump chain, or to empty
  when unset, `none`, or suppressed by an earlier `ProxyCommand`.
- Add OpenSSH oracle coverage for `ProxyJump` and `ProxyCommand` resolution.
  The fixture corpus now pins ordinary jump chains, fallback jumps, explicit
  `ProxyJump none`, `ProxyCommand none`, and proxy directive precedence
  suppressing later fallback output from `ssh -G`.
- Add initial configured-first ordering for agent identities.  Agent-backed
  user authentication now tries identities matching resolved configured
  `IdentityFile` and `CertificateFile` blobs before other agent identities,
  and appends unconfigured agent identities only when `IdentitiesOnly` is off.
- Align initial private-key fallback ordering with OpenSSH.  Userauth now
  tries unencrypted `IdentityFile` certificate candidates before configured
  agent-backed identities, then unconfigured agent identities when
  `IdentitiesOnly` is off, and then raw unencrypted `IdentityFile`
  candidates.
- Make client identity candidate ordering explicit.  Userauth signing now
  builds an ordered candidate plan with private-certificate, configured-agent,
  unconfigured-agent, and raw-private-key fallback sources before attempting
  signatures.  Configured candidates now retain whether they came from
  `CertificateFile`, an implicit `IdentityFile` `-cert.pub` sidecar, or a raw
  `IdentityFile` path, with direct tests for policy source recording and plan
  order.
- Add initial agent certificate/private-key pairing.  Agent-backed user
  authentication can now offer a configured user certificate when the agent
  only lists the matching raw public key, and `IdentitiesOnly` accepts an
  agent-listed certificate when its subject public key is configured.  Unit
  and fake-agent userauth tests cover both pairing directions.
- Document initial agent certificate/private-key pairing.  README and
  architecture notes now describe configured certificates backed by matching
  raw agent keys, while keeping exact candidate ordering listed as incomplete.
- Add initial initiator handling for signature retry tokens.  When the
  acceptor asks for a new user signature with a retry token, the initiator now
  reuses the established transcript state and attempts a fresh agent-backed
  userauth signature filtered by the retry algorithm list.
- Add initial fake-agent coverage for retry signing.  Unit tests now drive the
  retry userauth path through a fake SSH agent, verify that the acceptor's
  retry algorithm list filters the selected signature, and assert that RSA
  SHA-2 sign requests carry the OpenSSH ssh-agent flag values.
- Add fake-agent coverage for security-key userauth signing.  Unit tests now
  drive the encrypted userauth path with an agent-listed
  `sk-ssh-ed25519@openssh.com` identity, verify the OpenSSH SK signature flags,
  and verify the final SK signature against the userauth transcript.
- Add fake-agent coverage for client identity policy.  Unit tests now exercise
  configured-first identity ordering, `IdentitiesOnly`, and `IdentityAgent`
  environment sockets through the actual SSH agent request path.
- Add an initial ssh-agent session-binding hook.  When an SSH integration
  supplies hex-encoded `SSHKEY_SESSION_ID` and `SSHKEY_SESSION_SIGNATURE`
  values, initiator user authentication sends OpenSSH
  `session-bind@openssh.com` on the same agent connection used for identity
  listing and signing.
- Add fake-agent ordering coverage for session binding.  Unit tests now verify
  that `session-bind@openssh.com` is sent before identity listing and signing
  on the agent connection that performs user authentication.
- Add initial OpenSSH host-bound agent signing payload support.  When the SSH
  integration supplies a verified host key and SSH session id, userauth signing
  asks ssh-agent to sign the OpenSSH
  `publickey-hostbound-v00@openssh.com` payload so destination-constrained keys
  can inspect the requested user, session id, offered key, and host key.
- Add fake-agent destination-constrained policy coverage.  The fake agent can
  now model a key that signs only after a matching
  `session-bind@openssh.com` request and OpenSSH host-bound userauth payload,
  and tests cover both accepted context and missing-context refusal before
  unencrypted `IdentityFile` fallback.
- Add fake-agent coverage for missing verified host-key context.  If the
  client has SSH session-binding data but no verified acceptor host key, the
  initiator skips agent identity listing and signing before falling back to a
  configured unencrypted `IdentityFile` candidate, or fails closed when no
  later candidate is available.
- Bind userauth signatures to the verified host key.  The user signature
  transcript now includes the acceptor host public key when hostauth is
  available, and fake-agent coverage verifies that the same signature no
  longer validates under a different host key.
- Fail closed on malformed explicit acceptor host-key path overrides.  A
  supplied `SSHKEY_HOST_KEY` value must now name a non-empty, readable OpenSSH
  private key, instead of silently suppressing hostauth when the explicit file
  cannot be read or parsed.
- Bind userauth signatures to the SSH transport session id.  When
  `SSHKEY_SESSION_ID` is supplied, the user signature transcript now includes
  it, and fake-agent coverage verifies that the same signature no longer
  validates under a different session id.
- Fail closed on malformed SSH session-binding context.  The client now
  rejects supplied `SSHKEY_SESSION_ID` and `SSHKEY_SESSION_SIGNATURE` values
  that are not valid non-empty hex, rejects a session signature without a
  session id, and the acceptor rejects malformed session ids before verifying
  userauth transcripts.
- Add initial unencrypted `IdentityFile` private-key fallback.  Initiator
  policy now reads unencrypted OpenSSH private keys from resolved
  `IdentityFile` paths, records their public blobs for identity filtering, and
  signs certificate candidates before configured agent-backed candidates while
  leaving raw private-key candidates after unconfigured agent identities.
- Add initial configured-certificate private-key fallback.  When no usable
  agent signature is available, an unencrypted `IdentityFile` private key can
  now offer a matching configured `CertificateFile` certificate before the raw
  public key.
- Honor initial OpenSSH private-key file permission checks.  Unencrypted
  `IdentityFile` fallback now applies OpenSSH's owner-sensitive exposed-key
  check: group or other permission bits reject a key only when the file is
  owned by the invoking user.
- Honor encrypted `IdentityFile` public-key filtering.  Initiator policy now
  reads the public key embedded in encrypted OpenSSH private-key files for
  configured identity and `IdentitiesOnly` agent selection, while keeping those
  encrypted keys out of unencrypted private-key fallback signing.
- Add initial agent sign-failure fallback behavior.  Initiator userauth now
  treats an `ssh-agent` sign failure as a failed identity candidate, continues
  to later agent identities and later non-agent candidates, and can fall back
  to a configured unencrypted `IdentityFile` private key, or fails closed when
  no later candidate is available.
- Add fake-agent coverage for agent sign-failure fallback.  Unit tests now
  cover a failed agent identity followed by a later successful agent identity,
  modeling confirmation denial or other per-key agent failures, and no-candidate
  fail-closed behavior.
- Add explicit fake-agent confirmation-denial coverage.  Focused cargo-backed
  rows now model a confirmation-required key whose sign request returns
  `SSH_AGENT_FAILURE`, verify that it receives the OpenSSH host-bound userauth
  payload first, and then continue to a later successful agent identity, fall
  back to a configured unencrypted `IdentityFile`, or fail closed when no
  later candidate is available.
- Add userauth-path RSA SHA-2 retry signature coverage.  Unit tests now drive
  the encrypted userauth path with an RSA agent identity and retry-filtered
  `rsa-sha2-512` and `rsa-sha2-256` algorithm lists, verifying the OpenSSH
  `SSH_AGENT_RSA_SHA2_512` and `SSH_AGENT_RSA_SHA2_256` sign-request flags,
  decrypted userauth payloads, and final RSA/SHA-2 signature verification.
- Add fake-agent coverage for mismatched signature algorithms.  Unit tests now
  verify that an agent response carrying a signature algorithm different from
  the requested RSA/SHA-2 algorithm is rejected before a userauth credential is
  emitted, and that the initiator can continue to a later valid agent
  identity.
- Add fake-agent coverage for wrong-key signatures.  Unit tests now verify
  that a syntactically valid agent signature made by a different private key
  than the advertised identity key is rejected before a userauth credential is
  emitted, and that the initiator can continue to a later valid agent
  identity.
- Add userauth-path legacy `ssh-rsa` retry signature coverage.  The RSA
  signing path now supports explicit SHA-1 RSA signatures when client and
  server policy both allow `ssh-rsa`, and fake-agent tests verify the
  OpenSSH zero sign-request flag, decrypted userauth payload, and final
  signature verification.
- Add fake-agent coverage for malformed sign replies and disconnects.  Unit
  tests now verify that a malformed agent sign response is treated as a failed
  identity candidate, that malformed sign responses and agent disconnects can
  fall back to a configured unencrypted `IdentityFile`, and that both cases
  fail closed when no later candidate is available.
- Add fake-agent coverage for identity-list and session-bind failures.  Unit
  tests now verify that agent identity-list refusal or malformed output falls
  back to configured unencrypted `IdentityFile` keys or fails closed when no
  later candidate is available, and that a refused `session-bind@openssh.com`
  prevents agent signing before fallback or fail-closed completion.
- Add initial `TrustedUserCAKeys` user-certificate authorization.  The
  acceptor now accepts valid user certificates signed by configured trusted
  CAs, matching the requested local user principal, with unsupported critical
  options rejected.  `PubkeyAcceptedAlgorithms` must allow the certificate key
  type and signature algorithm.  `RevokedKeys` rejects matching certificate
  subject or CA public keys from plain text and KRL revocation files, including
  through the resolved `user_key_authorization()` path.
- Add `TrustedUserCAKeys none` authorization coverage.  The server fixture,
  resolver tests, and trusted-CA authorization-path tests now pin that `none`
  disables trusted-CA certificate login authorization.
- Add config-driven `TrustedUserCAKeys` login authorization coverage.  Unit
  tests now verify that a resolved `sshd_config` CA file can authorize a user
  certificate in the `user_key_authorization()` path.
- Honor initial user-certificate `source-address` critical options.  The
  acceptor now enforces comma-separated exact-address, CIDR, and negated
  source-address lists against `SSHKEY_PEER_ADDR` and fails closed when the
  peer address is unavailable, invalid, or outside the allowed ranges, including
  through the resolved `user_key_authorization()` path.  Other critical options
  remain rejected in this login-only milestone.
- Honor initial `AuthorizedPrincipalsFile` certificate authorization.  User
  certificates signed by `TrustedUserCAKeys` can now match configured
  authorized-principals files instead of the requested local user name, with
  `StrictModes`, globbed file paths, and the supported `from` and
  `expiry-time` options enforced.
- Add config-driven `AuthorizedPrincipalsFile` login authorization coverage.
  Unit tests now verify that a resolved `sshd_config` principals file can
  authorize a non-local-name user-certificate principal in the
  `user_key_authorization()` path, that `from` and `expiry-time` restrictions
  are enforced there, and that a session-restricted principal line fails
  closed instead of becoming a plain login grant.
- Add `AuthorizedPrincipalsFile` token-expansion coverage.  Trusted-CA
  authorization-path tests now pin OpenSSH-style `%h`, `%u`, `%U`, and `%%`
  expansion for configured authorized-principals file paths.
- Add `AuthorizedPrincipalsFile none` coverage.  The server fixture,
  resolver tests, and trusted-CA authorization-path tests now pin that `none`
  disables the principals file source while preserving OpenSSH's local-user
  principal fallback.
- Add initial `AuthorizedPrincipalsCommand` certificate authorization.  The
  acceptor now executes the configured command as
  `AuthorizedPrincipalsCommandUser`, requires the same safe root-owned command
  path as `AuthorizedKeysCommand`, expands OpenSSH command tokens including
  `%u`, `%h`, `%U`, `%F`, `%f`, `%K`, `%k`, `%i`, `%s`, `%T`, `%t`, `%C`,
  `%D`, and `%%`, bounds stdout and runtime, and parses stdout as
  authorized-principals data.
- Add config-driven `AuthorizedPrincipalsCommand` login authorization
  coverage.  Unit tests now verify that a resolved `sshd_config` principals
  command can authorize a non-local-name user-certificate principal in the
  `user_key_authorization()` path, that command-output `from` and
  `expiry-time` restrictions are enforced there, and that session-restricted
  command output fails closed instead of becoming a plain login grant.
- Match OpenSSH authorized-principals file-to-command fallback.  When
  `TrustedUserCAKeys` is configured with both `AuthorizedPrincipalsFile` and
  `AuthorizedPrincipalsCommand`, a file miss now falls through to the command
  source while a matching non-login file entry still fails closed.
- Keep local-user principal fallback disabled when authorized-principals
  sources are configured.  A configured `AuthorizedPrincipalsFile` or
  `AuthorizedPrincipalsCommand` now requires a match from those sources; the
  implicit requested-local-user principal is used only when neither source is
  active.
- Add `AuthorizedPrincipalsCommand` failure-behavior coverage.  Unit tests now
  verify fail-closed handling for nonzero exits, stdout that exceeds the
  configured output bound, unsafe command paths, command timeout, and command
  token expansion that requires missing `%C` or `%D` SSH transport context,
  including the resolved `user_key_authorization()` path.
- Add `AuthorizedPrincipalsCommand none` coverage.  The server fixture,
  resolver tests, and trusted-CA authorization-path tests now pin that `none`
  disables the command principal source even when
  `AuthorizedPrincipalsCommandUser` is configured.
- Fail closed on authorization material that is not a pure login grant.  Key,
  certificate, authorized-principals, and server options that do not answer
  the login question are parsed only far enough to avoid treating them as
  unrestricted login authorization.
- Make non-login authorization fail-closed coverage deterministic.  Unit tests
  now exercise restricted authorization inputs without mutating process-wide
  environment, so the login-only boundary remains stable under parallel tests.
- Add initial install targets.  `make install` now stages `sshkey.so` and a
  GSS mechanism config fragment with overridable `DESTDIR`, `PREFIX`,
  `LIBDIR`, `SYSCONFDIR`, GSS mechanism directory, mechanism name, and OID
  variables; `make uninstall` removes those installed files from the same
  path set.
- Document initial Heimdal and MIT krb5 mechanism registration.  README now
  describes default install paths, Heimdal-style `name oid library
  kernel-module` registration, MIT-style `name oid library` registration, and
  the `GSS_MECH_CONFIG_FORMAT=mit` install override.
- Carry initial key and certificate identity in login authorization result data.
  The mechanism-specific authorization inquiry API now reports the matched key
  type, key fingerprint, signature algorithm, and user-certificate serial, key
  id, and CA fingerprint when applicable.
- Carry initial certificate-principal mapping data in login authorization result
  data.  The mechanism-specific authorization inquiry API now reports the
  offered user certificate's valid principals, including OpenSSH's
  all-principals special case.
- Carry initial authorization source classification in login authorization
  result data.  The mechanism-specific authorization inquiry API now reports
  whether a key matched local authorized-key files, `AuthorizedKeysCommand`, or
  `TrustedUserCAKeys`, and whether a certificate principal matched the local
  user, an authorized-principals file, or `AuthorizedPrincipalsCommand`.
- Match OpenSSH authorization source order for user certificates.  The
  resolved userauth path now checks local authorized-key files before
  `TrustedUserCAKeys` and command fallback, and a matching local file entry
  that is not a plain login grant fails closed instead of falling through to a
  later unrestricted trusted-CA source.  Matching trusted-CA principal data
  that is not a plain login grant likewise fails closed before
  `AuthorizedKeysCommand` fallback.
- Require local-name authorization to carry SSH authorization data.
  `gss_localname()`, `gss_authorize_localname()`, and
  `gssspi_authorize_localname()` now reject source names that are marked
  authenticated but do not carry a matched user authorization result.
- Add local-name authorization coverage for SSH policy results.  Unit tests
  now verify that local-name authorization succeeds only when SSH key policy
  produced authorization data, rejects a wrong local user, and rejects
  authorization results denied by key revocation, expired certificates, wrong
  certificate principals, or missing authorization data.
- Carry initial authorized local-user mapping into local-name authorization.
  Login authorization results now record the target local account; when a
  source name displays a different authorized-principals certificate identity,
  `gss_localname()`, `gss_authorize_localname()`, and
  `gssspi_authorize_localname()` use the recorded local account.
- Treat `PermitRootLogin forced-commands-only` as outside the plain-login
  grant.  Root authorizations under that policy fail closed at the GSSAPI
  layer because command execution happens after authentication.
- Add initial OpenSSH KRL revocation support.  `RevokedHostKeys` and
  `RevokedKeys` now detect OpenSSH KRL files and query them with
  `ssh-keygen -Q`, failing closed if the KRL cannot be queried or marks any
  offered key, certificate subject, or certificate CA as revoked.
- Settle the near-term KRL dependency strategy.  KRL revocation remains backed
  by OpenSSH `ssh-keygen -Q` rather than a native parser; packaging must include
  `ssh-keygen`, and helper failures continue to fail closed.
- Settle the near-term `russh` dependency strategy.  `gss-sshkey` does not
  depend on `russh` for now; it keeps focused SSH key/config/agent code and
  should reconsider a narrow `russh` component only if an OpenSSH oracle row
  exposes a concrete compatibility gap.
- Report adapter parsing errors with SSH context field names.  Adapter lookup
  still uses the prototype `SSHKEY_*` keys internally, but invalid context
  values now report typed field names such as `user`, `ssh-config`, and
  `ctx-key`.
- Freeze integration-facing context-field tests around typed field constants.
  The v1 ABI inventory, successful login-exchange tests, agent-bound exchange
  test, and malformed-context GSS entrypoint tests now use the same
  `CONTEXT_*_FIELD` names as the mapper instead of duplicating field strings.
- Split client SSH transport facts inside the typed login context.  Parsed
  client session id, session signature, and verified server host key now live
  in `ClientSshTransportContext`, leaving `ClientLoginContext` focused on
  command, config, path, and user inputs.
- Split client target facts inside the typed login context.  The original
  target host, resolved host, port, and `CheckHostIP` peer address now live in
  `ClientTargetContext`, leaving `ClientLoginContext` focused on client
  config, user, local process facts, and owned sub-contexts.
- Split client config-input facts inside the typed login context.  Explicit
  client config path lists, inline config options, known-host path overrides,
  initial config tags, and requested remote-user overrides now live in
  `ClientConfigInputContext`, leaving `ClientLoginContext` focused on
  local process facts and owned sub-contexts.
- Split client local process facts inside the typed login context.  The client
  local user, home directory, and captured environment for path expansion,
  `Match exec`, agent socket lookup, and helper-command execution now live in
  `ClientLocalContext`, leaving `ClientLoginContext` as an owner of typed
  sub-contexts.
- Split server SSH transport facts inside the typed login context.  Parsed
  acceptor session id now lives in `ServerSshTransportContext`, leaving
  `ServerLoginContext` focused on server config, host key, peer, connection,
  helper locale, and server home inputs.
- Split server config-input facts inside the typed login context.  Explicit
  `sshd_config` path, inline `sshd_config` options, and authorized-key path
  overrides now live in `ServerConfigInputContext`, leaving
  `ServerLoginContext` focused on host key, helper locale, server home, and
  owned sub-contexts.
- Split server local process facts inside the typed login context.  Server
  home and captured helper-command locale now live in `ServerLocalContext`,
  leaving `ServerLoginContext` focused on host key and owned sub-contexts.
- Split server host-key facts inside the typed login context.  The acceptor
  private host key now lives in `ServerHostKeyContext`, leaving
  `ServerLoginContext` as an owner of typed sub-contexts.
- Split server peer facts inside the typed login context.  Parsed `Match`
  host, peer address, local connection tuple, and routing domain now live in
  `ServerPeerContext`, leaving `ServerLoginContext` focused on server config,
  host key, helper locale, server home, and owned sub-contexts.
- Split local mechanism facts inside the typed context.  The
  continuation-state seal key and shared replay-cache directory now live in
  `LocalContextKey` and `LocalReplayCacheContext`, leaving
  `LocalMechanismContext` as an owner of typed sub-contexts.
- Add an explicit adapter snapshot boundary.  Pending v1 context fields or
  process environment are now collected into `AdapterContextSnapshot` before
  the client, server, and mechanism-local adapter constructors parse them into
  typed context objects.
- Move adapter value reads behind snapshot accessors.  Client, server, and
  mechanism-local sub-context constructors now consume
  `AdapterContextSnapshot` string, os-string, hex, public-key, home, and locale
  accessors instead of raw environment maps.
- Store pending v1 context fields under SSH context names.  Explicit fields
  supplied through `gss_sshkey_set_context_fields()` now remain keyed as
  `host`, `session-id`, `sshd-config`, `ctx-key`, and related SSH concepts
  inside `AdapterContextSnapshot`; only process-environment fallback uses the
  prototype `SSHKEY_*` names.
- Make adapter snapshot lookup source-specific.  Process-environment
  snapshots now ignore SSH context field names, while explicit v1
  context-field snapshots ignore prototype `SSHKEY_*` names.
- Make adapter string decoding errors source-specific.  Non-Unicode process
  environment values still report invalid environment values, while
  non-Unicode explicit v1 fields now report invalid context field values.
- Make verified host-key decoding source-specific.  Explicit v1 `host-key`
  fields now accept only raw SSH public key blobs, while the legacy
  `SSHKEY_VERIFIED_HOST_KEY` process-environment adapter accepts the same
  value only as hex.
- Make SSH transport byte decoding source-specific.  Explicit v1 `session-id`
  and `session-signature` fields now preserve raw SSH transport bytes, while
  the legacy `SSHKEY_SESSION_ID` and `SSHKEY_SESSION_SIGNATURE`
  process-environment adapter values remain hex strings.
- Validate client local-user context at the typed boundary.  Explicit v1
  `local-user` fields and legacy `USER` adapter values now fail closed when
  they are empty, non-Unicode, whitespace-containing, or
  control-character-containing instead of silently falling back to `sshkey`.
- Validate explicit home context at the typed boundary.  Missing client or
  server home remains optional and empty legacy `HOME` adapter values remain
  absent for compatibility, but empty explicit v1 `home` fields now fail
  closed before policy resolution.
- Validate explicit client environment path aliases at the typed boundary.
  Missing `agent-sock` and `shell` fields remain optional and empty legacy
  `SSH_AUTH_SOCK` or `SHELL` adapter values remain absent for compatibility,
  but empty explicit v1 `agent-sock` and `shell` fields now fail closed before
  client policy resolution.
- Validate typed helper locale at the server boundary.  Legacy `LANG` and
  explicit `env:LANG` escapes remain raw helper environment values, while an
  explicit v1 `lang` field must be a non-empty Unicode string before server
  policy resolution.
- Make helper-command locale lookup source-specific.  Process-environment
  snapshots now collect `LANG`, while explicit v1 context-field snapshots
  collect only the typed `lang` field plus `env:LANG` helper-environment
  escapes.
- Clarify client context transcript binding.  The architecture now records
  that the requested user, supplied verified host key, and supplied SSH
  transport session id are userauth signature inputs, and a unit test pins
  that the fallback GSS-specific userauth transcript binds a supplied verified
  host key even when no SSH session id is available.
- Rename raw-map adapter constructors as process-env constructors.  The
  client, server, local, and test-helper constructors that consume prototype
  environment maps now use `from_process_env_values()` or
  `*_process_env_entries()` names so they cannot be confused with explicit v1
  context-field snapshots.
- Rename role-level adapter constructors as adapter-source constructors.  The
  client, server, and mechanism-local constructors that choose pending v1
  context fields or process-environment fallback now use
  `from_adapter_sources()`.
- Add server-side invalid-KRL coverage for `RevokedKeys`.  Unit tests now
  verify that a KRL-like user-key revocation file that cannot be queried fails
  closed instead of allowing the offered key, including through the resolved
  `user_key_authorization()` path.
- Fail closed on non-login user-certificate extensions.  Trusted-CA
  certificates that require behavior outside the login decision no longer
  authorize as unrestricted login grants, including through the resolved
  `user_key_authorization()` path.
- Fail closed on non-login `authorized_keys` options.  Options whose meaning
  cannot be reduced to the login decision now require explicit support instead
  of being treated as unrestricted login grants, including through the
  resolved `user_key_authorization()` path.
- Fail closed on user certificates that require behavior outside the login
  decision.  Trusted-CA certificates with unsupported critical options now
  have explicit `user_key_authorization()` path coverage proving they do not
  authorize.
- Add server `Match` oracle coverage for user negation and host criteria.
  The OpenSSH compatibility fixture and local resolver tests now pin
  login-relevant `Match User deploy,!blocked` and `Match Host` behavior.
- Add server `Match All` oracle coverage for login authentication policy.
  The server fixture and resolver tests now pin that all-user match blocks
  contribute authentication policy such as `PubkeyAuthOptions`.
- Keep the OpenSSH compatibility matrix login-only.  The server oracle now
  tracks login authorization inputs and no longer carries expectations for
  controls outside the login decision.
- Keep the documented and runtime scope login-only.  README and architecture
  notes now describe only login authorization for the current target, and the
  old runtime opt-in for post-login policy reporting is disabled.
- Keep server post-authentication settings out of GSS login authorization.
  Resolved server settings whose effects happen after authentication no longer
  create mechanism-side login restrictions or block ordinary non-root logins;
  key and certificate restrictions still fail closed.
- Expand server OpenSSH oracle coverage for account policy.  The fixture now
  pins login-relevant `PermitRootLogin`, cumulative `AllowUsers` and
  `DenyUsers`, and `RequiredRSASize` behavior against `sshd -T`.
- Add server OpenSSH oracle coverage for security-key authentication policy.
  The fixture now pins global and `Match`-scoped `PubkeyAuthOptions`
  resolution for login authentication.
- Expand server OpenSSH oracle coverage for group account policy.  The fixture
  now pins cumulative `AllowGroups` and `DenyGroups` behavior that affects
  login authorization.
- Expand server OpenSSH oracle coverage for command and certificate
  authorization inputs.  The fixture now pins `AuthorizedKeysCommand`,
  `AuthorizedPrincipalsFile`, `AuthorizedPrincipalsCommand`,
  `TrustedUserCAKeys`, and `CASignatureAlgorithms` login policy resolution.
- Add server OpenSSH oracle coverage for invalid-user account state.  The
  fixture now pins `Match Invalid-User` behavior for a missing account that
  should not be allowed to log in.
- Add server OpenSSH oracle coverage for local connection `Match` criteria.
  The fixture now pins `LocalAddress`, `LocalPort`, and `RDomain` policy
  resolution for login authorization.
- Fail closed on malformed implemented server login policy.  The server
  resolver now records missing, extra, invalid, and unterminated quoted
  arguments for implemented login-relevant `sshd_config` directives and
  `Match` criteria, and the acceptor refuses GSS login when resolved server
  policy carries such an error.
- Expand client OpenSSH oracle coverage for host-trust modes.  The fixture
  corpus now pins `StrictHostKeyChecking yes`, `ask`, `no`, and `off`, plus
  `VerifyHostKeyDNS ask` and `no` normalization from `ssh -G`.
- Expand client OpenSSH oracle coverage for public-key method modes.  The
  fixture corpus now pins `PubkeyAuthentication yes`, `no`, `unbound`, and
  `host-bound` normalization from `ssh -G`.
- Retain historical off-scope client password/keyboard-interactive parser
  inventory.  Existing rows record `PasswordAuthentication`,
  `KbdInteractiveAuthentication`, and the `ChallengeResponseAuthentication`
  alias only as method-selection guardrails.
- Retain historical off-scope client hostbased parser inventory.  Existing
  rows record `HostbasedAuthentication` only as method-selection inventory
  beside GSSAPI and public-key controls.
- Retain historical off-scope client `EnableSSHKeysign` parser inventory.
  Existing rows record OpenSSH's boolean setting and malformed arguments only;
  the mechanism does not invoke `ssh-keysign`.
- Retain historical off-scope client hostbased algorithm parser inventory.
  Existing rows record `HostbasedAcceptedAlgorithms` and `HostbasedKeyTypes`
  resolved output and malformed argument behavior only.
- Carry initial client external key-provider policy.  The client resolver now
  parses, validates, preserves, and reports `PKCS11Provider` and
  `SecurityKeyProvider`, including OpenSSH's default
  `SecurityKeyProvider internal` behavior and malformed argument coverage.
  Actual provider loading remains future identity-source work.
- Expand client OpenSSH oracle coverage for key and trust update policy.  The
  fixture corpus now pins `UpdateHostKeys`, `HashKnownHosts`, `CheckHostIP`,
  `FingerprintHash sha1`, mixed-case scalar values, and `AddKeysToAgent` mode
  and duration normalization from `ssh -G`.
- Expand client OpenSSH oracle coverage for command-line overrides.  The
  fixture corpus now pins `ssh -G -o` precedence for user, port, identity
  files, certificate files, `IdentitiesOnly`, `GSSAPIAuthentication`,
  `PreferredAuthentications`, and `PubkeyAuthentication`, with matching local
  resolver coverage.
- Add OpenSSH oracle coverage for negated client `Match` host criteria.  The
  focused `Match` criteria fixtures and local resolver tests now pin a
  negated `host` criterion alongside existing `originalhost`, `host`,
  `localuser`, `exec`, `!exec`, `user` pattern-list, tagged, canonical, and
  final `Match` coverage.
- Expand client OpenSSH oracle coverage for method defaults.  Focused default
  `ssh -G` rows now pin OpenSSH's empty-config defaults for
  `GSSAPIAuthentication`, public-key method control, non-scope login method
  toggles, `BatchMode`, `NumberOfPasswordPrompts`, and `AddKeysToAgent`, with
  matching local default-option assertions.
