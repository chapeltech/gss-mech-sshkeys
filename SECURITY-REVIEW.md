# Security Review

Reviewed: 2026-08-19

Status: all numbered findings resolved or accepted.
Additional cross-crate findings from the 2026-08-13 review are tracked in
`TODO.md`.

This document records a security review of the current `gss-sshkey` working
tree and its adjacent `ssh-config`, `gss-mech-builder`, and `rfc4121` crates.
It is a review record, not an expansion of the `0.1` requirements.  Each
finding remains pending until it is accepted, revised, or dismissed.  Accepted
release work should then be moved into `TODO.md`; deferred work belongs in
`BACKLOG.md`.

## SR-001: Authorized Keys Restrictions Are Discarded

Severity: high

Status: resolved 2026-08-13

Proposed release treatment: blocker

`authorized_key_from_line()` finds the public key using whitespace-delimited
fields but retains only the first field as its complete options string.  The
authorization path then understands only `from=` and silently ignores other
restrictions.

This can authorize a key more broadly than its entry permits.  In particular:

- a quoted command containing spaces can place a later `from=` outside the
  retained field;
- `expiry-time` and `cert-authority` alter whether the key itself may
  authenticate, but are ignored; and
- forced commands and other post-authentication restrictions cannot be
  propagated by this mechanism, so accepting such an entry grants broader
  access than OpenSSH would.

The safe `0.1` behavior is to parse the complete options list, enforce the
supported `expiry-time` condition, and reject a matching key candidate
whenever any other option would affect authorization or resulting access.

Follow-up review found that the implementation still retains only the first
whitespace-delimited options field and enforces only `from=`.  The prior
resolution was therefore incomplete.

Resolution: `authorized_keys` parsing now belongs to the adjacent
`ssh-config` crate.  It handles the complete quoted option field, escaped
quotes, comments, known and unknown options, and OpenSSH absolute expiry
times.  The mechanism accepts plain entries and entries containing only an
unexpired `expiry-time`.  It rejects every other option, including `from=`,
`cert-authority`, forced commands, session restrictions, and unknown future
options.  Parser and mechanism-policy tests cover these cases.

Evidence: `../ssh-config/src/authorized_keys.rs`, `src/lib.rs`, and
`REQUIREMENTS.md`.

## SR-002: Authentication Is Not Bound to the Acceptor Name

Severity: high

Status: resolved 2026-08-01

Proposed release treatment: blocker

The host, host-challenge, user, and Finished transcript helpers do not include
the acceptor name.  The host signatures also omit the protocol-specified
nonces, and the user signature omits the nonces and channel-binding data.
Finished indirectly covers the nonces and application channel-binding data,
but it never restores the missing acceptor-name binding.

If a host key or continuation-state key is shared between names, this permits
relay or unknown-key-share behavior in carriers that do not add their own
fresh binding.

The implementation should define one canonical acceptor name, make it
available to both roles, and match the signature inputs defined by the draft.
The acceptor credential name must be enforced rather than merely stored.

Resolution: `acceptorName` is carried in each proposal and sealed server
context.  It is included in host, user, and Finished transcripts together
with the draft-required nonces and channel-binding data.  Named acceptor
credentials are canonicalized and enforced.  Acceptor-first establishment
requires a named credential; initiator-first may use the target supplied by
the initiator.

Evidence: `src/lib.rs:1422-1505`,
`draft-dowdeswell-kitten-gss-sshkey-00.xml:224-279`, and
`REQUIREMENTS.md:69-70`.

## SR-003: Completed Exchanges Are Replayable

Severity: high

Status: accepted residual risk for 0.1 2026-08-01

Release treatment: accepted with mandatory server age policy and disclosure

The acceptor can process a captured final token on a fresh GSS context,
restore the old session key, and reset receive sequencing to zero.  This can
recreate an authenticated context and make previously captured per-message
tokens valid again.

OpenSSH's later `gssapi-with-mic` exchange binds a fresh SSH session identifier
and therefore limits this attack for a new SSH transport.  That carrier-level
property does not make the GSS mechanism itself replay resistant.

Decision: sealed server state now carries its canonical acceptor audience and
a mandatory authenticated issuance time.  The acceptor applies local server
policy, currently rejecting state at least 120 seconds old or excessively
future-dated.  A five-second tolerance accommodates acceptors sharing state
across hosts.  This limits but does not eliminate replay: without carrier
mitigation, a completed exchange is explicitly a bearer token while server
age policy accepts it.

Version `0.1` does not require channel bindings that reverse-proxied protocols
often cannot supply, nor does it depend on a replay cache whose operational
failure could make authentication unreliable.  Future integration should
provide a flag through which the carrier explicitly accepts replay
responsibility, for example because TLS already protects the channel.  It does
not promise mechanism-level replay detection or enforcement.  GSS per-message
replay detection remains independently enforced.

Evidence: `sshkey.asn1:139-160`, `src/lib.rs:1905-1957`,
`src/lib.rs:3057-3081`, `src/lib.rs:3226-3250`,
`src/lib.rs:4595-4626`, and `REQUIREMENTS.md:108-120`.

## SR-004: Client Conditional Resolution Can Fail Open

Severity: high

Status: resolved 2026-08-19

Proposed release treatment: blocker

The client adapter supplies the original host as both `original_host` and
`host`, and always supplies `canonical = false`.  It does not feed the resolved
`HostName` into a later resolution pass.  `validate_resolvable_with_context()`
also validates only the first pass.

Consequences include:

- `Match host` may not see a `HostName` selected earlier in configuration;
- `Match canonical` is never applicable in the mechanism adapter; and
- an unresolved condition guarded by `Match final` can be false in validation
  and then silently skipped in the final pass.

These cases can select the wrong username, identity, or host-trust policy.  The
adapter needs a preliminary/effective-host pass, any required canonicalization,
and fail-closed validation of every pass that is actually resolved.

Resolution: the adapter now resolves a preliminary effective `HostName`, then
resolves and validates again with that host for `Match host` and final-pass
conditions.  The parser validates unresolved authentication-relevant
conditions in both passes.  DNS hostname canonicalization requests fail
closed until a canonicalization implementation is available.

Follow-up review found that the second resolution starts with fresh option
state and that host matching remains fixed within a pass.  First-obtained
values can therefore disappear, so the prior resolution was incomplete.

Final resolution: `ssh-config` now owns connection-level resolution.  It uses
one accumulator for the initial and requested final passes, exposes the
selected `HostName` to later `Match host` conditions during the initial pass,
and retains the original alias for `Match originalhost`.  A final pass
reprocesses all blocks against the effective host, with OpenSSH's
first-obtained scalar and unique-list behavior.  `Match final` requests that
pass; `Match canonical` applies only during it.  Unsupported hostname
canonicalization and authentication-relevant unresolved conditions fail
closed in the pass where they apply.  The mechanism adapter now makes one
resolver call.

Evidence: `../ssh-config/src/client.rs:505-576`,
`../ssh-config/src/client.rs:2280-2369`,
`../ssh-config/src/client.rs:6498-6654`, `src/lib.rs:795-830`, and
`REQUIREMENTS.md:42-53`.

## SR-005: Explicit Host-Key Denial Policy Is Ignored

Severity: high

Status: resolved 2026-08-01

Proposed release treatment: blocker

The configuration crate resolves `RevokedHostKeys`, `KnownHostsCommand`,
`HostKeyAlgorithms`, and `RequiredRSASize`, but `ClientPolicy` retains none of
them.  A key denied by those settings can therefore still be accepted through
a static `known_hosts` entry or a matching SSHFP record.

A caller-supplied transport key may already have passed the caller's complete
host policy.  The independent configuration fallback cannot make that
assumption.  For `0.1`, each unsupported security-relevant setting should
either be implemented or make authentication for that target unavailable.

Resolution: the client retains and enforces `HostKeyAlgorithms` and
`RequiredRSASize` before accepting a key from any trust source.  A non-`none`
`RevokedHostKeys` value or a nonempty `KnownHostsCommand` now makes
authentication for that target unavailable because the mechanism has no
non-interactive implementation of those hooks.

Evidence: `src/lib.rs:821-837`, `src/lib.rs:881-916`,
`src/lib.rs:1218-1280`, and `src/lib.rs:4079-4142`.

## SR-006: Source-Address Policy Depends on Unsafe Integration

Severity: high

Status: resolved 2026-08-01

Proposed release treatment: blocker

When a peer address is unavailable, supported `Match Address` conditions are
treated as false rather than unresolved.  Address-qualified `DenyUsers` rules
can likewise fail to match, after which an unrestricted authorized-key entry
may authenticate.

The current OpenSSH patch does not stage typed peer context.  Its live harness
uses one process environment value, which is unsuitable for independent
connections and does not prove production source-address handling.

Native integration must pass the actual numeric peer address for each
connection.  Missing source data must reject any candidate whose result could
depend on source policy.

Resolution: a missing address now leaves `Match Address` unresolved, and a
matching address-qualified `DenyUsers` rule rejects authentication when no
peer address is available.  The typed server context accepts only numeric IP
addresses.  The OpenSSH adapter stages `ssh_remote_ipaddr()` before each
SSHKEY accept step and fails if the typed integration is unavailable; the
peer-address environment fallback has been removed.

Evidence: `../ssh-config/src/server.rs:1484-1491`, `src/lib.rs:1369-1417`,
`src/lib.rs:2959-2977`, `tests/openssh-live/openssh-gss-sshkey.patch`, and
`src/lib.rs:4145-4148`.

## SR-007: Missing User Credentials Complete Anonymously

Severity: medium

Status: resolved 2026-07-31

Proposed release treatment: blocker for the current non-anonymous goal

When no usable user key is available, `encrypted_userauth()` returns `None`,
but the initiator still reports `GSS_S_COMPLETE`.  The acceptor also treats an
absent `encuserauth` field as a complete anonymous context.  Finished does not
cover the presence or contents of that optional field, so a carrier able to
modify mechanism tokens can strip it and downgrade the acceptor's result.

OpenSSH currently rejects the resulting source name through `gss_userok`, but
generic GSS applications may accept a completed context.  The `0.1` mechanism
should require user authentication on both roles and fail when identity
material is absent.

Resolution: the initiator now returns `GSS_S_UNAUTHORIZED` when no usable user
key can produce encrypted user authentication.  The acceptor rejects a final
token without `encuserauth`, so stripping that field cannot produce a complete
context.  Successful contexts report the authorized requested username as the
authenticated GSS source name, and the mechanism no longer reports
`GSS_C_ANON_FLAG`.  Unit, direct GSS, `knc`, and `gss-token` tests cover the
changed behavior, and the complete `make test` target passes.

Evidence: `src/lib.rs:1689-1805`, `src/lib.rs:2457-2517`,
`src/lib.rs:2963-3070`, and `README.md:32-34`.

## SR-008: Channel-Binding Enforcement Is Incomplete

Severity: medium

Status: resolved 2026-08-19

Proposed release treatment: blocker unless the requirement is narrowed

Only `gss_channel_bindings.application_data` is passed into the mechanism.
Initiator and acceptor address fields are ignored.  Null bindings and a
non-null structure with empty application data derive the same key, although
the latter reports `GSS_C_CHANNEL_BOUND_FLAG`.

The project must either bind a canonical representation of the complete GSS
channel-binding structure or narrow the protocol and requirements explicitly
to application data and report the resulting capability accurately.

Resolution: `gss-mech-builder` validates every component and encodes the full
structure using a presence octet followed by RFC 4121 field ordering and
little-endian integers and lengths.  `gss-sshkey` binds that encoding into key
derivation and all authentication transcripts, rejects a changed value during
multipass establishment, and reports `GSS_C_CHANNEL_BOUND_FLAG` only for a
completed context that used a present structure.  Unit tests cover both
address types, both addresses, application data, invalid buffers, and the
null/empty distinction.  Direct GSS smoke tests exercise populated bindings
and mismatch rejection through both Heimdal and MIT loaders.

Evidence: `../gss-mech-builder/src/lib.rs`, `src/lib.rs`,
`tests/gss-token/smoke.c`, `sshkey.asn1`, and
`draft-dowdeswell-kitten-gss-sshkey-00.xml`.

## SR-009: In-Process RSA Signing Uses a Vulnerable Dependency

Severity: medium

Status: resolved 2026-08-01

Proposed release treatment: blocker for direct RSA private-key use

The `ssh-key` `crypto` feature brings in `rsa 0.9.10`.  RustSec advisory
RUSTSEC-2023-0071 reports remotely observable private-key timing leakage and no
patched version.  The mechanism performs in-process signing for both RSA
IdentityFile keys and RSA host keys, where a peer can obtain repeated timing
observations.

Until a constant-time implementation is available, direct RSA signing should
be disabled or moved to an implementation with suitable side-channel
protections.  Agent-backed signing is a separate process and must be assessed
according to that agent's implementation.

Resolution: all in-process signing paths reject RSA private keys before
constructing a signature.  RSA-SHA2 agent-backed user signing remains
available, as does RSA signature verification.  Direct RSA `IdentityFile` and
host-key signing are explicitly outside the `0.1` requirements until a
suitable constant-time backend is available.

Evidence: `Cargo.toml:27`, `src/lib.rs:1776-1797`,
`src/lib.rs:1999-2044`, `src/lib.rs:2091-2150`,
`src/lib.rs:4495-4527`, and
<https://rustsec.org/advisories/RUSTSEC-2023-0071.html>.

## SR-010: Acquired Initiator Names Do Not Select User Credentials

Severity: medium

Status: resolved 2026-08-01

Proposed release treatment: blocker for named initiator credentials

`gss_acquire_cred()` stores and reports the desired credential name, but
context initiation ignores it and selects the first usable configured key.
The caller may therefore request one SSH credential principal while the
mechanism authenticates with another.

The desired name must either select and validate the matching SSH key or be
rejected when the mechanism cannot honor it.  It must not be repurposed as the
remote login username.

Resolution: version `0.1` rejects a non-null desired name for initiator and
`GSS_C_BOTH` credential acquisition with `GSS_S_UNAVAILABLE` and `ENOTSUP`.
Default initiator acquisition remains available.  Named acceptor credentials
remain available because Heimdal `gss-token` and OpenSSH strict acceptor
checking use them; SR-002 now binds that service name into authentication.
Focused acquisition tests and the complete `make test` target pass.

Evidence: `src/lib.rs:284-318`, `src/lib.rs:1689-1805`, and
`src/lib.rs:3126-3187`.

## SR-011: Context Tokens Have No Size Limits

Severity: medium

Status: resolved 2026-08-01

Proposed release treatment: hardening blocker

The mechanism passes the complete caller-supplied buffer to the DER decoder,
and the ASN.1 schema leaves octet strings and algorithm lists unbounded.
Subsequent parsing, cloning, transcript construction, and public-key operations
can amplify attacker-controlled memory and CPU use.

The mechanism should reject oversized context tokens before DER decoding and
enforce conservative per-field limits for names, algorithm lists, keys,
signatures, and sealed state.

Resolution: input is capped at 256 KiB before DER decoding.  Decoded and
decrypted fields have separate limits for names, algorithm lists, key blobs,
signatures, Finished MACs, and encrypted state.  Locally generated output is
subject to the same total-token ceiling.

Evidence: `src/lib.rs:2222-2242` and `sshkey.asn1:43-49,109-149`.

## SR-012: StrictModes Checks Are Incomplete and Racy

Severity: medium

Status: resolved 2026-08-03

Proposed release treatment: blocker where `StrictModes yes` is claimed

`safe_authorization_file()` checks the target and only its immediate parent.
It then reopens the path by name, leaving unchecked writable ancestors and a
metadata/read time-of-check to time-of-use race.

The authorization path should validate all relevant ancestors and read through
the same safely opened descriptor that was checked, with symlink and ownership
handling matching the supported OpenSSH policy.

Resolution: authorized-keys paths are opened once with `O_NONBLOCK`, rejected
unless the descriptor identifies a regular file, and then read through that
same descriptor.  With `StrictModes yes`, the descriptor metadata and every
directory in the canonical path through the user's home directory (or root)
must be owned by root or the user and must not be group- or world-writable.
This mirrors OpenSSH's `auth_openfile()` and `safe_path_fd()` behavior.

Evidence: `src/lib.rs:1449-1520`, `src/lib.rs:1650-1662`, and
`src/lib.rs:4088-4125`.

## SR-013: Context Transfer Is Advertised but Unavailable

Severity: low

Status: resolved 2026-07-31

Proposed release treatment: correctness blocker

Every context reports `GSS_C_TRANS_FLAG`, but both context export and import are
wired to unavailable operations.  Applications can therefore make an unsafe
capability decision from inaccurate mechanism flags.

The flag should be removed unless context transfer is implemented and tested.

Resolution: `sshkey_context_flags()` no longer returns `GSS_C_TRANS_FLAG`.
The unavailable export and import operations remain unavailable, so callers
now receive an accurate capability result.  A regression test covers the flag,
and the complete `make test` target passes.

Evidence: `src/lib.rs:479-492` and `src/lib.rs:3397-3408`.

## Verification Performed

`make test` passed the Rust, header, install, package, `knc`, direct GSS,
Heimdal loader, MIT krb5 loader, and `gss-token` phases.  The opt-in live
OpenSSH test was not run as part of this review.

`cargo clippy --offline --all-targets` completed with seven non-security
warnings.  `cargo audit` and `cargo deny` were unavailable, so the lockfile was
compared manually with a current RustSec advisory database.  The applicable
unpatched result found was SR-009.  Hickory `0.26.1` contains the current fixes
for the reviewed DNSSEC denial-of-service advisories.

Passing tests do not resolve the findings above because the suite does not yet
exercise these adversarial policy and replay cases.
