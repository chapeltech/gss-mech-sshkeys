# Architecture

The protocol specification lives in
`draft-dowdeswell-kitten-gss-sshkey-00.xml`, with message syntax mirrored in
`sshkey.asn1`.  This document records implementation boundaries; it is not a
second protocol specification.

Product behavior for the current milestone is normative in `REQUIREMENTS.md`.
`TODO.md` contains release-blocking work, and `BACKLOG.md` contains deferred
compatibility work.

## Purpose

GSS-SSHKEY authenticates with ordinary SSH public-key credentials.  For the
initial SSH login profile, it should reach substantially the same identity,
host-trust, and authorization decisions as common OpenSSH public-key
authentication without implementing the SSH transport or SSH userauth
protocol.

It is a standalone GSS mechanism.  Integration into OpenSSH or another GSS
application is adapter work outside the mechanism's release boundary.

The mechanism answers one question:

> May this authenticated SSH key log in as this local account from this
> source?

It does not process SSH packets, reproduce `SSH_MSG_USERAUTH_REQUEST`, bind an
ssh-agent session to an SSH transport, or model shells, commands, subsystems,
forwarding, TTYs, environment variables, or other session requests.

## Protocol Boundary

The ASN.1 exchange owns:

- ephemeral key agreement and algorithm negotiation;
- canonical acceptor-name agreement and binding;
- acceptor host-key proof;
- encrypted initiator username, public key, and signature;
- encrypted acceptor continuation state;
- key confirmation; and
- the session key used by GSS message protection.

SSH key and signature encodings are reused as credential formats.  That does
not make the mechanism an SSH protocol implementation.

Any change to token syntax, cryptographic transcript inputs, negotiation, key
derivation, or context-state semantics must update both the Internet-Draft and
`sshkey.asn1`.

## Client Boundary

The initiator receives a GSS target name and resolves a focused `ssh_config`
subset through the adjacent `ssh-config` crate.  `Host`, `Match`, and
`Include` processing must be sufficient to determine the destination,
requested username, identity files, agent socket, accepted key algorithms,
and non-interactive host-trust policy.

The client:

- gets the requested remote username from typed caller context, resolved
  `User`, or the invoking local username, in that order;
- orders ordinary ssh-agent and unencrypted Ed25519 or ECDSA `IdentityFile`
  candidates like OpenSSH, including per-key signature algorithms;
- advances that queue only after a session-authenticated authorization retry;
- validates the acceptor host key against an already-verified key supplied by
  the caller, existing known-hosts files, or DNSSEC-validated SSHFP records;
  and
- signs the GSS-SSHKEY transcript with the selected user key.

Client configuration is resolved first for the destination alias and then
again with the effective `HostName`, so `Match host` and final-pass policy see
the correct host.  Requested DNS hostname canonicalization fails closed until
the mechanism has a DNS canonicalization implementation.

It never prompts.  Missing identity or host trust fails authentication.
Version `0.1` supports default initiator credential acquisition.  A non-null
initiator credential name is rejected because named SSH-key selection is not
yet defined; it is never treated as a remote-username input.  Named acceptor
credentials remain available for service-name binding.
The canonical name retains the GSS service component and uses the effective,
lowercase destination hostname without a trailing root dot.

## Server Boundary

The acceptor resolves a focused `sshd_config` subset through `ssh-config` and
checks ordinary local account and `authorized_keys` policy.

The server:

- loads an Ed25519 or ECDSA SSH host private key and proves possession in the
  ASN.1 exchange;
- verifies the initiator's SSH key signature over the GSS-SSHKEY transcript;
- resolves `AuthorizedKeysFile`, supported `Match` conditions, basic
  allow/deny account policy, source restrictions, revocation lists, and
  accepted signature algorithms; and
- records authorization for the exact requested local account.

Initiator-first exchanges may use the acceptor name supplied by the initiator;
the host signature reflects it before the initiator trusts the host key.
Acceptor-first exchanges require a named acceptor credential because no
initiator target name is yet available when the challenge is signed.

An accepted GSS source name is the requested username after that account and
its SSH key have been authenticated and authorized.  `gss_localname()` and
`gss_authorize_localname()` expose the same account authorized during context
establishment.

SSH certificates, authorization helper commands, PAM parity, hardware-backed
keys, destination-constrained agents, and post-login restrictions are outside
the `0.1` implementation boundary.

## Crate Ownership

- `gss-sshkey` owns the ASN.1 exchange and the focused SSH credential,
  host-trust, and login-authorization adapters.
- `ssh-config` owns OpenSSH client and server configuration parsing,
  conditional resolution, and `authorized_keys` syntax.  Valid unknown
  directives and key options remain representable without changing policy.
- `gss-mech-builder` owns generic GSS ABI validation, handles, names,
  credentials, context entrypoints, channel-binding validation and canonical
  encoding, status plumbing, per-message exports, and MIT/Heimdal loader
  adaptation.
- `rfc4121` is an implementation detail of `gss-mech-builder`.
- `ssh-key` owns SSH public/private key and signature encoding support.
- `hickory-resolver` owns DNS transport, caching, DNSSEC validation, and SSHFP
  record decoding.  `gss-sshkey` owns only SSHFP-to-SSH-key matching and host
  trust policy.

`gss-sshkey` must not depend directly on `rfc4121`, duplicate generic GSS ABI
machinery, acquire a full SSH protocol-stack dependency, or implement a
general DNS subsystem.

## Typed Integration

An embedding application may supply SSH-related facts it already knows, such
as the resolved username, verified host key, or peer address.  These values
cross a narrow typed boundary and are consumed when a new mechanism context
is created.  Configuration files remain the source for ordinary identity and
authorization policy.

Process environment variables may remain as a test and compatibility adapter
for configuration and credential paths.  Connection-specific transport facts
must use typed client and server inputs.  In particular, the server peer
address has no process-environment fallback.

Acceptor continuation state remains self-contained so another process with
the same protection key can finish an exchange.  It carries an authenticated
issuance time; the server's local policy limits its accepted age to less than
120 seconds in version `0.1`.  The mechanism does not claim single-use context
establishment when the carrier does not mitigate replay.

## Failure Model

Valid configuration containing unrelated or unsupported directives remains
valid.  A malformed supported directive fails closed.  An unsupported
condition that could change the selected host, username, identity, trust
source, or authorization result makes authentication unavailable for that
candidate.

The initial milestone intentionally targets common cases rather than exhaustive
OpenSSH parity.

## Source Map

- `REQUIREMENTS.md`: normative `0.1` behavior.
- `TODO.md`: remaining release blockers.
- `BACKLOG.md`: deferred compatibility work.
- `src/lib.rs`: mechanism-specific protocol and SSH credential adapters.
- `src/host_trust.rs`: non-interactive host-key trust policy.
- `src/sshfp.rs`: Hickory DNSSEC lookup and SSHFP key matching.
- `../ssh-config/`: client and server configuration resolver and
  `authorized_keys` parser.
- `../gss-mech-builder/`: generic GSS mechanism construction.
- `../rfc4121/`: builder-private message protection.
- `sshkey.asn1`: ASN.1 schema and protocol notes.
- `draft-dowdeswell-kitten-gss-sshkey-00.xml`: protocol specification.
