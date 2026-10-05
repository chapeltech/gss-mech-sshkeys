# Backlog

This file records work that may improve `gss-sshkey` after the current `0.1`
requirements are met.  Nothing here is a `0.1` release gate.

The current release requirements are in `REQUIREMENTS.md`.  Active work is in
`TODO.md`.

## Authentication Compatibility

- SSH user certificates and implicit certificate fallback.
- Destination-constrained ssh-agent keys.
- Confirmation-required agent keys and agent refusal fallback.
- PKCS#11-backed identities.
- Security-key provider identities.
- Additional key types and legacy algorithm policy.
- Direct RSA `IdentityFile` and host-key signing through a constant-time
  private-key implementation.

## Host Trust

- Host-certificate CA trust and rejection.
- `KnownHostsCommand` parity.
- `UpdateHostKeys` writes.
- `HashKnownHosts` update behavior.
- Additional revoked-host-key and hashed-hostname cases.

## Server Policy

- `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand` parity.
- SSH certificate principals, certificate expiry, and CA policy.
- PAM account policy.
- Platform-specific account restrictions.
- Additional revocation and unavailable-credential cases.

## Configuration Compatibility

- `Match` conditions beyond the client and server resolution subset required
  by `REQUIREMENTS.md`.
- Hostname canonicalization and CNAME policy.
- Complete token and environment expansion.
- Uncommon client and server directives.
- Exact behavior across additional OpenSSH releases.

## GSS And Deployment

- Context export and import.
- Additional optional GSS entry points.
- Maintain and upstream optional native OpenSSH integration.  Replace its
  remaining client environment compatibility with typed requested-user and
  verified-host-key inputs, while retaining server mechanism registration,
  `gss_userok()`, and peer-address plumbing.  This application adapter and
  its live test are not release gates for the standalone mechanism.
- Define a caller flag that explicitly accepts replayable context
  establishment and assigns replay-mitigation responsibility to the carrier
  protocol, for example an already encrypted TLS channel.
- Consider additional replay handling and continuation-age controls without
  promising mechanism-level replay detection or single-use enforcement.
- Distribution-native packages.
- Additional GSS implementations and operating systems.

Compatibility work must be added as focused tests when a backlog item is
implemented.  Exhaustive OpenSSH oracle fixtures are intentionally not kept in
this repository.
