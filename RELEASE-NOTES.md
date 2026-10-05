# gss-sshkey 0.1.0-alpha.1

This is an experimental source and binary alpha of the GSS-SSHKEY mechanism.
It is not a crates.io release.  The source archive contains `gss-sshkey` and
the exact sibling `gss-mech-builder`, `rfc4121`, and `ssh-config` sources used
to build it.  Binary archives are provided separately for Heimdal and MIT
krb5 mechanism-loader configuration formats.

## Scope

The alpha authenticates a requested local username with ordinary SSH public
keys through the standard GSS-API.  It supports common OpenSSH configuration,
agent and unencrypted identity-file credentials, non-interactive host trust,
plain login authorization, complete GSS channel bindings, and post-login GSS
integrity and confidentiality services.

The release scope is defined by `REQUIREMENTS.md`.  Native OpenSSH integration
is optional application work and is not required to use the mechanism through
another GSS application.

## Security Limitations

- The mechanism OID `1.3.6.1.4.1.99999.1` is private and experimental.  Data
  produced with this OID must not be represented as interoperable with a
  future assigned mechanism OID.
- A completed stateless exchange is a bearer token while the server accepts
  its authenticated continuation state.  The alpha rejects state at least
  120 seconds old and excessively future-dated state, but it does not maintain
  a replay cache.  Applications without fresh carrier binding or equivalent
  replay mitigation accept this bounded replay risk.
- The mechanism never prompts for host trust or private-key passphrases.  It
  fails when it cannot validate the host key non-interactively.
- Direct RSA private-key signing is disabled.  RSA-SHA2 user keys require
  `ssh-agent`; direct identity-file and host-key signing use Ed25519 or ECDSA.
- Only the documented OpenSSH configuration subset is enforced.  Valid
  unrelated directives are ignored, while unresolved security-critical
  policy fails authentication or makes the affected candidate unavailable.
- Server authorization never uses a reverse-resolved or client-asserted
  hostname.  Hostname-dependent authorization policy therefore fails closed.
- `authorized_keys` entries are accepted only when plain or restricted solely
  by an unexpired `expiry-time`.  Other options cannot be propagated by this
  login-only mechanism and make that entry unavailable.
- DNS SSHFP trust is accepted only for a matching record whose DNSSEC chain
  validates to the resolver's configured trust anchors.

See `SECURITY-REVIEW.md`, `REQUIREMENTS.md`, and `BACKLOG.md` for the complete
review record, supported policy, and deferred work.

## Acceptance

The release acceptance command is:

```sh
make test-alpha
```

It requires real `ssh-agent`, Heimdal loader, and MIT krb5 loader phases and
fails if any required phase is skipped.
