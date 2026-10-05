# OpenSSH live login test

This test proves a real OpenSSH login through `gssapi-with-mic` with native
public-key authentication disabled on both the client and server.  It checks
the authenticated requested username and a remote command's output.
It is optional application-integration evidence, not a release gate for the
standalone GSS mechanism.

Stock OpenSSH servers accept only mechanisms with compiled account-mapping
support.  Apply `openssh-gss-sshkey.patch` to a portable OpenSSH source tree,
configure it with GSSAPI support, and install the resulting binaries under a
temporary prefix.  The patch retains the authenticated GSS source name and
uses this mechanism's `gss_userok()` implementation for account authorization;
it also stages the connection's numeric `ssh_remote_ipaddr()` through the
typed server interface before each SSHKEY accept step.  It does not duplicate
SSH userauth or `authorized_keys` policy.

For example:

```sh
git apply /path/to/gss-sshkey/tests/openssh-live/openssh-gss-sshkey.patch
autoreconf -fi
CPPFLAGS="-I/path/to/gss-sshkey/include" \
  ./configure --with-kerberos5 --prefix=/tmp/openssh-gss-install
make -j4
make install-nosysconf
```

Then run from the `gss-sshkey` repository:

```sh
make test-openssh-live \
  SSHD_BIN=/tmp/openssh-gss-install/sbin/sshd
```

`SSH_BIN` defaults to the installed client.  `SSHD_BIN` must name an OpenSSH
server containing the integration patch, with its matching `sshd-auth` and
`sshd-session` binaries installed at the paths compiled into it.  Override the
loopback port with `OPENSSH_TEST_PORT` when necessary.

The fixture preloads the mechanism, which makes its typed setter visible to
the patched monitor, and uses environment compatibility only for mechanism
key and configuration paths.  The server peer address is always supplied by
OpenSSH through the typed interface.
