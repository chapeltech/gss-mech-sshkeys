use std::fs;
use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use ssh_key::known_hosts::{HostPatterns, KnownHosts, Marker};

use crate::sshfp::{self, SshfpResult};
use crate::wildcard_match;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostTrustSource {
    Explicit,
    KnownHosts,
    Sshfp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostTrust {
    Trusted(HostTrustSource),
    Rejected,
}

pub(crate) struct HostTrustConfig<'a> {
    pub known_hosts_name: &'a str,
    pub dns_name: &'a str,
    pub known_hosts_files: &'a [PathBuf],
    pub verified_host_key: Option<&'a [u8]>,
    pub verify_host_key_dns: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KnownHostsTrust {
    Trusted,
    Revoked,
    Mismatch,
    NotFound,
}

pub(crate) fn lookup_name(
    alias: Option<&str>,
    host: &str,
    port: u16,
) -> String {
    if let Some(alias) = alias {
        alias.to_string()
    } else if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

pub(crate) fn verify(
    config: HostTrustConfig<'_>,
    key_blob: &[u8],
) -> HostTrust {
    verify_with(config, key_blob, sshfp::verify)
}

fn verify_with(
    config: HostTrustConfig<'_>,
    key_blob: &[u8],
    resolve_sshfp: impl FnOnce(&str, &[u8]) -> SshfpResult,
) -> HostTrust {
    if let Some(verified) = config.verified_host_key {
        return if verified == key_blob {
            HostTrust::Trusted(HostTrustSource::Explicit)
        } else {
            HostTrust::Rejected
        };
    }

    match known_hosts_trust(
        config.known_hosts_name,
        key_blob,
        config.known_hosts_files,
    ) {
        KnownHostsTrust::Trusted => {
            return HostTrust::Trusted(HostTrustSource::KnownHosts);
        }
        KnownHostsTrust::Revoked | KnownHostsTrust::Mismatch => {
            return HostTrust::Rejected;
        }
        KnownHostsTrust::NotFound => {}
    }

    if config.verify_host_key_dns
        && resolve_sshfp(config.dns_name, key_blob) == SshfpResult::Match
    {
        HostTrust::Trusted(HostTrustSource::Sshfp)
    } else {
        HostTrust::Rejected
    }
}

fn plain_pattern_matches(pattern: &str, host: &str) -> bool {
    wildcard_match(pattern.as_bytes(), host.as_bytes())
}

fn hash_matches(salt: &[u8], hash: &[u8; 20], host: &str) -> bool {
    type HmacSha1 = Hmac<Sha1>;

    let Ok(mut mac) = HmacSha1::new_from_slice(salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    let actual = mac.finalize().into_bytes();
    actual.as_slice() == hash
}

fn patterns_match(patterns: &HostPatterns, host: &str) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => {
            let mut matched = false;
            for pattern in patterns {
                if let Some(pattern) = pattern.strip_prefix('!') {
                    if plain_pattern_matches(pattern, host) {
                        return false;
                    }
                    continue;
                }
                matched |= plain_pattern_matches(pattern, host);
            }
            matched
        }
        HostPatterns::HashedName { salt, hash } => {
            hash_matches(salt, hash, host)
        }
    }
}

fn known_hosts_trust_text(
    host: &str,
    key_blob: &[u8],
    text: &str,
) -> KnownHostsTrust {
    let mut trusted = false;
    let mut mismatch = false;
    for entry in KnownHosts::new(text).flatten() {
        if !patterns_match(entry.host_patterns(), host) {
            continue;
        }
        let Ok(entry_key) = entry.public_key().to_bytes() else {
            continue;
        };
        if entry_key == key_blob {
            if entry.marker() == Some(&Marker::Revoked) {
                return KnownHostsTrust::Revoked;
            }
            if entry.marker().is_none() {
                trusted = true;
            }
        } else if entry.marker().is_none() {
            mismatch = true;
        }
    }
    if trusted {
        KnownHostsTrust::Trusted
    } else if mismatch {
        KnownHostsTrust::Mismatch
    } else {
        KnownHostsTrust::NotFound
    }
}

fn known_hosts_trust(
    host: &str,
    key_blob: &[u8],
    paths: &[PathBuf],
) -> KnownHostsTrust {
    let mut trusted = false;
    let mut mismatch = false;
    for path in paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        match known_hosts_trust_text(host, key_blob, &text) {
            KnownHostsTrust::Trusted => trusted = true,
            KnownHostsTrust::Revoked => return KnownHostsTrust::Revoked,
            KnownHostsTrust::Mismatch => mismatch = true,
            KnownHostsTrust::NotFound => {}
        }
    }
    if trusted {
        KnownHostsTrust::Trusted
    } else if mismatch {
        KnownHostsTrust::Mismatch
    } else {
        KnownHostsTrust::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use ssh_key::PublicKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PUBLIC_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/",
        "XFSqti"
    );
    const OTHER_PUBLIC_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAIKg+TFsCEa1ur2I8XEPVHrtu6kHIwpQTrM8bK5I",
        "hKU1A"
    );

    fn public_key() -> PublicKey {
        PUBLIC_KEY.parse().unwrap()
    }

    fn other_public_key() -> PublicKey {
        OTHER_PUBLIC_KEY.parse().unwrap()
    }

    fn temporary_file(contents: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("gss-sshkey-{nonce}.known"));
        fs::write(&path, contents).unwrap();
        path
    }

    fn config<'a>(
        paths: &'a [PathBuf],
        verified: Option<&'a [u8]>,
        dns: bool,
    ) -> HostTrustConfig<'a> {
        HostTrustConfig {
            known_hosts_name: "example.com",
            dns_name: "real.example.com",
            known_hosts_files: paths,
            verified_host_key: verified,
            verify_host_key_dns: dns,
        }
    }

    #[test]
    fn lookup_name_honors_alias_and_nondefault_port() {
        assert_eq!(lookup_name(None, "example.com", 22), "example.com");
        assert_eq!(
            lookup_name(None, "example.com", 2222),
            "[example.com]:2222"
        );
        assert_eq!(
            lookup_name(None, "2001:db8::1", 2222),
            "[2001:db8::1]:2222"
        );
        assert_eq!(
            lookup_name(Some("host-key-name"), "example.com", 2222),
            "host-key-name"
        );
    }

    #[test]
    fn known_hosts_text_trusts_revokes_and_detects_mismatch() {
        let public_key = public_key();
        let key = public_key.to_bytes().unwrap();
        let trusted = format!("example.com {}", public_key.to_string());
        let revoked =
            format!("@revoked example.com {}", public_key.to_string());
        let other = other_public_key();
        let mismatch = format!("example.com {}", other.to_string());

        assert_eq!(
            known_hosts_trust_text("example.com", &key, &trusted),
            KnownHostsTrust::Trusted
        );
        assert_eq!(
            known_hosts_trust_text("example.com", &key, &revoked),
            KnownHostsTrust::Revoked
        );
        assert_eq!(
            known_hosts_trust_text("example.com", &key, &mismatch),
            KnownHostsTrust::Mismatch
        );
        assert_eq!(
            known_hosts_trust_text("other.example", &key, &trusted),
            KnownHostsTrust::NotFound
        );
    }

    #[test]
    fn known_hosts_text_matches_nondefault_port() {
        let public_key = public_key();
        let key = public_key.to_bytes().unwrap();
        let trusted = format!("[example.com]:2222 {}", public_key.to_string());

        assert_eq!(
            known_hosts_trust_text("[example.com]:2222", &key, &trusted),
            KnownHostsTrust::Trusted
        );
        assert_eq!(
            known_hosts_trust_text("example.com", &key, &trusted),
            KnownHostsTrust::NotFound
        );
    }

    #[test]
    fn hashed_patterns_match_hmac_sha1() {
        type HmacSha1 = Hmac<Sha1>;

        let salt = b"salt";
        let mut mac = HmacSha1::new_from_slice(salt).unwrap();
        mac.update(b"example.com");
        let hash: [u8; 20] = mac.finalize().into_bytes().into();
        let patterns = HostPatterns::HashedName {
            salt: salt.to_vec(),
            hash,
        };

        assert!(patterns_match(&patterns, "example.com"));
        assert!(!patterns_match(&patterns, "other.example"));
    }

    #[test]
    fn known_hosts_match_avoids_dns() {
        let public_key = public_key();
        let key = public_key.to_bytes().unwrap();
        let path = temporary_file(&format!(
            "example.com {}\n",
            public_key.to_string()
        ));
        let paths = [path.clone()];
        let result = verify_with(config(&paths, None, true), &key, |_, _| {
            panic!("DNS should not be queried")
        });
        fs::remove_file(path).unwrap();

        assert_eq!(result, HostTrust::Trusted(HostTrustSource::KnownHosts));
    }

    #[test]
    fn sshfp_may_trust_an_unknown_host() {
        let key = public_key().to_bytes().unwrap();
        let result =
            verify_with(config(&[], None, true), &key, |host, blob| {
                assert_eq!(host, "real.example.com");
                assert_eq!(Sha256::digest(blob), Sha256::digest(&key));
                SshfpResult::Match
            });

        assert_eq!(result, HostTrust::Trusted(HostTrustSource::Sshfp));
    }

    #[test]
    fn known_hosts_mismatch_cannot_be_overridden_by_sshfp() {
        let key = public_key().to_bytes().unwrap();
        let path = temporary_file(&format!(
            "example.com {}\n",
            other_public_key().to_string()
        ));
        let paths = [path.clone()];
        let result = verify_with(config(&paths, None, true), &key, |_, _| {
            panic!("DNS must not override a known-host mismatch")
        });
        fs::remove_file(path).unwrap();

        assert_eq!(result, HostTrust::Rejected);
    }

    #[test]
    fn insecure_or_unavailable_sshfp_does_not_authenticate() {
        let key = public_key().to_bytes().unwrap();
        for dns_result in [
            SshfpResult::Mismatch,
            SshfpResult::NoRecords,
            SshfpResult::Insecure,
            SshfpResult::Bogus,
            SshfpResult::Unavailable,
        ] {
            assert_eq!(
                verify_with(config(&[], None, true), &key, |_, _| {
                    dns_result
                }),
                HostTrust::Rejected
            );
        }
    }

    #[test]
    fn ask_or_no_policy_does_not_query_dns() {
        let key = public_key().to_bytes().unwrap();
        let result = verify_with(config(&[], None, false), &key, |_, _| {
            panic!("DNS should be disabled")
        });

        assert_eq!(result, HostTrust::Rejected);
    }

    #[test]
    fn explicit_key_remains_authoritative() {
        let key = public_key().to_bytes().unwrap();
        let other = other_public_key().to_bytes().unwrap();

        assert_eq!(
            verify_with(config(&[], Some(&key), true), &key, |_, _| {
                panic!("explicit trust should avoid DNS")
            }),
            HostTrust::Trusted(HostTrustSource::Explicit)
        );
        assert_eq!(
            verify_with(config(&[], Some(&other), true), &key, |_, _| {
                panic!("explicit mismatch should avoid DNS")
            }),
            HostTrust::Rejected
        );
    }
}
