use std::cell::RefCell;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::rdata::sshfp::{
    Algorithm as SshfpAlgorithm, FingerprintType, SSHFP,
};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, PublicKey};
use subtle::ConstantTimeEq;
use tokio::runtime::{Builder, Runtime};

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SshfpResult {
    Match,
    Mismatch,
    NoRecords,
    Insecure,
    Bogus,
    Unavailable,
}

struct Resolver {
    runtime: Runtime,
    resolver: TokioResolver,
}

thread_local! {
    static RESOLVER: RefCell<Option<Resolver>> = const { RefCell::new(None) };
}

impl Resolver {
    fn new() -> Result<Self, ()> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ())?;
        let resolver = {
            let _guard = runtime.enter();
            let mut builder = TokioResolver::builder_tokio().map_err(|_| ())?;
            let options = builder.options_mut();
            options.validate = true;
            options.timeout = REQUEST_TIMEOUT;
            options.attempts = 2;
            builder.build().map_err(|_| ())?
        };
        Ok(Self { runtime, resolver })
    }

    fn lookup(&mut self, host: &str, key_blob: &[u8]) -> SshfpResult {
        let name = format!("{host}.");
        let lookup = self.runtime.block_on(async {
            tokio::time::timeout(
                LOOKUP_TIMEOUT,
                self.resolver.lookup(name, RecordType::SSHFP),
            )
            .await
        });
        match lookup {
            Ok(Ok(lookup)) => {
                let records =
                    lookup.message().dnssec_answers().filter_map(|record| {
                        let (proof, record) = record.into_parts();
                        match &record.data {
                            RData::SSHFP(sshfp) => Some((proof, sshfp)),
                            _ => None,
                        }
                    });
                match_records(key_blob, records)
            }
            Ok(Err(error)) => classify_error(&error),
            Err(_) => SshfpResult::Unavailable,
        }
    }
}

pub(crate) fn verify(host: &str, key_blob: &[u8]) -> SshfpResult {
    if IpAddr::from_str(host).is_ok() {
        return SshfpResult::NoRecords;
    }
    RESOLVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            let Ok(resolver) = Resolver::new() else {
                return SshfpResult::Unavailable;
            };
            *slot = Some(resolver);
        }
        slot.as_mut()
            .map(|resolver| resolver.lookup(host, key_blob))
            .unwrap_or(SshfpResult::Unavailable)
    })
}

fn classify_error(error: &NetError) -> SshfpResult {
    match error {
        NetError::Dns(DnsError::Nsec { proof, .. }) => match proof {
            Proof::Secure => SshfpResult::NoRecords,
            Proof::Insecure => SshfpResult::Insecure,
            Proof::Bogus => SshfpResult::Bogus,
            Proof::Indeterminate => SshfpResult::Unavailable,
        },
        _ => SshfpResult::Unavailable,
    }
}

fn match_records<'a>(
    key_blob: &[u8],
    records: impl IntoIterator<Item = (Proof, &'a SSHFP)>,
) -> SshfpResult {
    let Ok(public_key) = PublicKey::from_bytes(key_blob) else {
        return SshfpResult::Mismatch;
    };
    let Some(algorithm) = sshfp_algorithm(&public_key.algorithm()) else {
        return SshfpResult::Mismatch;
    };

    let mut found = false;
    let mut matched = false;
    let mut insecure = false;
    let mut indeterminate = false;
    for (proof, record) in records {
        found = true;
        match proof {
            Proof::Bogus => return SshfpResult::Bogus,
            Proof::Insecure => insecure = true,
            Proof::Indeterminate => indeterminate = true,
            Proof::Secure => {}
        }
        if proof == Proof::Secure
            && record.algorithm == algorithm
            && fingerprint_matches(record, key_blob)
        {
            matched = true;
        }
    }

    if !found {
        SshfpResult::NoRecords
    } else if insecure {
        SshfpResult::Insecure
    } else if indeterminate {
        SshfpResult::Unavailable
    } else if matched {
        SshfpResult::Match
    } else {
        SshfpResult::Mismatch
    }
}

fn sshfp_algorithm(algorithm: &Algorithm) -> Option<SshfpAlgorithm> {
    match algorithm {
        Algorithm::Rsa { .. } => Some(SshfpAlgorithm::RSA),
        Algorithm::Dsa => Some(SshfpAlgorithm::DSA),
        Algorithm::Ecdsa { .. } => Some(SshfpAlgorithm::ECDSA),
        Algorithm::Ed25519 => Some(SshfpAlgorithm::Ed25519),
        _ => None,
    }
}

fn fingerprint_matches(record: &SSHFP, key_blob: &[u8]) -> bool {
    let actual = match record.fingerprint_type {
        FingerprintType::SHA1 => Sha1::digest(key_blob).to_vec(),
        FingerprintType::SHA256 => Sha256::digest(key_blob).to_vec(),
        _ => return false,
    };
    actual.len() == record.fingerprint.len()
        && bool::from(actual.ct_eq(record.fingerprint.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = concat!(
        "ssh-ed25519 ",
        "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/",
        "XFSqti"
    );

    fn public_key() -> Vec<u8> {
        PUBLIC_KEY.parse::<PublicKey>().unwrap().to_bytes().unwrap()
    }

    fn record(
        algorithm: SshfpAlgorithm,
        fingerprint_type: FingerprintType,
        fingerprint: Vec<u8>,
    ) -> SSHFP {
        SSHFP::new(algorithm, fingerprint_type, fingerprint)
    }

    #[test]
    fn secure_sha256_record_matches_key_blob() {
        let key = public_key();
        let fingerprint = Sha256::digest(&key).to_vec();
        let record = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            fingerprint,
        );

        assert_eq!(
            match_records(&key, [(Proof::Secure, &record)]),
            SshfpResult::Match
        );
    }

    #[test]
    fn secure_sha1_record_matches_key_blob() {
        let key = public_key();
        let fingerprint = Sha1::digest(&key).to_vec();
        let record =
            record(SshfpAlgorithm::Ed25519, FingerprintType::SHA1, fingerprint);

        assert_eq!(
            match_records(&key, [(Proof::Secure, &record)]),
            SshfpResult::Match
        );
    }

    #[test]
    fn any_secure_record_may_match() {
        let key = public_key();
        let stale = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            vec![0; 32],
        );
        let current = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            Sha256::digest(&key).to_vec(),
        );

        assert_eq!(
            match_records(
                &key,
                [(Proof::Secure, &stale), (Proof::Secure, &current)]
            ),
            SshfpResult::Match
        );
    }

    #[test]
    fn secure_mismatched_record_is_rejected() {
        let key = public_key();
        let record = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            vec![0; 32],
        );

        assert_eq!(
            match_records(&key, [(Proof::Secure, &record)]),
            SshfpResult::Mismatch
        );
    }

    #[test]
    fn bogus_matching_record_is_rejected() {
        let key = public_key();
        let record = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            Sha256::digest(&key).to_vec(),
        );

        assert_eq!(
            match_records(&key, [(Proof::Bogus, &record)]),
            SshfpResult::Bogus
        );
    }

    #[test]
    fn insecure_match_does_not_authenticate() {
        let key = public_key();
        let record = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            Sha256::digest(&key).to_vec(),
        );

        assert_eq!(
            match_records(&key, [(Proof::Insecure, &record)]),
            SshfpResult::Insecure
        );
    }

    #[test]
    fn mixed_secure_and_insecure_records_do_not_authenticate() {
        let key = public_key();
        let record = record(
            SshfpAlgorithm::Ed25519,
            FingerprintType::SHA256,
            Sha256::digest(&key).to_vec(),
        );

        assert_eq!(
            match_records(
                &key,
                [(Proof::Secure, &record), (Proof::Insecure, &record)]
            ),
            SshfpResult::Insecure
        );
    }

    #[test]
    fn unknown_record_values_are_ignored() {
        let key = public_key();
        let record = record(
            SshfpAlgorithm::Unassigned(200),
            FingerprintType::Unassigned(200),
            vec![0; 17],
        );

        assert_eq!(
            match_records(&key, [(Proof::Secure, &record)]),
            SshfpResult::Mismatch
        );
    }

    #[test]
    fn numeric_hosts_do_not_start_dns_lookups() {
        assert_eq!(verify("192.0.2.1", &public_key()), SshfpResult::NoRecords);
    }
}
