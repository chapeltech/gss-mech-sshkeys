use rfc4121::Role;

pub const DEFAULT_PROTOCOL_LABEL: &[u8] = b"gss-mech-builder signed-ecdh v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    CryptoFailure,
    InvalidInput,
    NoSignatureAlgorithm,
    SignatureRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmSuite {
    pub kex: Vec<Vec<u8>>,
    pub enctype: Vec<Vec<u8>>,
    pub signature: Vec<Vec<u8>>,
}

impl AlgorithmSuite {
    pub fn choose_signature<'a>(
        &'a self,
        peer_supported: &'a [Vec<u8>],
    ) -> Option<&'a [u8]> {
        if peer_supported.is_empty() {
            return self.signature.first().map(Vec::as_slice);
        }

        self.signature
            .iter()
            .find(|alg| peer_supported.iter().any(|peer| peer == *alg))
            .map(Vec::as_slice)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub key_type: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub trait TranscriptSigner {
    fn sign(
        &self,
        algorithm: &[u8],
        transcript: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

pub trait TranscriptVerifier {
    fn verify(
        &self,
        identity: &Identity,
        algorithm: &[u8],
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;
}

pub trait EcdhExchange {
    fn public_key(&self) -> &[u8];
    fn shared_secret(&self, peer_public: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait ContinuationProtector {
    fn seal_state(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn open_state(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait KeyConfirmation {
    fn mac(&self, input: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify_mac(&self, input: &[u8], mac: &[u8]) -> Result<(), Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthInput {
    pub role: Role,
    pub identity: Identity,
    pub ecdh_public: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithms: AlgorithmSuite,
    pub peer_nonce: Option<Vec<u8>>,
    pub continuation_state: Option<Vec<u8>>,
}

impl AuthInput {
    pub fn signature_transcript(
        &self,
        protocol_label: &[u8],
        signature_algorithm: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, b"protocol", protocol_label);
        push_field(&mut out, b"purpose", b"sshkey signed ecdh auth v1");
        push_field(&mut out, b"role", &[role_byte(self.role)]);
        push_field(&mut out, b"key-type", &self.identity.key_type);
        push_field(&mut out, b"public-key", &self.identity.public_key);
        push_field(&mut out, b"ecdh-public", &self.ecdh_public);
        push_field(&mut out, b"nonce", &self.nonce);
        push_list(&mut out, b"kex", &self.algorithms.kex);
        push_list(&mut out, b"enctype", &self.algorithms.enctype);
        push_list(&mut out, b"signature", &self.algorithms.signature);
        push_field(&mut out, b"signature-algorithm", signature_algorithm);
        push_optional(&mut out, b"peer-nonce", self.peer_nonce.as_deref());
        push_optional(
            &mut out,
            b"continuation-state",
            self.continuation_state.as_deref(),
        );
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAuth {
    pub input: AuthInput,
    pub signature_algorithm: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedAuth {
    pub fn sign(
        input: AuthInput,
        peer_signature_algorithms: &[Vec<u8>],
        signer: &impl TranscriptSigner,
    ) -> Result<Self, Error> {
        Self::sign_with_label(
            DEFAULT_PROTOCOL_LABEL,
            input,
            peer_signature_algorithms,
            signer,
        )
    }

    pub fn sign_with_label(
        protocol_label: &[u8],
        input: AuthInput,
        peer_signature_algorithms: &[Vec<u8>],
        signer: &impl TranscriptSigner,
    ) -> Result<Self, Error> {
        let algorithm = input
            .algorithms
            .choose_signature(peer_signature_algorithms)
            .ok_or(Error::NoSignatureAlgorithm)?
            .to_vec();
        let transcript = input.signature_transcript(protocol_label, &algorithm);
        let signature = signer.sign(&algorithm, &transcript)?;
        Ok(Self {
            input,
            signature_algorithm: algorithm,
            signature,
        })
    }

    pub fn verify(
        &self,
        verifier: &impl TranscriptVerifier,
    ) -> Result<(), Error> {
        self.verify_with_label(DEFAULT_PROTOCOL_LABEL, verifier)
    }

    pub fn verify_with_label(
        &self,
        protocol_label: &[u8],
        verifier: &impl TranscriptVerifier,
    ) -> Result<(), Error> {
        let transcript = self
            .input
            .signature_transcript(protocol_label, &self.signature_algorithm);
        verifier.verify(
            &self.input.identity,
            &self.signature_algorithm,
            &transcript,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedInput {
    pub role: Role,
    pub exchange_transcript: Vec<u8>,
    pub local_nonce: Vec<u8>,
    pub peer_nonce: Vec<u8>,
}

impl FinishedInput {
    pub fn transcript(&self, protocol_label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, b"protocol", protocol_label);
        push_field(&mut out, b"purpose", b"sshkey signed ecdh finished v1");
        push_field(&mut out, b"role", &[role_byte(self.role)]);
        push_field(&mut out, b"exchange-transcript", &self.exchange_transcript);
        push_field(&mut out, b"local-nonce", &self.local_nonce);
        push_field(&mut out, b"peer-nonce", &self.peer_nonce);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedProof {
    pub role: Role,
    pub mac: Vec<u8>,
}

impl FinishedProof {
    pub fn make(
        input: &FinishedInput,
        keys: &impl KeyConfirmation,
    ) -> Result<Self, Error> {
        let transcript = input.transcript(DEFAULT_PROTOCOL_LABEL);
        Ok(Self {
            role: input.role,
            mac: keys.mac(&transcript)?,
        })
    }

    pub fn verify(
        &self,
        input: &FinishedInput,
        keys: &impl KeyConfirmation,
    ) -> Result<(), Error> {
        if self.role != input.role {
            return Err(Error::InvalidInput);
        }
        let transcript = input.transcript(DEFAULT_PROTOCOL_LABEL);
        keys.verify_mac(&transcript, &self.mac)
    }
}

fn role_byte(role: Role) -> u8 {
    match role {
        Role::Initiator => 0,
        Role::Acceptor => 1,
    }
}

fn push_optional(out: &mut Vec<u8>, tag: &[u8], value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            push_field(out, tag, value);
        }
        None => {
            out.push(0);
            push_field(out, tag, &[]);
        }
    }
}

fn push_list(out: &mut Vec<u8>, tag: &[u8], values: &[Vec<u8>]) {
    push_len(out, tag.len());
    out.extend_from_slice(tag);
    push_len(out, values.len());
    for value in values {
        push_len(out, value.len());
        out.extend_from_slice(value);
    }
}

fn push_field(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    push_len(out, tag.len());
    out.extend_from_slice(tag);
    push_len(out, value.len());
    out.extend_from_slice(value);
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ToySigner;

    impl TranscriptSigner for ToySigner {
        fn sign(
            &self,
            algorithm: &[u8],
            transcript: &[u8],
        ) -> Result<Vec<u8>, Error> {
            let mut out = Vec::new();
            out.extend_from_slice(algorithm);
            out.push(0);
            out.extend_from_slice(transcript);
            Ok(out)
        }
    }

    struct ToyVerifier;

    impl TranscriptVerifier for ToyVerifier {
        fn verify(
            &self,
            _identity: &Identity,
            algorithm: &[u8],
            transcript: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            let mut expected = Vec::new();
            expected.extend_from_slice(algorithm);
            expected.push(0);
            expected.extend_from_slice(transcript);
            if signature == expected {
                Ok(())
            } else {
                Err(Error::SignatureRejected)
            }
        }
    }

    struct ToyKeys;

    impl KeyConfirmation for ToyKeys {
        fn mac(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
            let mut out = b"mac:".to_vec();
            out.extend_from_slice(input);
            Ok(out)
        }

        fn verify_mac(&self, input: &[u8], mac: &[u8]) -> Result<(), Error> {
            if self.mac(input)? == mac {
                Ok(())
            } else {
                Err(Error::SignatureRejected)
            }
        }
    }

    fn input(role: Role) -> AuthInput {
        AuthInput {
            role,
            identity: Identity {
                key_type: b"ssh-ed25519".to_vec(),
                public_key: b"public-key".to_vec(),
            },
            ecdh_public: b"ecdh-public".to_vec(),
            nonce: b"nonce".to_vec(),
            algorithms: AlgorithmSuite {
                kex: vec![b"curve25519-sha256".to_vec()],
                enctype: vec![b"aes256-gcm-sha256".to_vec()],
                signature: vec![
                    b"rsa-sha2-512".to_vec(),
                    b"ssh-ed25519".to_vec(),
                ],
            },
            peer_nonce: None,
            continuation_state: None,
        }
    }

    #[test]
    fn signature_transcript_binds_role_and_algorithms() {
        let initiator = input(Role::Initiator);
        let mut acceptor = input(Role::Acceptor);
        let left = initiator.signature_transcript(b"proto", b"ssh-ed25519");
        let right = acceptor.signature_transcript(b"proto", b"ssh-ed25519");
        assert_ne!(left, right);

        acceptor.role = Role::Initiator;
        acceptor.algorithms.signature = vec![b"ssh-ed25519".to_vec()];
        assert_ne!(
            left,
            acceptor.signature_transcript(b"proto", b"ssh-ed25519")
        );
    }

    #[test]
    fn signed_auth_chooses_peer_compatible_algorithm() {
        let peer_algs = vec![b"ssh-ed25519".to_vec()];
        let signed =
            SignedAuth::sign(input(Role::Initiator), &peer_algs, &ToySigner)
                .unwrap();

        assert_eq!(signed.signature_algorithm, b"ssh-ed25519");
        signed.verify(&ToyVerifier).unwrap();
    }

    #[test]
    fn signed_auth_opportunistically_uses_local_preference() {
        let signed =
            SignedAuth::sign(input(Role::Initiator), &[], &ToySigner).unwrap();

        assert_eq!(signed.signature_algorithm, b"rsa-sha2-512");
        signed.verify(&ToyVerifier).unwrap();
    }

    #[test]
    fn finished_transcript_binds_role_and_nonces() {
        let input = FinishedInput {
            role: Role::Acceptor,
            exchange_transcript: b"exchange".to_vec(),
            local_nonce: b"acceptor".to_vec(),
            peer_nonce: b"initiator".to_vec(),
        };
        let proof = FinishedProof::make(&input, &ToyKeys).unwrap();
        proof.verify(&input, &ToyKeys).unwrap();

        let mut changed = input.clone();
        changed.peer_nonce = b"other".to_vec();
        assert_eq!(
            proof.verify(&changed, &ToyKeys).unwrap_err(),
            Error::SignatureRejected
        );
    }
}
