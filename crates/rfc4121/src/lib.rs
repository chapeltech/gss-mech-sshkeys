use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const HEADER_LEN: usize = 16;
pub const CHECKSUM_TOKEN_ID: [u8; 2] = [0x04, 0x04];
pub const MESSAGE_TOKEN_ID: [u8; 2] = [0x05, 0x04];
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
pub const FLAG_SEALED: u8 = 0x02;
pub const FILLER: u8 = 0xff;
pub const AES256_GCM_SHA256_CHECKSUM_LEN: usize = 32;
pub const AES256_GCM_SHA256_SEALED_OVERHEAD: usize = 16;
pub const AES256_GCM_SHA256_NONCE_LEN: usize = 12;

const ACCEPTOR_SEAL_LABEL: &[u8] = b"RFC4121 KG-USAGE-ACCEPTOR-SEAL 22";
const ACCEPTOR_SIGN_LABEL: &[u8] = b"RFC4121 KG-USAGE-ACCEPTOR-SIGN 23";
const INITIATOR_SEAL_LABEL: &[u8] = b"RFC4121 KG-USAGE-INITIATOR-SEAL 24";
const INITIATOR_SIGN_LABEL: &[u8] = b"RFC4121 KG-USAGE-INITIATOR-SIGN 25";
const NONCE_LABEL: &[u8] = b"RFC4121 AES-256-GCM nonce";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    pub fn is_acceptor(self) -> bool {
        matches!(self, Role::Acceptor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BadSignature,
    DefectiveToken,
    Failure,
    Sequence,
}

pub trait CryptoProfile {
    const CHECKSUM_LEN: usize;
    const SEALED_OVERHEAD: usize;

    fn seal(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error>;

    fn open(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error>;

    fn sign(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
    ) -> Result<Vec<u8>, Error>;

    fn verify(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
        checksum: &[u8],
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionResult {
    pub token: Vec<u8>,
    pub sealed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnprotectionResult {
    pub plaintext: Vec<u8>,
    pub sealed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChecksumResult {
    pub token: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferPlan {
    pub header_len: usize,
    pub data_len: usize,
    pub trailer_len: usize,
    pub stream_len: usize,
    pub sealed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Aes256GcmSha256Profile {
    session_key: Vec<u8>,
}

impl Aes256GcmSha256Profile {
    pub fn new(session_key: impl AsRef<[u8]>) -> Self {
        Self {
            session_key: session_key.as_ref().to_vec(),
        }
    }
}

impl CryptoProfile for Aes256GcmSha256Profile {
    const CHECKSUM_LEN: usize = AES256_GCM_SHA256_CHECKSUM_LEN;
    const SEALED_OVERHEAD: usize = AES256_GCM_SHA256_SEALED_OVERHEAD;

    fn seal(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes256_gcm_sha256_key(
            &self.session_key,
            sender.is_acceptor(),
            true,
        )?;
        let nonce =
            derive_aes256_gcm_sha256_nonce(&key, sender.is_acceptor(), seq)?;
        aes256_gcm_encrypt(&key, &nonce, aad, plaintext)
    }

    fn open(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes256_gcm_sha256_key(
            &self.session_key,
            sender.is_acceptor(),
            true,
        )?;
        let nonce =
            derive_aes256_gcm_sha256_nonce(&key, sender.is_acceptor(), seq)?;
        aes256_gcm_decrypt(&key, &nonce, aad, ciphertext)
    }

    fn sign(
        &self,
        sender: Role,
        _seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes256_gcm_sha256_key(
            &self.session_key,
            sender.is_acceptor(),
            false,
        )?;
        let mut signed =
            Vec::with_capacity(aad.len() + plaintext.len() + HEADER_LEN);
        signed.extend_from_slice(aad);
        signed.extend_from_slice(plaintext);
        signed.extend_from_slice(checksum_header);
        Ok(hmac_sha256(&key, &signed)?.to_vec())
    }

    fn verify(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
        checksum: &[u8],
    ) -> Result<(), Error> {
        let expected =
            self.sign(sender, seq, aad, plaintext, checksum_header)?;
        if constant_time_eq(checksum, &expected) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenState {
    local_role: Role,
    send_seq: u64,
    recv_seq: u64,
}

impl TokenState {
    pub fn new(local_role: Role, send_seq: u64, recv_seq: u64) -> Self {
        Self {
            local_role,
            send_seq,
            recv_seq,
        }
    }

    pub fn send_seq(&self) -> u64 {
        self.send_seq
    }

    pub fn recv_seq(&self) -> u64 {
        self.recv_seq
    }

    pub fn protect<P: CryptoProfile>(
        &mut self,
        profile: &P,
        seal: bool,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<ProtectionResult, Error> {
        let sender = self.local_role;
        let seq = self.send_seq;
        let token_header = header(sender, seal, 0, 0, seq);

        let token = if seal {
            let mut sealed = Vec::with_capacity(plaintext.len() + HEADER_LEN);
            sealed.extend_from_slice(plaintext);
            sealed.extend_from_slice(&token_header);

            let body = profile.seal(sender, seq, aad, &sealed)?;
            let mut token = Vec::with_capacity(HEADER_LEN + body.len());
            token.extend_from_slice(&token_header);
            token.extend_from_slice(&body);
            token
        } else {
            let checksum_header = token_header;
            let checksum =
                profile.sign(sender, seq, aad, plaintext, &checksum_header)?;
            let ec =
                u16::try_from(checksum.len()).map_err(|_| Error::Failure)?;
            let header = header(sender, false, ec, 0, seq);

            let mut token = Vec::with_capacity(
                HEADER_LEN + plaintext.len() + checksum.len(),
            );
            token.extend_from_slice(&header);
            token.extend_from_slice(plaintext);
            token.extend_from_slice(&checksum);
            token
        };

        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(ProtectionResult {
            token,
            sealed: seal,
        })
    }

    pub fn unprotect<P: CryptoProfile>(
        &mut self,
        profile: &P,
        token: &[u8],
        aad: &[u8],
    ) -> Result<UnprotectionResult, Error> {
        if token.len() < HEADER_LEN {
            return Err(Error::DefectiveToken);
        }

        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&token[..HEADER_LEN]);
        if header[..2] != MESSAGE_TOKEN_ID || header[3] != FILLER {
            return Err(Error::DefectiveToken);
        }

        let sender = if header[2] & FLAG_SENT_BY_ACCEPTOR != 0 {
            Role::Acceptor
        } else {
            Role::Initiator
        };
        if sender == self.local_role {
            return Err(Error::BadSignature);
        }

        let flags = header[2] & !(FLAG_SENT_BY_ACCEPTOR | FLAG_SEALED);
        if flags != 0 {
            return Err(Error::DefectiveToken);
        }

        let sealed = header[2] & FLAG_SEALED != 0;
        let ec = u16::from_be_bytes([header[4], header[5]]) as usize;
        let rrc = u16::from_be_bytes([header[6], header[7]]);
        let seq = u64::from_be_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| Error::DefectiveToken)?,
        );
        if seq != self.recv_seq {
            return Err(Error::Sequence);
        }

        let body = unrotate_body(&token[HEADER_LEN..], rrc);
        let plaintext = if sealed {
            let sealed = profile.open(sender, seq, aad, &body)?;
            if sealed.len() < HEADER_LEN {
                return Err(Error::DefectiveToken);
            }
            let split = sealed.len() - HEADER_LEN;
            let (message, encrypted_header) = sealed.split_at(split);
            let expected_header = header_with_zero_rrc(&header);
            if !constant_time_eq(encrypted_header, &expected_header) {
                return Err(Error::BadSignature);
            }
            message.to_vec()
        } else {
            if ec != P::CHECKSUM_LEN || body.len() < ec {
                return Err(Error::DefectiveToken);
            }
            let split = body.len() - ec;
            let (message, checksum) = body.split_at(split);
            let checksum_header = header_with_zero_ec_rrc(&header);
            profile.verify(
                sender,
                seq,
                aad,
                message,
                &checksum_header,
                checksum,
            )?;
            message.to_vec()
        };

        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(UnprotectionResult { plaintext, sealed })
    }

    pub fn checksum<P: CryptoProfile>(
        &mut self,
        profile: &P,
        message: &[u8],
    ) -> Result<ChecksumResult, Error> {
        let sender = self.local_role;
        let seq = self.send_seq;
        let checksum_header = checksum_header(sender, seq);
        let checksum =
            profile.sign(sender, seq, &[], message, &checksum_header)?;
        let mut token = Vec::with_capacity(HEADER_LEN + checksum.len());
        token.extend_from_slice(&checksum_header);
        token.extend_from_slice(&checksum);

        self.send_seq = self.send_seq.wrapping_add(1);
        Ok(ChecksumResult { token })
    }

    pub fn verify_checksum<P: CryptoProfile>(
        &mut self,
        profile: &P,
        message: &[u8],
        token: &[u8],
    ) -> Result<(), Error> {
        if token.len() < HEADER_LEN {
            return Err(Error::DefectiveToken);
        }

        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&token[..HEADER_LEN]);
        if header[..2] != CHECKSUM_TOKEN_ID
            || header[3..8].iter().any(|byte| *byte != FILLER)
        {
            return Err(Error::DefectiveToken);
        }

        let sender = if header[2] & FLAG_SENT_BY_ACCEPTOR != 0 {
            Role::Acceptor
        } else {
            Role::Initiator
        };
        if sender == self.local_role {
            return Err(Error::BadSignature);
        }

        let flags = header[2] & !FLAG_SENT_BY_ACCEPTOR;
        if flags != 0 {
            return Err(Error::DefectiveToken);
        }

        let seq = u64::from_be_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| Error::DefectiveToken)?,
        );
        if seq != self.recv_seq {
            return Err(Error::Sequence);
        }

        let checksum = &token[HEADER_LEN..];
        if checksum.len() != P::CHECKSUM_LEN {
            return Err(Error::DefectiveToken);
        }
        profile.verify(sender, seq, &[], message, &header, checksum)?;
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Ok(())
    }
}

pub fn trailer_len<P: CryptoProfile>(sealed: bool) -> usize {
    if sealed {
        HEADER_LEN + P::SEALED_OVERHEAD
    } else {
        P::CHECKSUM_LEN
    }
}

pub fn buffer_plan<P: CryptoProfile>(
    data_len: usize,
    sealed: bool,
) -> Result<BufferPlan, Error> {
    let trailer_len = trailer_len::<P>(sealed);
    let stream_len = HEADER_LEN
        .checked_add(data_len)
        .and_then(|len| len.checked_add(trailer_len))
        .ok_or(Error::Failure)?;

    Ok(BufferPlan {
        header_len: HEADER_LEN,
        data_len,
        trailer_len,
        stream_len,
        sealed,
    })
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

fn header(
    sender: Role,
    sealed: bool,
    ec: u16,
    rrc: u16,
    seq: u64,
) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    header[..2].copy_from_slice(&MESSAGE_TOKEN_ID);
    header[2] = if sender.is_acceptor() {
        FLAG_SENT_BY_ACCEPTOR
    } else {
        0
    };
    if sealed {
        header[2] |= FLAG_SEALED;
    }
    header[3] = FILLER;
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[6..8].copy_from_slice(&rrc.to_be_bytes());
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    header
}

fn checksum_header(sender: Role, seq: u64) -> [u8; HEADER_LEN] {
    let mut header = [FILLER; HEADER_LEN];
    header[..2].copy_from_slice(&CHECKSUM_TOKEN_ID);
    header[2] = if sender.is_acceptor() {
        FLAG_SENT_BY_ACCEPTOR
    } else {
        0
    };
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    header
}

fn header_with_zero_ec_rrc(header: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut out = *header;
    out[4..8].fill(0);
    out
}

fn header_with_zero_rrc(header: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut out = *header;
    out[6..8].fill(0);
    out
}

fn derive_aes256_gcm_sha256_key(
    session_key: &[u8],
    sender_acceptor: bool,
    seal: bool,
) -> Result<[u8; AES256_GCM_SHA256_CHECKSUM_LEN], Error> {
    let label = match (sender_acceptor, seal) {
        (true, true) => ACCEPTOR_SEAL_LABEL,
        (true, false) => ACCEPTOR_SIGN_LABEL,
        (false, true) => INITIATOR_SEAL_LABEL,
        (false, false) => INITIATOR_SIGN_LABEL,
    };

    hmac_sha256(session_key, label)
}

fn derive_aes256_gcm_sha256_nonce(
    key: &[u8; AES256_GCM_SHA256_CHECKSUM_LEN],
    sender_acceptor: bool,
    seq: u64,
) -> Result<[u8; AES256_GCM_SHA256_NONCE_LEN], Error> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(NONCE_LABEL);
    data.push(u8::from(sender_acceptor));
    data.extend_from_slice(&seq.to_be_bytes());

    let digest = hmac_sha256(key, &data)?;
    let mut nonce = [0u8; AES256_GCM_SHA256_NONCE_LEN];
    nonce.copy_from_slice(&digest[..AES256_GCM_SHA256_NONCE_LEN]);
    Ok(nonce)
}

fn hmac_sha256(
    key: &[u8],
    data: &[u8],
) -> Result<[u8; AES256_GCM_SHA256_CHECKSUM_LEN], Error> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| Error::Failure)?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; AES256_GCM_SHA256_CHECKSUM_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn aes256_gcm_encrypt(
    key: &[u8; AES256_GCM_SHA256_CHECKSUM_LEN],
    nonce: &[u8; AES256_GCM_SHA256_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Failure)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Failure)
}

fn aes256_gcm_decrypt(
    key: &[u8; AES256_GCM_SHA256_CHECKSUM_LEN],
    nonce: &[u8; AES256_GCM_SHA256_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Failure)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::BadSignature)
}

fn unrotate_body(body: &[u8], rrc: u16) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }

    let shift = usize::from(rrc) % body.len();
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[shift..]);
    out.extend_from_slice(&body[..shift]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ToyProfile;

    impl ToyProfile {
        fn mac(
            sender: Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            suffix: &[u8],
        ) -> [u8; 4] {
            let mut acc = 0x4121_0000u32 ^ seq as u32;
            acc ^= if sender.is_acceptor() { 0xa5 } else { 0x5a };
            for byte in aad.iter().chain(plaintext).chain(suffix) {
                acc = acc.rotate_left(5).wrapping_add(u32::from(*byte));
            }
            acc.to_be_bytes()
        }
    }

    impl CryptoProfile for ToyProfile {
        const CHECKSUM_LEN: usize = 4;
        const SEALED_OVERHEAD: usize = 4;

        fn seal(
            &self,
            sender: Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, Error> {
            let tag = Self::mac(sender, seq, aad, plaintext, b"seal");
            let mut out = plaintext.to_vec();
            out.extend_from_slice(&tag);
            Ok(out)
        }

        fn open(
            &self,
            sender: Role,
            seq: u64,
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, Error> {
            if ciphertext.len() < Self::SEALED_OVERHEAD {
                return Err(Error::DefectiveToken);
            }
            let split = ciphertext.len() - Self::SEALED_OVERHEAD;
            let (plaintext, tag) = ciphertext.split_at(split);
            let expected = Self::mac(sender, seq, aad, plaintext, b"seal");
            if !constant_time_eq(tag, &expected) {
                return Err(Error::BadSignature);
            }
            Ok(plaintext.to_vec())
        }

        fn sign(
            &self,
            sender: Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            checksum_header: &[u8; HEADER_LEN],
        ) -> Result<Vec<u8>, Error> {
            Ok(
                Self::mac(sender, seq, aad, plaintext, checksum_header)
                    .to_vec(),
            )
        }

        fn verify(
            &self,
            sender: Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            checksum_header: &[u8; HEADER_LEN],
            checksum: &[u8],
        ) -> Result<(), Error> {
            let expected =
                Self::mac(sender, seq, aad, plaintext, checksum_header);
            if constant_time_eq(checksum, &expected) {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
    }

    #[test]
    fn signed_wrap_round_trips_and_rejects_replay() {
        let profile = ToyProfile;
        let mut initiator = TokenState::new(Role::Initiator, 0, 0);
        let mut acceptor = TokenState::new(Role::Acceptor, 0, 0);

        let wrapped = initiator
            .protect(&profile, false, b"hello", b"aad")
            .unwrap();
        assert!(!wrapped.sealed);
        assert_eq!(initiator.send_seq(), 1);

        let unwrapped = acceptor
            .unprotect(&profile, &wrapped.token, b"aad")
            .unwrap();
        assert_eq!(unwrapped.plaintext, b"hello");
        assert!(!unwrapped.sealed);
        assert_eq!(acceptor.recv_seq(), 1);
        assert_eq!(
            acceptor
                .unprotect(&profile, &wrapped.token, b"aad")
                .unwrap_err(),
            Error::Sequence,
        );
    }

    #[test]
    fn sealed_wrap_round_trips_and_authenticates_aad() {
        let profile = ToyProfile;
        let mut acceptor = TokenState::new(Role::Acceptor, 7, 0);
        let mut initiator = TokenState::new(Role::Initiator, 0, 7);

        let wrapped =
            acceptor.protect(&profile, true, b"secret", b"aad").unwrap();
        assert!(wrapped.sealed);
        assert_eq!(
            wrapped.token.len(),
            HEADER_LEN + b"secret".len() + trailer_len::<ToyProfile>(true),
        );
        assert_eq!(wrapped.token[2] & FLAG_SEALED, FLAG_SEALED);

        let unwrapped = initiator
            .unprotect(&profile, &wrapped.token, b"aad")
            .unwrap();
        assert_eq!(unwrapped.plaintext, b"secret");
        assert!(unwrapped.sealed);

        let wrapped =
            acceptor.protect(&profile, true, b"secret", b"aad").unwrap();
        assert_eq!(
            initiator
                .unprotect(&profile, &wrapped.token, b"bad")
                .unwrap_err(),
            Error::BadSignature,
        );
    }

    #[test]
    fn signed_wrap_rejects_tampering() {
        let profile = ToyProfile;
        let mut initiator = TokenState::new(Role::Initiator, 0, 0);
        let mut acceptor = TokenState::new(Role::Acceptor, 0, 0);
        let mut wrapped =
            initiator.protect(&profile, false, b"hello", b"").unwrap();

        let last = wrapped.token.len() - 1;
        wrapped.token[last] ^= 0x01;
        assert_eq!(
            acceptor
                .unprotect(&profile, &wrapped.token, b"")
                .unwrap_err(),
            Error::BadSignature,
        );
    }

    #[test]
    fn checksum_token_round_trips_and_rejects_tampering() {
        let profile = ToyProfile;
        let mut initiator = TokenState::new(Role::Initiator, 0, 0);
        let mut acceptor = TokenState::new(Role::Acceptor, 0, 0);

        let checksum = initiator.checksum(&profile, b"hello").unwrap();
        assert_eq!(checksum.token[..2], CHECKSUM_TOKEN_ID);
        assert_eq!(checksum.token[3..8], [FILLER; 5]);
        assert_eq!(initiator.send_seq(), 1);

        acceptor
            .verify_checksum(&profile, b"hello", &checksum.token)
            .unwrap();
        assert_eq!(acceptor.recv_seq(), 1);

        let checksum = initiator.checksum(&profile, b"hello").unwrap();
        assert_eq!(
            acceptor
                .verify_checksum(&profile, b"HELLO", &checksum.token)
                .unwrap_err(),
            Error::BadSignature,
        );
    }

    #[test]
    fn buffer_plan_returns_split_lengths() {
        assert_eq!(
            buffer_plan::<ToyProfile>(7, false).unwrap(),
            BufferPlan {
                header_len: HEADER_LEN,
                data_len: 7,
                trailer_len: ToyProfile::CHECKSUM_LEN,
                stream_len: HEADER_LEN + 7 + ToyProfile::CHECKSUM_LEN,
                sealed: false,
            },
        );
        assert_eq!(
            buffer_plan::<ToyProfile>(7, true).unwrap().trailer_len,
            HEADER_LEN + ToyProfile::SEALED_OVERHEAD,
        );
    }

    #[test]
    fn aes256_gcm_sha256_profile_round_trips() {
        let profile = Aes256GcmSha256Profile::new([0x5a; 16]);
        let mut initiator = TokenState::new(Role::Initiator, 0, 0);
        let mut acceptor = TokenState::new(Role::Acceptor, 0, 0);

        let sealed = initiator
            .protect(&profile, true, b"secret", b"aad")
            .unwrap();
        let opened =
            acceptor.unprotect(&profile, &sealed.token, b"aad").unwrap();
        assert_eq!(opened.plaintext, b"secret");
        assert!(opened.sealed);

        let checksum = initiator.checksum(&profile, b"message").unwrap();
        acceptor
            .verify_checksum(&profile, b"message", &checksum.token)
            .unwrap();
    }
}
