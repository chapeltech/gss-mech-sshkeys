use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};

pub const HEADER_LEN: usize = 16;
pub const CHECKSUM_TOKEN_ID: [u8; 2] = [0x04, 0x04];
pub const MESSAGE_TOKEN_ID: [u8; 2] = [0x05, 0x04];
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
pub const FLAG_SEALED: u8 = 0x02;
pub const FILLER: u8 = 0xff;
pub const AES256_GCM_SHA256_CHECKSUM_LEN: usize = 32;
pub const AES256_GCM_SHA256_SEALED_OVERHEAD: usize = 16;
pub const AES256_GCM_SHA256_NONCE_LEN: usize = 12;
pub const AES128_GCM_SHA256_CHECKSUM_LEN: usize = 32;
pub const AES128_GCM_SHA256_SEALED_OVERHEAD: usize = 16;
pub const AES128_GCM_SHA256_NONCE_LEN: usize = 12;
pub const AES_CTS_BLOCK_LEN: usize = 16;
pub const AES_CTS_CONFOUNDER_LEN: usize = 16;
pub const AES_SHA1_CHECKSUM_LEN: usize = 12;
pub const AES128_SHA2_CHECKSUM_LEN: usize = 16;
pub const AES256_SHA2_CHECKSUM_LEN: usize = 24;
pub const ENCTYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17;
pub const ENCTYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;
pub const ENCTYPE_AES128_CTS_HMAC_SHA256_128: i32 = 19;
pub const ENCTYPE_AES256_CTS_HMAC_SHA384_192: i32 = 20;

const ACCEPTOR_SEAL_LABEL: &[u8] = b"RFC4121 KG-USAGE-ACCEPTOR-SEAL 22";
const ACCEPTOR_SIGN_LABEL: &[u8] = b"RFC4121 KG-USAGE-ACCEPTOR-SIGN 23";
const INITIATOR_SEAL_LABEL: &[u8] = b"RFC4121 KG-USAGE-INITIATOR-SEAL 24";
const INITIATOR_SIGN_LABEL: &[u8] = b"RFC4121 KG-USAGE-INITIATOR-SIGN 25";
const GCM_NONCE_LABEL: &[u8] = b"RFC4121 AES-GCM nonce";
const KEY_USAGE_ACCEPTOR_SEAL: u32 = 22;
const KEY_USAGE_ACCEPTOR_SIGN: u32 = 23;
const KEY_USAGE_INITIATOR_SEAL: u32 = 24;
const KEY_USAGE_INITIATOR_SIGN: u32 = 25;
const KEY_USAGE_ENCRYPTION: u8 = 0xaa;
const KEY_USAGE_INTEGRITY: u8 = 0x55;
const KEY_USAGE_CHECKSUM: u8 = 0x99;

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
    const SEALED_PREFIX_LEN: usize = 0;
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
pub struct Aes128GcmSha256Profile {
    session_key: Vec<u8>,
}

impl Aes128GcmSha256Profile {
    pub fn new(session_key: impl AsRef<[u8]>) -> Self {
        Self {
            session_key: session_key.as_ref().to_vec(),
        }
    }
}

impl CryptoProfile for Aes128GcmSha256Profile {
    const CHECKSUM_LEN: usize = AES128_GCM_SHA256_CHECKSUM_LEN;
    const SEALED_OVERHEAD: usize = AES128_GCM_SHA256_SEALED_OVERHEAD;

    fn seal(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes128_gcm_sha256_key(
            &self.session_key,
            sender.is_acceptor(),
            true,
        )?;
        let nonce = derive_gcm_sha256_nonce(&key, sender.is_acceptor(), seq)?;
        aes128_gcm_encrypt(&key, &nonce, aad, plaintext)
    }

    fn open(
        &self,
        sender: Role,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes128_gcm_sha256_key(
            &self.session_key,
            sender.is_acceptor(),
            true,
        )?;
        let nonce = derive_gcm_sha256_nonce(&key, sender.is_acceptor(), seq)?;
        aes128_gcm_decrypt(&key, &nonce, aad, ciphertext)
    }

    fn sign(
        &self,
        sender: Role,
        _seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
    ) -> Result<Vec<u8>, Error> {
        let key = derive_aes128_gcm_sha256_key(
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AesCtsKind {
    Aes128Sha1,
    Aes256Sha1,
    Aes128Sha256,
    Aes256Sha384,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AesCtsHmacProfile {
    session_key: Vec<u8>,
    kind: AesCtsKind,
}

impl AesCtsHmacProfile {
    fn new(session_key: impl AsRef<[u8]>, kind: AesCtsKind) -> Self {
        Self {
            session_key: session_key.as_ref().to_vec(),
            kind,
        }
    }
}

macro_rules! aes_cts_profile {
    ($name:ident, $kind:expr, $checksum_len:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name {
            inner: AesCtsHmacProfile,
        }

        impl $name {
            pub fn new(session_key: impl AsRef<[u8]>) -> Self {
                Self {
                    inner: AesCtsHmacProfile::new(session_key, $kind),
                }
            }
        }

        impl CryptoProfile for $name {
            const CHECKSUM_LEN: usize = $checksum_len;
            const SEALED_PREFIX_LEN: usize = AES_CTS_CONFOUNDER_LEN;
            const SEALED_OVERHEAD: usize = $checksum_len;

            fn seal(
                &self,
                sender: Role,
                seq: u64,
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<Vec<u8>, Error> {
                self.inner.seal(sender, seq, aad, plaintext)
            }

            fn open(
                &self,
                sender: Role,
                seq: u64,
                aad: &[u8],
                ciphertext: &[u8],
            ) -> Result<Vec<u8>, Error> {
                self.inner.open(sender, seq, aad, ciphertext)
            }

            fn sign(
                &self,
                sender: Role,
                seq: u64,
                aad: &[u8],
                plaintext: &[u8],
                checksum_header: &[u8; HEADER_LEN],
            ) -> Result<Vec<u8>, Error> {
                self.inner
                    .sign(sender, seq, aad, plaintext, checksum_header)
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
                self.inner.verify(
                    sender,
                    seq,
                    aad,
                    plaintext,
                    checksum_header,
                    checksum,
                )
            }
        }
    };
}

aes_cts_profile!(
    Aes128CtsHmacSha1_96Profile,
    AesCtsKind::Aes128Sha1,
    AES_SHA1_CHECKSUM_LEN
);
aes_cts_profile!(
    Aes256CtsHmacSha1_96Profile,
    AesCtsKind::Aes256Sha1,
    AES_SHA1_CHECKSUM_LEN
);
aes_cts_profile!(
    Aes128CtsHmacSha256_128Profile,
    AesCtsKind::Aes128Sha256,
    AES128_SHA2_CHECKSUM_LEN
);
aes_cts_profile!(
    Aes256CtsHmacSha384_192Profile,
    AesCtsKind::Aes256Sha384,
    AES256_SHA2_CHECKSUM_LEN
);

impl CryptoProfile for AesCtsHmacProfile {
    const CHECKSUM_LEN: usize = AES256_SHA2_CHECKSUM_LEN;
    const SEALED_PREFIX_LEN: usize = AES_CTS_CONFOUNDER_LEN;
    const SEALED_OVERHEAD: usize = AES256_SHA2_CHECKSUM_LEN;

    fn seal(
        &self,
        sender: Role,
        _seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut confounded =
            vec![0u8; AES_CTS_CONFOUNDER_LEN + plaintext.len()];
        fill_random(&mut confounded[..AES_CTS_CONFOUNDER_LEN])?;
        confounded[AES_CTS_CONFOUNDER_LEN..].copy_from_slice(plaintext);
        let usage = key_usage(sender, true);
        let ciphertext = self.encrypt(
            usage_constant(usage, KEY_USAGE_ENCRYPTION),
            &confounded,
        )?;
        let checksum = self.sealed_checksum(
            usage_constant(usage, KEY_USAGE_INTEGRITY),
            aad,
            Some(&confounded),
            &ciphertext,
        )?;

        let mut out = Vec::with_capacity(ciphertext.len() + checksum.len());
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    fn open(
        &self,
        sender: Role,
        _seq: u64,
        aad: &[u8],
        ciphertext_and_checksum: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if ciphertext_and_checksum.len()
            < AES_CTS_CONFOUNDER_LEN + self.checksum_len()
        {
            return Err(Error::DefectiveToken);
        }
        let split = ciphertext_and_checksum.len() - self.checksum_len();
        let (ciphertext, checksum) = ciphertext_and_checksum.split_at(split);
        let usage = key_usage(sender, true);
        if self.is_encrypt_then_checksum() {
            let expected = self.sealed_checksum(
                usage_constant(usage, KEY_USAGE_INTEGRITY),
                aad,
                None,
                ciphertext,
            )?;
            if !constant_time_eq(checksum, &expected) {
                return Err(Error::BadSignature);
            }
        }

        let confounded = self
            .decrypt(usage_constant(usage, KEY_USAGE_ENCRYPTION), ciphertext)?;
        if confounded.len() < AES_CTS_CONFOUNDER_LEN {
            return Err(Error::DefectiveToken);
        }
        if !self.is_encrypt_then_checksum() {
            let expected = self.sealed_checksum(
                usage_constant(usage, KEY_USAGE_INTEGRITY),
                aad,
                Some(&confounded),
                ciphertext,
            )?;
            if !constant_time_eq(checksum, &expected) {
                return Err(Error::BadSignature);
            }
        }
        Ok(confounded[AES_CTS_CONFOUNDER_LEN..].to_vec())
    }

    fn sign(
        &self,
        sender: Role,
        _seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; HEADER_LEN],
    ) -> Result<Vec<u8>, Error> {
        let mut signed =
            Vec::with_capacity(aad.len() + plaintext.len() + HEADER_LEN);
        signed.extend_from_slice(aad);
        signed.extend_from_slice(plaintext);
        signed.extend_from_slice(checksum_header);
        self.hmac(
            usage_constant(key_usage(sender, false), KEY_USAGE_CHECKSUM),
            &signed,
            self.checksum_len(),
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
            self.sign(sender, seq, aad, plaintext, checksum_header)?;
        if constant_time_eq(checksum, &expected) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

impl AesCtsHmacProfile {
    fn checksum_len(&self) -> usize {
        match self.kind {
            AesCtsKind::Aes128Sha1 | AesCtsKind::Aes256Sha1 => {
                AES_SHA1_CHECKSUM_LEN
            }
            AesCtsKind::Aes128Sha256 => AES128_SHA2_CHECKSUM_LEN,
            AesCtsKind::Aes256Sha384 => AES256_SHA2_CHECKSUM_LEN,
        }
    }

    fn key_len(&self) -> usize {
        match self.kind {
            AesCtsKind::Aes128Sha1 | AesCtsKind::Aes128Sha256 => 16,
            AesCtsKind::Aes256Sha1 | AesCtsKind::Aes256Sha384 => 32,
        }
    }

    fn is_encrypt_then_checksum(&self) -> bool {
        matches!(
            self.kind,
            AesCtsKind::Aes128Sha256 | AesCtsKind::Aes256Sha384
        )
    }

    fn derived_key(&self, constant: [u8; 5]) -> Result<Vec<u8>, Error> {
        match self.kind {
            AesCtsKind::Aes128Sha1 | AesCtsKind::Aes256Sha1 => {
                rfc3961_derive_aes_key(
                    &self.session_key,
                    &constant,
                    self.key_len(),
                )
            }
            AesCtsKind::Aes128Sha256 => sp800_108_hmac_sha256(
                &self.session_key,
                &constant,
                sp800_108_output_len(&constant, 16, 32),
            ),
            AesCtsKind::Aes256Sha384 => sp800_108_hmac_sha384(
                &self.session_key,
                &constant,
                sp800_108_output_len(&constant, 32, 48),
            ),
        }
    }

    fn hmac(
        &self,
        constant: [u8; 5],
        data: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let key = self.derived_key(constant)?;
        match self.kind {
            AesCtsKind::Aes128Sha1 | AesCtsKind::Aes256Sha1 => {
                Ok(hmac_sha1(&key, data)?[..out_len].to_vec())
            }
            AesCtsKind::Aes128Sha256 => {
                Ok(hmac_sha256(&key, data)?[..out_len].to_vec())
            }
            AesCtsKind::Aes256Sha384 => {
                Ok(hmac_sha384(&key, data)?[..out_len].to_vec())
            }
        }
    }

    fn encrypt(
        &self,
        constant: [u8; 5],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = self.derived_key(constant)?;
        aes_cbc_cts_encrypt(&key, plaintext)
    }

    fn decrypt(
        &self,
        constant: [u8; 5],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = self.derived_key(constant)?;
        aes_cbc_cts_decrypt(&key, ciphertext)
    }

    fn sealed_checksum(
        &self,
        constant: [u8; 5],
        aad: &[u8],
        confounded_plaintext: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        data.extend_from_slice(aad);
        match self.kind {
            AesCtsKind::Aes128Sha1 | AesCtsKind::Aes256Sha1 => {
                let Some(confounded_plaintext) = confounded_plaintext else {
                    return Err(Error::Failure);
                };
                data.extend_from_slice(confounded_plaintext);
            }
            AesCtsKind::Aes128Sha256 | AesCtsKind::Aes256Sha384 => {
                data.extend_from_slice(&[0u8; AES_CTS_BLOCK_LEN]);
                data.extend_from_slice(ciphertext);
            }
        }
        self.hmac(constant, &data, self.checksum_len())
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
    let header_len = if sealed {
        HEADER_LEN
            .checked_add(P::SEALED_PREFIX_LEN)
            .ok_or(Error::Failure)?
    } else {
        HEADER_LEN
    };
    let trailer_len = trailer_len::<P>(sealed);
    let stream_len = header_len
        .checked_add(data_len)
        .and_then(|len| len.checked_add(trailer_len))
        .ok_or(Error::Failure)?;

    Ok(BufferPlan {
        header_len,
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

fn key_usage(sender: Role, seal: bool) -> u32 {
    match (sender.is_acceptor(), seal) {
        (true, true) => KEY_USAGE_ACCEPTOR_SEAL,
        (true, false) => KEY_USAGE_ACCEPTOR_SIGN,
        (false, true) => KEY_USAGE_INITIATOR_SEAL,
        (false, false) => KEY_USAGE_INITIATOR_SIGN,
    }
}

fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let raw = (usage << 8) | u32::from(suffix);
    let mut out = [0u8; 5];
    out[1..].copy_from_slice(&raw.to_be_bytes());
    out
}

fn fill_random(out: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(out).map_err(|_| Error::Failure)
}

fn sp800_108_output_len(
    constant: &[u8; 5],
    key_len: usize,
    digest_len: usize,
) -> usize {
    match constant[4] {
        KEY_USAGE_CHECKSUM | KEY_USAGE_INTEGRITY => digest_len / 2,
        _ => key_len,
    }
}

fn rfc3961_derive_aes_key(
    key: &[u8],
    constant: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, Error> {
    if key.len() != 16 && key.len() != 32 {
        return Err(Error::Failure);
    }

    let mut block = n_fold(constant, AES_CTS_BLOCK_LEN)?;
    let mut out = Vec::with_capacity(key_len);
    while out.len() < key_len {
        aes_encrypt_block(key, &mut block)?;
        out.extend_from_slice(&block);
    }
    out.truncate(key_len);
    Ok(out)
}

fn sp800_108_hmac_sha256(
    key: &[u8],
    label: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    sp800_108_hmac(key, label, out_len, hmac_sha256_vec)
}

fn sp800_108_hmac_sha384(
    key: &[u8],
    label: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    sp800_108_hmac(key, label, out_len, hmac_sha384)
}

fn sp800_108_hmac(
    key: &[u8],
    label: &[u8],
    out_len: usize,
    hmac: fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 1u32;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + 4);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(&((out_len * 8) as u32).to_be_bytes());

        let block = hmac(key, &input)?;
        let len = core::cmp::min(block.len(), out_len - out.len());
        out.extend_from_slice(&block[..len]);
        counter = counter.checked_add(1).ok_or(Error::Failure)?;
    }
    Ok(out)
}

fn n_fold(input: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() || out_len == 0 {
        return Err(Error::Failure);
    }

    let mut out = vec![0u8; out_len];
    let mut tmp = input.to_vec();
    let mut rotated = input.to_vec();
    let mut len = 0usize;

    loop {
        len += input.len();
        while len >= out_len {
            ones_complement_add(&mut out, &tmp[..out_len]);
            len -= out_len;
            if len == 0 {
                break;
            }
            tmp.copy_within(out_len..out_len + len, 0);
            tmp.truncate(len);
        }

        let next = rotate_right_13(&rotated);
        if len != 0 {
            tmp.truncate(len);
            tmp.extend_from_slice(&next);
        }
        rotated = next;
        if len == 0 {
            return Ok(out);
        }
    }
}

fn rotate_right_13(input: &[u8]) -> Vec<u8> {
    let bit_len = input.len() * 8;
    let shift = 13 % bit_len;
    let mut out = vec![0u8; input.len()];

    for (i, byte) in out.iter_mut().enumerate() {
        let mut bit_base = (8 * i) as isize - shift as isize;
        while bit_base < 0 {
            bit_base += bit_len as isize;
        }
        let bit_base = bit_base as usize;
        let b1 = bit_base / 8;
        let s1 = bit_base % 8;
        let s2 = if bit_base + 8 > bit_len {
            (bit_len + 8 - s1) % 8
        } else {
            8 - s1
        };
        let b2 = (b1 + 1) % input.len();
        let left = input[b1].wrapping_shl(s1 as u32);
        let right = if s2 == 8 {
            0
        } else {
            input[b2].wrapping_shr(s2 as u32)
        };
        *byte = left | right;
    }

    out
}

fn ones_complement_add(out: &mut [u8], add: &[u8]) {
    let mut carry = 0u16;
    for i in (0..out.len()).rev() {
        let sum = u16::from(out[i]) + u16::from(add[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }

    while carry != 0 {
        for i in (0..out.len()).rev() {
            let sum = u16::from(out[i]) + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
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

fn derive_aes128_gcm_sha256_key(
    session_key: &[u8],
    sender_acceptor: bool,
    seal: bool,
) -> Result<[u8; 16], Error> {
    let label = match (sender_acceptor, seal) {
        (true, true) => ACCEPTOR_SEAL_LABEL,
        (true, false) => ACCEPTOR_SIGN_LABEL,
        (false, true) => INITIATOR_SEAL_LABEL,
        (false, false) => INITIATOR_SIGN_LABEL,
    };

    let digest = hmac_sha256(session_key, label)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}

fn derive_aes256_gcm_sha256_nonce(
    key: &[u8; AES256_GCM_SHA256_CHECKSUM_LEN],
    sender_acceptor: bool,
    seq: u64,
) -> Result<[u8; AES256_GCM_SHA256_NONCE_LEN], Error> {
    derive_gcm_sha256_nonce(key, sender_acceptor, seq)
}

fn derive_gcm_sha256_nonce(
    key: &[u8],
    sender_acceptor: bool,
    seq: u64,
) -> Result<[u8; AES256_GCM_SHA256_NONCE_LEN], Error> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(GCM_NONCE_LABEL);
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
    let bytes = hmac_sha256_vec(key, data)?;
    let mut out = [0u8; AES256_GCM_SHA256_CHECKSUM_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    type HmacSha1 = Hmac<Sha1>;

    let mut mac =
        <HmacSha1 as Mac>::new_from_slice(key).map_err(|_| Error::Failure)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256_vec(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| Error::Failure)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    type HmacSha384 = Hmac<Sha384>;

    let mut mac =
        <HmacSha384 as Mac>::new_from_slice(key).map_err(|_| Error::Failure)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn aes_encrypt_block(key: &[u8], block: &mut [u8]) -> Result<(), Error> {
    if block.len() != AES_CTS_BLOCK_LEN {
        return Err(Error::Failure);
    }

    match key.len() {
        16 => {
            let cipher =
                Aes128::new_from_slice(key).map_err(|_| Error::Failure)?;
            let block = GenericArray::from_mut_slice(block);
            cipher.encrypt_block(block);
        }
        32 => {
            let cipher =
                Aes256::new_from_slice(key).map_err(|_| Error::Failure)?;
            let block = GenericArray::from_mut_slice(block);
            cipher.encrypt_block(block);
        }
        _ => return Err(Error::Failure),
    }
    Ok(())
}

fn aes_decrypt_block(key: &[u8], block: &mut [u8]) -> Result<(), Error> {
    if block.len() != AES_CTS_BLOCK_LEN {
        return Err(Error::Failure);
    }

    match key.len() {
        16 => {
            let cipher =
                Aes128::new_from_slice(key).map_err(|_| Error::Failure)?;
            let block = GenericArray::from_mut_slice(block);
            cipher.decrypt_block(block);
        }
        32 => {
            let cipher =
                Aes256::new_from_slice(key).map_err(|_| Error::Failure)?;
            let block = GenericArray::from_mut_slice(block);
            cipher.decrypt_block(block);
        }
        _ => return Err(Error::Failure),
    }
    Ok(())
}

fn cbc_encrypt_in_place(key: &[u8], data: &mut [u8]) -> Result<(), Error> {
    if data.len() % AES_CTS_BLOCK_LEN != 0 {
        return Err(Error::Failure);
    }

    let mut prev = [0u8; AES_CTS_BLOCK_LEN];
    for block in data.chunks_exact_mut(AES_CTS_BLOCK_LEN) {
        xor_block(block, &prev);
        aes_encrypt_block(key, block)?;
        prev.copy_from_slice(block);
    }
    Ok(())
}

fn cbc_decrypt_in_place(key: &[u8], data: &mut [u8]) -> Result<(), Error> {
    if data.len() % AES_CTS_BLOCK_LEN != 0 {
        return Err(Error::Failure);
    }

    let mut prev = [0u8; AES_CTS_BLOCK_LEN];
    for block in data.chunks_exact_mut(AES_CTS_BLOCK_LEN) {
        let mut current = [0u8; AES_CTS_BLOCK_LEN];
        current.copy_from_slice(block);
        aes_decrypt_block(key, block)?;
        xor_block(block, &prev);
        prev = current;
    }
    Ok(())
}

fn aes_cbc_cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext.len() < AES_CTS_BLOCK_LEN {
        return Err(Error::Failure);
    }
    if plaintext.len() == AES_CTS_BLOCK_LEN {
        let mut out = plaintext.to_vec();
        cbc_encrypt_in_place(key, &mut out)?;
        return Ok(out);
    }

    let mut out = plaintext.to_vec();
    let full_prefix_len =
        ((plaintext.len() - 1) / AES_CTS_BLOCK_LEN) * AES_CTS_BLOCK_LEN;
    cbc_encrypt_in_place(key, &mut out[..full_prefix_len])?;

    let penultimate = full_prefix_len - AES_CTS_BLOCK_LEN;
    let partial_len = plaintext.len() - full_prefix_len;
    let mut previous = [0u8; AES_CTS_BLOCK_LEN];
    previous
        .copy_from_slice(&out[penultimate..penultimate + AES_CTS_BLOCK_LEN]);

    let mut final_block = previous;
    for i in 0..partial_len {
        final_block[i] ^= out[full_prefix_len + i];
    }
    aes_encrypt_block(key, &mut final_block)?;
    out[penultimate..penultimate + AES_CTS_BLOCK_LEN]
        .copy_from_slice(&final_block);
    out[full_prefix_len..].copy_from_slice(&previous[..partial_len]);
    Ok(out)
}

fn aes_cbc_cts_decrypt(
    key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < AES_CTS_BLOCK_LEN {
        return Err(Error::Failure);
    }
    if ciphertext.len() == AES_CTS_BLOCK_LEN {
        let mut out = ciphertext.to_vec();
        cbc_decrypt_in_place(key, &mut out)?;
        return Ok(out);
    }

    let mut out = ciphertext.to_vec();
    let (offset, prev_cipher, partial_len) = if ciphertext.len()
        > 2 * AES_CTS_BLOCK_LEN
    {
        let prefix_len =
            round_up_to_block(ciphertext.len() - 2 * AES_CTS_BLOCK_LEN);
        let mut prev = [0u8; AES_CTS_BLOCK_LEN];
        prev.copy_from_slice(&out[prefix_len - AES_CTS_BLOCK_LEN..prefix_len]);
        cbc_decrypt_in_place(key, &mut out[..prefix_len])?;
        (
            prefix_len,
            prev,
            ciphertext.len() - prefix_len - AES_CTS_BLOCK_LEN,
        )
    } else {
        (
            0,
            [0u8; AES_CTS_BLOCK_LEN],
            ciphertext.len() - AES_CTS_BLOCK_LEN,
        )
    };

    let mut tmp = [0u8; AES_CTS_BLOCK_LEN];
    tmp.copy_from_slice(&out[offset..offset + AES_CTS_BLOCK_LEN]);
    let mut decrypted_tmp = tmp;
    aes_decrypt_block(key, &mut decrypted_tmp)?;

    let mut stolen = [0u8; AES_CTS_BLOCK_LEN];
    stolen[..partial_len].copy_from_slice(
        &out[offset + AES_CTS_BLOCK_LEN
            ..offset + AES_CTS_BLOCK_LEN + partial_len],
    );
    stolen[partial_len..].copy_from_slice(&decrypted_tmp[partial_len..]);

    for i in 0..partial_len {
        out[offset + AES_CTS_BLOCK_LEN + i] = decrypted_tmp[i] ^ stolen[i];
    }

    let mut penultimate = stolen;
    aes_decrypt_block(key, &mut penultimate)?;
    for i in 0..AES_CTS_BLOCK_LEN {
        out[offset + i] = penultimate[i] ^ prev_cipher[i];
    }
    Ok(out)
}

fn round_up_to_block(len: usize) -> usize {
    len.div_ceil(AES_CTS_BLOCK_LEN) * AES_CTS_BLOCK_LEN
}

fn xor_block(block: &mut [u8], other: &[u8; AES_CTS_BLOCK_LEN]) {
    for (left, right) in block.iter_mut().zip(other) {
        *left ^= *right;
    }
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

fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; AES128_GCM_SHA256_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::Failure)?;
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

fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; AES128_GCM_SHA256_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::Failure)?;
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

    #[test]
    fn aes128_gcm_sha256_profile_round_trips() {
        let profile = Aes128GcmSha256Profile::new([0x5a; 16]);
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

    #[test]
    fn n_fold_matches_rfc3961_vectors() {
        assert_eq!(n_fold(b"012345", 8).unwrap(), hex("be072631276b1955"),);
        assert_eq!(n_fold(b"password", 7).unwrap(), hex("78a07b6caf85fa"));
        assert_eq!(
            n_fold(b"Rough Consensus, and Running Code", 8).unwrap(),
            hex("bb6ed30870b7f0e0"),
        );
    }

    #[test]
    fn aes_cbc_cts_round_trips_varied_lengths() {
        let key128 = [0x11u8; 16];
        let key256 = [0x22u8; 32];

        for len in 16..96 {
            let plaintext = patterned_bytes(len);
            for key in [&key128[..], &key256[..]] {
                let ciphertext = aes_cbc_cts_encrypt(key, &plaintext).unwrap();
                assert_eq!(ciphertext.len(), plaintext.len());
                let decrypted = aes_cbc_cts_decrypt(key, &ciphertext).unwrap();
                assert_eq!(decrypted, plaintext);
            }
        }
    }

    #[test]
    fn aes_sha2_kdf_matches_rfc8009_vectors() {
        let profile128 = AesCtsHmacProfile::new(
            hex("3705d96080c17728a0e800eab6e0d23c"),
            AesCtsKind::Aes128Sha256,
        );
        assert_eq!(
            profile128
                .derived_key(usage_constant(2, KEY_USAGE_CHECKSUM))
                .unwrap(),
            hex("b31a018a48f54776f403e9a396325dc3"),
        );
        assert_eq!(
            profile128
                .derived_key(usage_constant(2, KEY_USAGE_ENCRYPTION))
                .unwrap(),
            hex("9b197dd1e8c5609d6e67c3e37c62c72e"),
        );
        assert_eq!(
            profile128
                .derived_key(usage_constant(2, KEY_USAGE_INTEGRITY))
                .unwrap(),
            hex("9fda0e56ab2d85e1569a688696c26a6c"),
        );

        let profile256 = AesCtsHmacProfile::new(
            hex("6d404d37faf79f9df0d33568d3206698\
                 00eb4836472ea8a026d16b7182460c52"),
            AesCtsKind::Aes256Sha384,
        );
        assert_eq!(
            profile256
                .derived_key(usage_constant(2, KEY_USAGE_CHECKSUM))
                .unwrap(),
            hex("ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d"),
        );
        assert_eq!(
            profile256
                .derived_key(usage_constant(2, KEY_USAGE_ENCRYPTION))
                .unwrap(),
            hex("56ab22bee63d82d7bc5227f6773f8ea7\
                 a5eb1c825160c38312980c442e5c7e49",),
        );
        assert_eq!(
            profile256
                .derived_key(usage_constant(2, KEY_USAGE_INTEGRITY))
                .unwrap(),
            hex("69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f"),
        );
    }

    #[test]
    fn aes_cts_hmac_profiles_round_trip_wrap_and_mic() {
        assert_aes_cts_profile(Aes128CtsHmacSha1_96Profile::new([0x10; 16]));
        assert_aes_cts_profile(Aes256CtsHmacSha1_96Profile::new([0x20; 32]));
        assert_aes_cts_profile(Aes128CtsHmacSha256_128Profile::new([0x30; 16]));
        assert_aes_cts_profile(Aes256CtsHmacSha384_192Profile::new([0x40; 32]));
    }

    fn assert_aes_cts_profile<P: CryptoProfile>(profile: P) {
        let mut initiator = TokenState::new(Role::Initiator, 0, 0);
        let mut acceptor = TokenState::new(Role::Acceptor, 0, 0);

        let plan = buffer_plan::<P>(b"secret".len(), true).unwrap();
        assert_eq!(plan.header_len, HEADER_LEN + AES_CTS_CONFOUNDER_LEN);
        assert_eq!(plan.trailer_len, HEADER_LEN + P::CHECKSUM_LEN);

        let sealed = initiator
            .protect(&profile, true, b"secret", b"metadata")
            .unwrap();
        assert_eq!(sealed.token.len(), plan.stream_len);
        let opened = acceptor
            .unprotect(&profile, &sealed.token, b"metadata")
            .unwrap();
        assert_eq!(opened.plaintext, b"secret");

        let checksum = initiator.checksum(&profile, b"mic").unwrap();
        acceptor
            .verify_checksum(&profile, b"mic", &checksum.token)
            .unwrap();
    }

    fn patterned_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn hex(input: &str) -> Vec<u8> {
        let input: String =
            input.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(input.len() % 2, 0);
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }
}
