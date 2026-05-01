pub const HEADER_LEN: usize = 16;
pub const MESSAGE_TOKEN_ID: [u8; 2] = [0x05, 0x04];
pub const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
pub const FLAG_SEALED: u8 = 0x02;
pub const FILLER: u8 = 0xff;

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
}

pub fn trailer_len<P: CryptoProfile>(sealed: bool) -> usize {
    if sealed {
        HEADER_LEN + P::SEALED_OVERHEAD
    } else {
        P::CHECKSUM_LEN
    }
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
}
