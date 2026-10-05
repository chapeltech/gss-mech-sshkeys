#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;
use std::cell::RefCell;
use std::env;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asn1::sshkey::{
    EncCtx, EncSshKeyUserAuth, SshKeyFinished, SshKeyHostAuth, SshKeyKEX,
    SshKeyServerContext, SshKeyStatus, SshKeyToken, SshKeyUserAuth,
};
use gss_mech_builder::sys::*;
use gss_mech_builder::{
    canonical_channel_bindings, clear_buffer, set_buffer_bytes, set_minor,
    AcceptSecContextResult, Aes128CtsHmacSha256128Profile, ChannelBindings,
    ContextMechanism, CredentialMechanism, DisplayName, EstablishmentMechanism,
    InitSecContextResult, LocalNameMechanism, MechanismInfo, NameMechanism,
    Rfc4121Context, Rfc4121ReceiveState, Role, StaticOidDesc, Status,
    MESSAGE_PROTECTION_CHECKSUM_LEN, MESSAGE_PROTECTION_CONFOUNDER_LEN,
    MESSAGE_PROTECTION_HEADER_LEN,
};
use rasn::types::{Integer, OctetString};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use ssh_config::authorized_keys::{
    parse_line as parse_authorized_key_line, AuthorizedKeyEntry,
    AuthorizedKeyOption,
};
use ssh_config::client::{
    ClientConfig, ClientConfigContext, ClientOptions, ConnectionResolveContext,
    VerifyHostKeyDns,
};
use ssh_config::server::{
    PermitRootLogin, ServerConfig, ServerOptions, ServerResolveContext,
};
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature as SshSignature};
use zeroize::{Zeroize, Zeroizing};

mod host_trust;
mod sshfp;

mod asn1 {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/sshkey_asn1.rs"));
}

type c_uchar = u8;
type c_uint = u32;

#[repr(C)]
struct EVP_PKEY {
    _private: [u8; 0],
}

#[repr(C)]
struct EVP_PKEY_CTX {
    _private: [u8; 0],
}

#[repr(C)]
struct EVP_MD {
    _private: [u8; 0],
}

const EVP_PKEY_X25519: c_int = 1034;

const SSH_KEY_COMPLETE: u8 = 1;
const SSH_KEY_CONTINUE_NEEDED: u8 = 2;
const GSS_S_NO_CRED_LOCAL: OM_uint32 = 7 << 16;

static SSHKEY_OID_ELEMENTS: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01];
static SSHKEY_OID_DESC: StaticOidDesc =
    StaticOidDesc::new(&SSHKEY_OID_ELEMENTS);

const SSHKEY_NAME_TYPES: &[&[u8]] = &[
    gss_mech_builder::GSSAPI_OID_NT_USER_NAME,
    gss_mech_builder::GSSAPI_OID_NT_HOSTBASED_SERVICE,
    gss_mech_builder::GSSAPI_OID_NT_HOSTBASED_SERVICE_X,
    gss_mech_builder::GSSAPI_OID_NT_EXPORT_NAME,
];

const SSHKEY_MECH_ATTRS: &[&[u8]] = &[
    gss_mech_builder::GSS_C_MA_MECH_CONCRETE,
    gss_mech_builder::GSS_C_MA_AUTH_INIT,
    gss_mech_builder::GSS_C_MA_AUTH_TARG,
    gss_mech_builder::GSS_C_MA_INTEG_PROT,
    gss_mech_builder::GSS_C_MA_CONF_PROT,
    gss_mech_builder::GSS_C_MA_MIC,
    gss_mech_builder::GSS_C_MA_WRAP,
    gss_mech_builder::GSS_C_MA_REPLAY_DET,
    gss_mech_builder::GSS_C_MA_OOS_DET,
    gss_mech_builder::GSS_C_MA_CBINDINGS,
];

const KEX_ALG: &[u8] = b"curve25519-sha256";
const ENC_ALG: &[u8] = b"aes128-cts-hmac-sha256-128";
const SIG_ALGS: &[u8] = b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";
const SANON_KDF_LABEL: &[u8] = b"sanon-x25519";
const SANON_SESSION_KEY_LEN: usize = 16;
const X25519_PUBLIC_LEN: usize = 32;
const X25519_SHARED_LEN: usize = 32;
const CONTEXT_KEY_LEN: usize = 32;
const PRIVATE_SEAL_KEY_LEN: usize = 16;
const CFX_HEADER_LEN: usize = MESSAGE_PROTECTION_HEADER_LEN;
const CFX_SEALED_HEADER_LEN: usize =
    CFX_HEADER_LEN + MESSAGE_PROTECTION_CONFOUNDER_LEN;
const CFX_SEALED_TRAILER_LEN: usize =
    CFX_HEADER_LEN + MESSAGE_PROTECTION_CHECKSUM_LEN;
const CFX_CHECKSUM_LEN: usize = MESSAGE_PROTECTION_CHECKSUM_LEN;
const CFX_HMAC_LEN: usize = 32;
const HANDSHAKE_NONCE_LEN: usize = 32;
const SERVER_CONTEXT_MAX_AGE_SECONDS: u64 = 120;
const SERVER_CONTEXT_CLOCK_SKEW_SECONDS: u64 = 5;
const SERVER_CONTEXT_LABEL: &[u8] = b"SSHKEY server context v1";
const USERAUTH_LABEL: &[u8] = b"SSHKEY userauth v1";
const FINISHED_KEY_LABEL: &[u8] = b"SSHKEY finished key v1";
const INITIATOR_FINISHED_LABEL: &[u8] = b"gss-sshkey initiator finished v1";
const ACCEPTOR_FINISHED_LABEL: &[u8] = b"gss-sshkey acceptor finished v1";
const ACCEPTOR_RETRY_FINISHED_LABEL: &[u8] = b"gss-sshkey acceptor retry v1";
const HOSTAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey hostauth v1";
const HOSTCHALLENGE_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey hostchallenge v1";
const USERAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey userauth v1";
const USERAUTH_RETRY_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey userauth retry v1";
const SSHKEY_CTX_KEY_ENV: &str = "SSHKEY_CTX_KEY";
const SSHKEY_HOST_KEY_ENV: &str = "SSHKEY_HOST_KEY";
const SSHKEY_USER_ENV: &str = "SSHKEY_USER";
const SSH_AGENT_MAX_REPLY_LEN: usize = 16 * 1024 * 1024;
const MAX_CONTEXT_TOKEN_LEN: usize = 256 * 1024;
const MAX_ENCRYPTED_FIELD_LEN: usize = 128 * 1024;
const MAX_KEY_BLOB_LEN: usize = 64 * 1024;
const MAX_SIGNATURE_LEN: usize = 64 * 1024;
const MAX_ALGORITHM_LIST_LEN: usize = 4 * 1024;
const MAX_NAME_LEN: usize = 1024;
const MAX_FINISHED_MAC_LEN: usize = 64;
const SSH_AGENT_TIMEOUT: Duration = Duration::from_secs(5);
const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH2_AGENT_FAILURE: u8 = 30;
const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;
const SSHKEY_KNOWN_HOSTS_ENV: &str = "SSHKEY_KNOWN_HOSTS";
const SSHKEY_HOST_ENV: &str = "SSHKEY_HOST";
const SSHKEY_SSH_CONFIG_ENV: &str = "SSHKEY_SSH_CONFIG";
const SSHKEY_SSHD_CONFIG_ENV: &str = "SSHKEY_SSHD_CONFIG";
const SSHKEY_AUTHORIZED_KEYS_ENV: &str = "SSHKEY_AUTHORIZED_KEYS";
const CONTEXT_VERSION: OM_uint32 = 1;
const CONTEXT_CLIENT: OM_uint32 = 1;
const CONTEXT_SERVER: OM_uint32 = 2;
const CONTEXT_ALL: OM_uint32 = OM_uint32::MAX;

#[link(name = "crypto")]
unsafe extern "C" {
    fn EVP_PKEY_CTX_new_id(id: c_int, engine: *mut c_void)
        -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_new(
        pkey: *mut EVP_PKEY,
        engine: *mut c_void,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_keygen(
        ctx: *mut EVP_PKEY_CTX,
        ppkey: *mut *mut EVP_PKEY,
    ) -> c_int;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_get_raw_public_key(
        pkey: *const EVP_PKEY,
        pubkey: *mut c_uchar,
        len: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_get_raw_private_key(
        pkey: *const EVP_PKEY,
        privkey: *mut c_uchar,
        len: *mut usize,
    ) -> c_int;
    fn EVP_PKEY_new_raw_public_key(
        pkey_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        keylen: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_new_raw_private_key(
        pkey_type: c_int,
        engine: *mut c_void,
        key: *const c_uchar,
        keylen: usize,
    ) -> *mut EVP_PKEY;
    fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_derive_set_peer(
        ctx: *mut EVP_PKEY_CTX,
        peer: *mut EVP_PKEY,
    ) -> c_int;
    fn EVP_PKEY_derive(
        ctx: *mut EVP_PKEY_CTX,
        key: *mut c_uchar,
        keylen: *mut usize,
    ) -> c_int;
    fn EVP_sha256() -> *const EVP_MD;
    fn HMAC(
        evp_md: *const EVP_MD,
        key: *const c_void,
        key_len: c_int,
        data: *const c_uchar,
        data_len: usize,
        md: *mut c_uchar,
        md_len: *mut c_uint,
    ) -> *mut c_uchar;
}

#[derive(Clone)]
struct SshKeyName {
    value: Vec<u8>,
    authorized_user: Option<Vec<u8>>,
}

struct SshKeyCredential {
    name: Option<SshKeyName>,
    usage: gss_cred_usage_t,
}

struct SshKeyMechanism;

impl NameMechanism for SshKeyMechanism {
    type Name = SshKeyName;

    const MECH_OID: &'static [u8] = &SSHKEY_OID_ELEMENTS;
    const NAME_TYPES: &'static [&'static [u8]] = SSHKEY_NAME_TYPES;

    fn import_name(
        input: &[u8],
        _name_type: Option<&[u8]>,
    ) -> Result<Self::Name, Status> {
        trace("import mechanism name");
        Ok(SshKeyName {
            value: input.to_vec(),
            authorized_user: None,
        })
    }

    fn display_name(name: &Self::Name) -> Result<DisplayName, Status> {
        Ok(DisplayName::new(name.value.clone()))
    }

    fn compare_name(
        left: &Self::Name,
        right: &Self::Name,
    ) -> Result<bool, Status> {
        Ok(left.value == right.value)
    }
}

impl LocalNameMechanism for SshKeyMechanism {
    fn local_name(
        name: &Self::Name,
        _mech_type: Option<&[u8]>,
    ) -> Result<Vec<u8>, Status> {
        name.authorized_user
            .clone()
            .ok_or_else(|| Status::new(GSS_S_UNAUTHORIZED, libc::EACCES as u32))
    }
}

impl MechanismInfo for SshKeyMechanism {
    const MECH_OIDS: &'static [&'static [u8]] = &[&SSHKEY_OID_ELEMENTS];
    const SASL_NAMES: &'static [&'static [u8]] = &[b"SSHKEY"];
    const MECH_NAME: &'static [u8] = b"SSH public-key mechanism";
    const MECH_DESCRIPTION: &'static [u8] =
        b"GSS authentication using SSH public keys";
    const MECH_ATTRS: &'static [&'static [u8]] = SSHKEY_MECH_ATTRS;
    const KNOWN_MECH_ATTRS: &'static [&'static [u8]] =
        gss_mech_builder::GSS_C_MA_KNOWN_ATTRS;
    const STATUS_MESSAGE: &'static [u8] = b"GSS-SSHKEY mechanism status";
}

impl CredentialMechanism for SshKeyMechanism {
    type Name = SshKeyName;
    type Credential = SshKeyCredential;

    const MECH_OIDS: &'static [&'static [u8]] = &[&SSHKEY_OID_ELEMENTS];

    fn acquire_cred(
        desired_name: Option<&Self::Name>,
        desired_mechs: &[Vec<u8>],
        cred_usage: gss_cred_usage_t,
    ) -> Result<Self::Credential, Status> {
        if cred_usage > 2
            || desired_mechs.iter().any(|oid| oid != &SSHKEY_OID_ELEMENTS)
        {
            return Err(Status::new(GSS_S_BAD_MECH, EINVAL));
        }
        if desired_name.is_some() && cred_usage != 2 {
            return Err(Status::new(GSS_S_UNAVAILABLE, ENOTSUP));
        }
        let name = desired_name
            .map(|name| {
                canonicalize_acceptor_credential_name(&name.value).map(
                    |value| SshKeyName {
                        value,
                        authorized_user: None,
                    },
                )
            })
            .transpose()
            .map_err(|_| Status::new(GSS_S_BAD_NAME, EINVAL))?;
        Ok(SshKeyCredential {
            name,
            usage: cred_usage,
        })
    }

    fn add_cred(
        _input_cred: Option<&Self::Credential>,
        desired_name: Option<&Self::Name>,
        desired_mech: &[u8],
        cred_usage: gss_cred_usage_t,
    ) -> Result<Self::Credential, Status> {
        if desired_mech != SSHKEY_OID_ELEMENTS {
            return Err(Status::new(GSS_S_BAD_MECH, EINVAL));
        }
        Self::acquire_cred(desired_name, &[desired_mech.to_vec()], cred_usage)
    }

    fn credential_name(credential: &Self::Credential) -> Option<Self::Name> {
        credential.name.clone()
    }

    fn credential_usage(credential: &Self::Credential) -> gss_cred_usage_t {
        credential.usage
    }
}

struct SshKeyCtx {
    is_initiator: bool,
    complete: bool,
    ecdh_key: Option<OpenSslPkey>,
    public_key: Option<[u8; X25519_PUBLIC_LEN]>,
    peer_public_key: Option<[u8; X25519_PUBLIC_LEN]>,
    session_key: Option<Zeroizing<[u8; SANON_SESSION_KEY_LEN]>>,
    message_profile: Option<SshKeyRfc4121Profile>,
    initiator_sigtypes: Vec<u8>,
    acceptor_sigtypes: Vec<u8>,
    server_context: Option<Vec<u8>>,
    display_name: Vec<u8>,
    acceptor_name: Option<Vec<u8>>,
    client_policy: Option<ClientPolicy>,
    authorized_user: Option<Vec<u8>>,
    server_peer_address: Option<String>,
    initiator_nonce: Option<Vec<u8>>,
    acceptor_nonce: Option<Vec<u8>>,
    channel_bindings: Option<Vec<u8>>,
    channel_bound: bool,
    server_first: bool,
    userauth_candidates_ready: bool,
    userauth_candidates: Vec<UserAuthCandidate>,
    next_userauth_candidate: usize,
    pending_userauth: Option<Vec<u8>>,
    send_seq: u64,
    receive_state: Rfc4121ReceiveState,
}

impl SshKeyCtx {
    fn new(is_initiator: bool) -> Self {
        Self {
            is_initiator,
            complete: false,
            ecdh_key: None,
            public_key: None,
            peer_public_key: None,
            session_key: None,
            message_profile: None,
            initiator_sigtypes: SIG_ALGS.to_vec(),
            acceptor_sigtypes: SIG_ALGS.to_vec(),
            server_context: None,
            display_name: b"sshkey".to_vec(),
            acceptor_name: None,
            client_policy: None,
            authorized_user: None,
            server_peer_address: None,
            initiator_nonce: None,
            acceptor_nonce: None,
            channel_bindings: None,
            channel_bound: false,
            server_first: false,
            userauth_candidates_ready: false,
            userauth_candidates: Vec::new(),
            next_userauth_candidate: 0,
            pending_userauth: None,
            send_seq: 0,
            receive_state: Rfc4121ReceiveState::new(0),
        }
    }

    fn zeroize_secrets(&mut self) {
        if let Some(session_key) = self.session_key.as_mut() {
            session_key.zeroize();
        }
    }

    fn clear_session_key(&mut self) {
        self.zeroize_secrets();
        self.session_key = None;
        self.message_profile = None;
    }

    fn set_session_key(&mut self, session_key: [u8; SANON_SESSION_KEY_LEN]) {
        self.clear_session_key();
        self.message_profile = Some(SshKeyRfc4121Profile::new(session_key));
        self.session_key = Some(Zeroizing::new(session_key));
    }
}

impl Drop for SshKeyCtx {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

impl ContextMechanism for SshKeyMechanism {
    type Name = SshKeyName;
    type Context = SshKeyCtx;

    fn source_name(ctx: &Self::Context) -> Option<Self::Name> {
        ctx.complete.then(|| SshKeyName {
            value: ctx.display_name.clone(),
            authorized_user: ctx.authorized_user.clone(),
        })
    }

    fn target_name(ctx: &Self::Context) -> Option<Self::Name> {
        ctx.acceptor_name.as_ref().map(|name| SshKeyName {
            value: name.clone(),
            authorized_user: None,
        })
    }

    fn mech(_ctx: &Self::Context) -> &'static StaticOidDesc {
        &SSHKEY_OID_DESC
    }

    fn flags(ctx: &Self::Context) -> OM_uint32 {
        sshkey_context_flags(ctx.complete && ctx.channel_bound)
    }

    fn lifetime(_ctx: &Self::Context) -> OM_uint32 {
        GSS_C_INDEFINITE
    }

    fn locally_initiated(ctx: &Self::Context) -> bool {
        ctx.is_initiator
    }

    fn open(ctx: &Self::Context) -> bool {
        ctx.complete
    }

    fn max_input_size(
        _ctx: &Self::Context,
        conf_req_flag: bool,
        req_output_size: OM_uint32,
    ) -> OM_uint32 {
        let overhead = if conf_req_flag {
            CFX_SEALED_HEADER_LEN + CFX_SEALED_TRAILER_LEN
        } else {
            CFX_HEADER_LEN + CFX_CHECKSUM_LEN
        };
        req_output_size.saturating_sub(overhead as OM_uint32)
    }
}

struct OpenSslPkey {
    ptr: *mut EVP_PKEY,
}

impl Drop for OpenSslPkey {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                EVP_PKEY_free(self.ptr);
            }
        }
    }
}

fn token_status(value: u8) -> SshKeyStatus {
    SshKeyStatus(Integer::from(value))
}

fn token_has_status(token: &SshKeyToken, value: u8) -> bool {
    token.status.0 == Integer::from(value)
}

fn required_userauth(
    token: &SshKeyToken,
) -> Result<&EncSshKeyUserAuth, OM_uint32> {
    token.encuserauth.as_ref().ok_or(GSS_S_UNAUTHORIZED)
}

fn trace(message: &str) {
    if env::var_os("SSHKEY_TRACE").is_some() {
        eprintln!("gss-sshkey: {message}");
    }
}

fn sshkey_context_flags(channel_bound: bool) -> OM_uint32 {
    let mut flags = GSS_C_MUTUAL_FLAG
        | GSS_C_REPLAY_FLAG
        | GSS_C_SEQUENCE_FLAG
        | GSS_C_CONF_FLAG
        | GSS_C_INTEG_FLAG;
    if channel_bound {
        flags |= GSS_C_CHANNEL_BOUND_FLAG;
    }
    flags
}

fn remember_channel_bindings(
    ctx: &mut SshKeyCtx,
    channel_bindings: &[u8],
    channel_bound: bool,
) -> Result<(), ()> {
    if ctx
        .channel_bindings
        .as_deref()
        .is_some_and(|existing| existing != channel_bindings)
    {
        return Err(());
    }
    if ctx.channel_bindings.is_none() {
        ctx.channel_bindings = Some(channel_bindings.to_vec());
    }
    ctx.channel_bound = channel_bound;
    Ok(())
}

fn kex_octets_match(value: &Option<OctetString>, expected: &[u8]) -> bool {
    match value {
        Some(value) => value.as_ref() == expected,
        None => false,
    }
}

fn kex_public_key(kex: &SshKeyKEX) -> Option<[u8; X25519_PUBLIC_LEN]> {
    let public = kex.pk.as_ref()?;
    public.as_ref().try_into().ok()
}

fn kex_nonce(kex: &SshKeyKEX) -> Option<Vec<u8>> {
    let nonce = kex.nonce.as_ref()?;
    if nonce.as_ref().len() != HANDSHAKE_NONCE_LEN {
        return None;
    }
    Some(nonce.as_ref().to_vec())
}

fn kex_acceptor_name(kex: &SshKeyKEX) -> Option<Vec<u8>> {
    let name = kex.acceptor_name.as_ref()?;
    canonicalize_acceptor_credential_name(name.as_ref()).ok()
}

fn generate_handshake_nonce() -> Option<Vec<u8>> {
    let mut nonce = vec![0u8; HANDSHAKE_NONCE_LEN];
    fill_random(&mut nonce).then_some(nonce)
}

fn initial_context_token(
    public_key: &[u8; X25519_PUBLIC_LEN],
    nonce: &[u8],
    acceptor_name: &[u8],
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from_static(SIG_ALGS),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(public_key.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
        Some(OctetString::from(nonce)),
        Some(OctetString::from(acceptor_name)),
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
        None,
        None,
        None,
        None,
        None,
    );

    rasn::der::encode(&token).map(|inner| encapsulate_initial_token(&inner))
}

fn acceptor_context_token(
    public_key: &[u8; X25519_PUBLIC_LEN],
    acceptor_sigtypes: &[u8],
    hostauth: Option<SshKeyHostAuth>,
    sctx: EncCtx,
    nonce: &[u8],
    acceptor_name: &[u8],
    finished: Option<SshKeyFinished>,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from(acceptor_sigtypes),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(public_key.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
        Some(OctetString::from(nonce)),
        Some(OctetString::from(acceptor_name)),
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
        hostauth,
        None,
        None,
        Some(sctx),
        finished,
    );

    rasn::der::encode(&token)
}

fn initiator_final_token(
    kex: Option<SshKeyKEX>,
    encuserauth: EncSshKeyUserAuth,
    sctx: EncCtx,
    finished: SshKeyFinished,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let token = SshKeyToken::new(
        token_status(SSH_KEY_COMPLETE),
        kex,
        None,
        Some(encuserauth),
        None,
        Some(sctx),
        Some(finished),
    );

    rasn::der::encode(&token)
}

fn initiator_response_kex(
    initiator_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_name: &[u8],
) -> SshKeyKEX {
    SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from(initiator_sigtypes),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(initiator_public.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
        Some(OctetString::from(initiator_nonce)),
        Some(OctetString::from(acceptor_name)),
    )
}

fn userauth_retry_token(
    acceptor_sigtypes: &[u8],
    sctx: EncCtx,
    finished: SshKeyFinished,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from(acceptor_sigtypes),
        None,
        None,
        None,
        None,
        None,
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
        None,
        None,
        None,
        Some(sctx),
        Some(finished),
    );

    rasn::der::encode(&token)
}

fn validate_initiator_kex(kex: &SshKeyKEX) -> Option<[u8; X25519_PUBLIC_LEN]> {
    if kex.kextypes.as_ref() != KEX_ALG {
        return None;
    }
    if kex.enctypes.as_ref() != ENC_ALG {
        return None;
    }
    if !kex_octets_match(&kex.kextype, KEX_ALG) {
        return None;
    }
    if !kex_octets_match(&kex.enctype, ENC_ALG) {
        return None;
    }
    kex_public_key(kex)
}

fn validate_acceptor_kex(kex: &SshKeyKEX) -> Option<[u8; X25519_PUBLIC_LEN]> {
    if kex.kextypes.as_ref() != KEX_ALG {
        return None;
    }
    if kex.enctypes.as_ref() != ENC_ALG {
        return None;
    }
    if !kex_octets_match(&kex.kextype, KEX_ALG) {
        return None;
    }
    if !kex_octets_match(&kex.enctype, ENC_ALG) {
        return None;
    }
    kex_public_key(kex)
}

fn push_ssh_string(out: &mut Vec<u8>, value: &[u8]) -> Option<()> {
    let len: u32 = value.len().try_into().ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Some(())
}

fn push_ssh_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_ssh_u32(input: &mut &[u8]) -> Option<u32> {
    if input.len() < 4 {
        return None;
    }
    let (head, rest) = input.split_at(4);
    *input = rest;
    Some(u32::from_be_bytes(head.try_into().ok()?))
}

fn read_ssh_string(input: &mut &[u8]) -> Option<Vec<u8>> {
    let len = read_ssh_u32(input)? as usize;
    if input.len() < len {
        return None;
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Some(value.to_vec())
}

fn signature_algorithms(key_alg: &Algorithm) -> Vec<Vec<u8>> {
    match key_alg {
        Algorithm::Ed25519 => vec![b"ssh-ed25519".to_vec()],
        Algorithm::Ecdsa { .. } => vec![key_alg.as_str().as_bytes().to_vec()],
        Algorithm::Rsa { .. } => {
            vec![b"rsa-sha2-512".to_vec(), b"rsa-sha2-256".to_vec()]
        }
        Algorithm::SkEd25519 => {
            vec![b"sk-ssh-ed25519@openssh.com".to_vec()]
        }
        Algorithm::SkEcdsaSha2NistP256 => {
            vec![b"sk-ecdsa-sha2-nistp256@openssh.com".to_vec()]
        }
        _ => Vec::new(),
    }
}

fn agent_signature_flags(sigtype: &[u8]) -> u32 {
    match sigtype {
        b"rsa-sha2-256" => SSH_AGENT_RSA_SHA2_256,
        b"rsa-sha2-512" => SSH_AGENT_RSA_SHA2_512,
        _ => 0,
    }
}

#[derive(Clone)]
struct AgentIdentity {
    key: Vec<u8>,
    public_key: PublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum UserAuthSigner {
    Agent(PathBuf),
    IdentityFile(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserAuthCandidate {
    keytype: Vec<u8>,
    key: Vec<u8>,
    sigtype: Vec<u8>,
    signer: UserAuthSigner,
}

#[derive(Clone)]
struct ClientPolicy {
    host: String,
    acceptor_name: Vec<u8>,
    known_hosts_name: String,
    username: Vec<u8>,
    agent_socket: Option<PathBuf>,
    identity_files: Vec<PathBuf>,
    identities_only: bool,
    accepted_algorithms: Vec<String>,
    host_key_algorithms: Vec<String>,
    required_rsa_size: usize,
    known_hosts_files: Vec<PathBuf>,
    verified_host_key: Option<Vec<u8>>,
    verify_host_key_dns: bool,
}

fn validate_supported_host_trust_options(
    options: &ClientOptions,
) -> Result<(), String> {
    if options
        .revoked_host_keys
        .as_deref()
        .is_some_and(|path| !path.eq_ignore_ascii_case("none"))
    {
        return Err("RevokedHostKeys is not supported".to_string());
    }
    if options
        .known_hosts_command
        .as_ref()
        .is_some_and(|command| !command.is_empty())
    {
        return Err("KnownHostsCommand is not supported".to_string());
    }
    Ok(())
}

impl ClientPolicy {
    fn resolve(
        original_host: &str,
        service: &str,
        explicit: ClientContextInput,
    ) -> Result<Self, String> {
        let local_user = env::var("USER")
            .ok()
            .filter(|user| valid_username(user))
            .ok_or_else(|| "local username is unavailable".to_string())?;
        let home = env::var_os("HOME").map(PathBuf::from);
        let context = ClientConfigContext {
            captured_env: None,
            home: home.as_deref(),
            shell: None,
        };
        let paths = client_config_paths(home.as_deref())?;
        let config = ClientConfig::parse_files_with_context(&paths, context);

        let defaults = client_defaults(&local_user);
        let mut overrides = ClientOptions::default();
        if let Some(user) = explicit.user {
            overrides.user = Some(user);
        } else if let Ok(user) = env::var(SSHKEY_USER_ENV) {
            if !valid_username(&user) {
                return Err("invalid requested username".to_string());
            }
            overrides.user = Some(user);
        }
        let resolved = config.resolve_connection_with_context(
            ConnectionResolveContext {
                original_host,
                local_user: Some(&local_user),
            },
            &overrides,
            &defaults,
            context,
        )?;
        let options = resolved.options;
        let host = normalize_host(&resolved.host)
            .ok_or_else(|| "resolved host is invalid".to_string())?;
        validate_supported_host_trust_options(&options)?;

        if options.gssapi_authentication == Some(false) {
            return Err("GSSAPIAuthentication is disabled".to_string());
        }
        if let Some(methods) = options.preferred_authentications.as_ref() {
            if !methods.iter().any(|method| method == "gssapi-with-mic") {
                return Err(
                    "PreferredAuthentications excludes gssapi-with-mic"
                        .to_string(),
                );
            }
        }

        let username = options
            .user
            .filter(|user| valid_username(user))
            .ok_or_else(|| "requested username is unavailable".to_string())?
            .into_bytes();
        let known_hosts_name = host_trust::lookup_name(
            options.host_key_alias.as_deref(),
            &host,
            options.port.unwrap_or(22),
        );
        let agent_socket = match options.identity_agent.as_deref() {
            Some("none") => None,
            Some("SSH_AUTH_SOCK") | None => {
                env::var_os("SSH_AUTH_SOCK").map(PathBuf::from)
            }
            Some(path) if path.is_empty() => None,
            Some(path) => Some(PathBuf::from(path)),
        };
        let known_hosts_files =
            if let Ok(value) = env::var(SSHKEY_KNOWN_HOSTS_ENV) {
                parse_path_list(&value)?
            } else {
                options
                    .user_known_hosts_files
                    .unwrap_or_default()
                    .into_iter()
                    .chain(options.global_known_hosts_files.unwrap_or_default())
                    .map(PathBuf::from)
                    .collect()
            };

        let acceptor_name = canonical_acceptor_name(service, &host)
            .ok_or_else(|| "resolved acceptor name is invalid".to_string())?;
        Ok(Self {
            host,
            acceptor_name,
            known_hosts_name,
            username,
            agent_socket,
            identity_files: options
                .identity_files
                .into_iter()
                .filter(|path| !path.eq_ignore_ascii_case("none"))
                .map(PathBuf::from)
                .collect(),
            identities_only: options.identities_only.unwrap_or(false),
            accepted_algorithms: options
                .pubkey_accepted_algorithms
                .unwrap_or_else(default_signature_algorithms),
            host_key_algorithms: options
                .host_key_algorithms
                .unwrap_or_else(default_signature_algorithms),
            required_rsa_size: options.required_rsa_size.unwrap_or(
                ssh_config::client::CLIENT_REQUIRED_RSA_SIZE_DEFAULT,
            ),
            known_hosts_files,
            verified_host_key: explicit.verified_host_key,
            verify_host_key_dns: matches!(
                options.verify_host_key_dns,
                Some(VerifyHostKeyDns::Yes)
            ),
        })
    }
}

#[derive(Default)]
struct ClientContextInput {
    user: Option<String>,
    verified_host_key: Option<Vec<u8>>,
}

#[derive(Default)]
struct ServerContextInput {
    peer_address: Option<String>,
}

thread_local! {
    static PENDING_CLIENT_CONTEXT: RefCell<Option<ClientContextInput>> =
        const { RefCell::new(None) };
    static PENDING_SERVER_CONTEXT: RefCell<Option<ServerContextInput>> =
        const { RefCell::new(None) };
}

fn take_client_context() -> ClientContextInput {
    PENDING_CLIENT_CONTEXT
        .with(|pending| pending.borrow_mut().take())
        .unwrap_or_default()
}

fn take_server_context() -> ServerContextInput {
    PENDING_SERVER_CONTEXT
        .with(|pending| pending.borrow_mut().take())
        .unwrap_or_default()
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn parse_path_list(value: &str) -> Result<Vec<PathBuf>, String> {
    let paths: Vec<_> = value.split(':').map(PathBuf::from).collect();
    if paths.is_empty() || paths.iter().any(|path| path.as_os_str().is_empty())
    {
        return Err("path list contains an empty entry".to_string());
    }
    Ok(paths)
}

fn client_config_paths(home: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    if let Ok(value) = env::var(SSHKEY_SSH_CONFIG_ENV) {
        return parse_path_list(&value);
    }

    let mut paths = Vec::new();
    if let Some(home) = home {
        paths.push(home.join(".ssh/config"));
    }
    paths.push(PathBuf::from("/etc/ssh/ssh_config"));
    Ok(paths)
}

fn default_signature_algorithms() -> Vec<String> {
    SIG_ALGS
        .split(|byte| *byte == b',')
        .filter_map(|algorithm| core::str::from_utf8(algorithm).ok())
        .map(ToOwned::to_owned)
        .collect()
}

fn client_defaults(local_user: &str) -> ClientOptions {
    ClientOptions {
        user: Some(local_user.to_string()),
        port: Some(22),
        identity_agent: Some("SSH_AUTH_SOCK".to_string()),
        identity_files: [
            "~/.ssh/id_ed25519",
            "~/.ssh/id_ecdsa",
            "~/.ssh/id_rsa",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect(),
        user_known_hosts_files: Some(vec![
            "~/.ssh/known_hosts".to_string(),
            "~/.ssh/known_hosts2".to_string(),
        ]),
        global_known_hosts_files: Some(vec![
            "/etc/ssh/ssh_known_hosts".to_string(),
            "/etc/ssh/ssh_known_hosts2".to_string(),
        ]),
        pubkey_accepted_algorithms: Some(default_signature_algorithms()),
        host_key_algorithms: Some(default_signature_algorithms()),
        required_rsa_size: Some(
            ssh_config::client::CLIENT_REQUIRED_RSA_SIZE_DEFAULT,
        ),
        ..ClientOptions::default()
    }
}

fn parse_agent_identities(mut payload: &[u8]) -> Option<Vec<AgentIdentity>> {
    if payload.first().copied()? != SSH2_AGENT_IDENTITIES_ANSWER {
        return None;
    }
    payload = &payload[1..];
    let count = read_ssh_u32(&mut payload)?;
    if count > 1024 {
        return None;
    }

    let mut identities = Vec::new();
    for _ in 0..count {
        let key = read_ssh_string(&mut payload)?;
        let _comment = read_ssh_string(&mut payload)?;
        let public_key = PublicKey::from_bytes(&key).ok()?;
        identities.push(AgentIdentity { key, public_key });
    }
    if !payload.is_empty() {
        return None;
    }
    Some(identities)
}

fn agent_request(path: &Path, payload: &[u8]) -> Option<Vec<u8>> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(SSH_AGENT_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(SSH_AGENT_TIMEOUT)).ok()?;

    let len: u32 = payload.len().try_into().ok()?;
    stream.write_all(&len.to_be_bytes()).ok()?;
    stream.write_all(payload).ok()?;

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).ok()?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > SSH_AGENT_MAX_REPLY_LEN {
        return None;
    }
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).ok()?;
    if matches!(
        reply.first().copied(),
        Some(SSH_AGENT_FAILURE | SSH2_AGENT_FAILURE)
    ) {
        return None;
    }
    Some(reply)
}

fn agent_identities(path: &Path) -> Option<Vec<AgentIdentity>> {
    let reply = agent_request(path, &[SSH2_AGENTC_REQUEST_IDENTITIES])?;
    parse_agent_identities(&reply)
}

fn agent_sign(
    path: &Path,
    key: &[u8],
    data: &[u8],
    sigtype: &[u8],
) -> Option<Vec<u8>> {
    let mut request = vec![SSH2_AGENTC_SIGN_REQUEST];
    push_ssh_string(&mut request, key)?;
    push_ssh_string(&mut request, data)?;
    push_ssh_u32(&mut request, agent_signature_flags(sigtype));

    let mut reply = agent_request(path, &request)?;
    if reply.first().copied()? != SSH2_AGENT_SIGN_RESPONSE {
        return None;
    }
    reply = reply.split_off(1);
    let mut body = reply.as_slice();
    let signature = read_ssh_string(&mut body)?;
    if !body.is_empty() {
        return None;
    }
    Some(signature)
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let host = if let Some((_, host)) = host.rsplit_once('@') {
        host
    } else {
        host
    };
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn canonical_acceptor_name(service: &str, host: &str) -> Option<Vec<u8>> {
    let service = service.trim();
    if service.is_empty()
        || service.len() > MAX_NAME_LEN
        || service
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'@')
    {
        return None;
    }
    let host = normalize_host(host)?;
    let name = format!("{service}@{host}").into_bytes();
    (name.len() <= MAX_NAME_LEN).then_some(name)
}

fn canonicalize_acceptor_credential_name(value: &[u8]) -> Result<Vec<u8>, ()> {
    let value = core::str::from_utf8(value).map_err(|_| ())?;
    let (service, host) = value.rsplit_once('@').ok_or(())?;
    canonical_acceptor_name(service, host).ok_or(())
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    match pattern[0] {
        b'*' => {
            wildcard_match(&pattern[1..], value)
                || (!value.is_empty() && wildcard_match(pattern, &value[1..]))
        }
        b'?' => !value.is_empty() && wildcard_match(&pattern[1..], &value[1..]),
        byte => {
            !value.is_empty()
                && byte.eq_ignore_ascii_case(&value[0])
                && wildcard_match(&pattern[1..], &value[1..])
        }
    }
}

unsafe fn target_service_and_host_from_name(
    name: gss_const_name_t,
) -> Option<(String, String)> {
    let (service, name_host) = if name.is_null() {
        ("sshkey".to_string(), None)
    } else {
        let name = &*(name.cast::<SshKeyName>());
        let value = core::str::from_utf8(&name.value).ok()?;
        if let Some((service, host)) = value.rsplit_once('@') {
            if canonical_acceptor_name(service, host).is_none() {
                return None;
            }
            (service.to_string(), Some(host.to_string()))
        } else {
            ("sshkey".to_string(), Some(value.to_string()))
        }
    };
    let host = env::var(SSHKEY_HOST_ENV)
        .ok()
        .or(name_host)
        .and_then(|host| normalize_host(&host))?;
    Some((service, host))
}

fn host_key_is_trusted(
    policy: &ClientPolicy,
    key_blob: &[u8],
    signature_algorithm: &[u8],
) -> bool {
    host_key_meets_policy(
        key_blob,
        signature_algorithm,
        &policy.host_key_algorithms,
        policy.required_rsa_size,
    ) && matches!(
        host_trust::verify(
            host_trust::HostTrustConfig {
                known_hosts_name: &policy.known_hosts_name,
                dns_name: &policy.host,
                known_hosts_files: &policy.known_hosts_files,
                verified_host_key: policy.verified_host_key.as_deref(),
                verify_host_key_dns: policy.verify_host_key_dns,
            },
            key_blob,
        ),
        host_trust::HostTrust::Trusted(_)
    )
}

fn positive_integer_bits(bytes: &[u8]) -> usize {
    let Some((first, rest)) = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|index| (bytes[index], &bytes[index + 1..]))
    else {
        return 0;
    };
    rest.len() * 8 + (8 - first.leading_zeros() as usize)
}

fn host_key_meets_policy(
    key_blob: &[u8],
    signature_algorithm: &[u8],
    allowed_algorithms: &[String],
    required_rsa_size: usize,
) -> bool {
    if !allowed_algorithms
        .iter()
        .any(|algorithm| algorithm.as_bytes() == signature_algorithm)
    {
        return false;
    }
    let Ok(key) = PublicKey::from_bytes(key_blob) else {
        return false;
    };
    key_meets_required_rsa_size(&key, required_rsa_size)
}

fn key_meets_required_rsa_size(
    key: &PublicKey,
    required_rsa_size: usize,
) -> bool {
    key.key_data().rsa().is_none_or(|rsa| {
        rsa.n
            .as_positive_bytes()
            .is_some_and(|n| positive_integer_bits(n) >= required_rsa_size)
    })
}

struct LocalAccount {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home: PathBuf,
}

fn local_account(username: &str) -> Option<LocalAccount> {
    let username = CString::new(username).ok()?;
    let mut pwd = core::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    let status = unsafe {
        libc::getpwnam_r(
            username.as_ptr(),
            pwd.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() {
        return None;
    }
    let pwd = unsafe { pwd.assume_init() };
    if pwd.pw_dir.is_null() {
        return None;
    }
    let home = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    Some(LocalAccount {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(std::ffi::OsStr::from_bytes(home)),
    })
}

fn local_account_groups(
    username: &str,
    account: &LocalAccount,
) -> Option<Vec<String>> {
    const INITIAL_GROUPS: usize = 16;
    const MAX_GROUPS: usize = 65_536;

    let username = CString::new(username).ok()?;
    let mut group_count = INITIAL_GROUPS as libc::c_int;
    let gids = loop {
        let count = usize::try_from(group_count).ok()?;
        if count == 0 || count > MAX_GROUPS {
            return None;
        }
        let mut gids = vec![account.gid; count];
        let mut required = group_count;
        let status = unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                account.gid,
                gids.as_mut_ptr(),
                &mut required,
            )
        };
        if status >= 0 {
            let required = usize::try_from(required).ok()?;
            if required > gids.len() {
                return None;
            }
            gids.truncate(required);
            break gids;
        }
        if required <= group_count {
            return None;
        }
        group_count = required;
    };

    let mut groups = Vec::new();
    for gid in gids {
        let Some(name) = group_name(gid) else {
            continue;
        };
        if !groups.iter().any(|existing| existing == &name) {
            groups.push(name);
        }
    }
    (!groups.is_empty()).then_some(groups)
}

fn group_name(gid: libc::gid_t) -> Option<String> {
    const INITIAL_BUFFER: usize = 1024;
    const MAX_BUFFER: usize = 1024 * 1024;

    let mut buffer_len = INITIAL_BUFFER;
    loop {
        let mut group = core::mem::MaybeUninit::<libc::group>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0u8; buffer_len];
        let status = unsafe {
            libc::getgrgid_r(
                gid,
                group.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_len < MAX_BUFFER {
            buffer_len = (buffer_len * 2).min(MAX_BUFFER);
            continue;
        }
        if status != 0 || result.is_null() {
            return None;
        }
        let group = unsafe { group.assume_init() };
        if group.gr_name.is_null() {
            return None;
        }
        return unsafe { CStr::from_ptr(group.gr_name) }
            .to_str()
            .ok()
            .map(ToOwned::to_owned);
    }
}

fn server_defaults() -> ServerOptions {
    ServerOptions {
        strict_modes: Some(true),
        permit_root_login: Some(PermitRootLogin::ProhibitPassword),
        authorized_keys_files: Some(vec![
            ".ssh/authorized_keys".to_string(),
            ".ssh/authorized_keys2".to_string(),
        ]),
        pubkey_accepted_algorithms: Some(default_signature_algorithms()),
        required_rsa_size: Some(ssh_config::server::REQUIRED_RSA_SIZE_DEFAULT),
        ..ServerOptions::default()
    }
}

fn server_options(
    username: &str,
    account: &LocalAccount,
    peer: Option<&str>,
) -> Result<ServerOptions, String> {
    let config = if let Some(path) = env::var_os(SSHKEY_SSHD_CONFIG_ENV) {
        ServerConfig::parse_file(Path::new(&path))
            .map_err(|error| format!("cannot read sshd_config: {error}"))?
    } else {
        let path = Path::new("/etc/ssh/sshd_config");
        if path.exists() {
            ServerConfig::parse_file(path)
                .map_err(|error| format!("cannot read sshd_config: {error}"))?
        } else {
            ServerConfig::parse_str("")
        }
    };
    let groups = local_account_groups(username, account);
    resolve_server_options(&config, username, account, groups.as_deref(), peer)
}

fn resolve_server_options(
    config: &ServerConfig,
    username: &str,
    account: &LocalAccount,
    groups: Option<&[String]>,
    peer: Option<&str>,
) -> Result<ServerOptions, String> {
    if let Some(error) = config.first_error() {
        return Err(error.to_string());
    }

    let options = config.resolve(
        ServerResolveContext {
            user: Some(username),
            groups,
            host: None,
            address: peer,
            local_address: None,
            local_port: None,
            rdomain: None,
            invalid_user: false,
        },
        &server_defaults(),
    );
    if let Some(error) = options.config_error.as_ref() {
        return Err(error.clone());
    }
    if options.gssapi_authentication == Some(false) {
        return Err("GSSAPIAuthentication is disabled".to_string());
    }
    if account.uid == 0
        && matches!(
            options.permit_root_login,
            Some(PermitRootLogin::No | PermitRootLogin::ForcedCommandsOnly)
        )
    {
        return Err("root login is disabled".to_string());
    }
    let mut unresolved_deny = false;
    for pattern in &options.deny_users {
        match account_pattern_match(pattern, username, peer) {
            AccountPatternMatch::Yes => {
                return Err("user is denied".to_string())
            }
            AccountPatternMatch::Unresolved => unresolved_deny = true,
            AccountPatternMatch::No => {}
        }
    }
    if unresolved_deny {
        return Err(
            "DenyUsers requires unavailable client source context".to_string()
        );
    }
    if !options.allow_users.is_empty() {
        let mut matched = false;
        let mut unresolved = false;
        for pattern in &options.allow_users {
            match account_pattern_match(pattern, username, peer) {
                AccountPatternMatch::Yes => matched = true,
                AccountPatternMatch::Unresolved => unresolved = true,
                AccountPatternMatch::No => {}
            }
        }
        if !matched {
            if unresolved {
                return Err(
                    "AllowUsers requires unavailable client source context"
                        .to_string(),
                );
            }
            return Err("user is not allowed".to_string());
        }
    }
    match options.group_policy_allows(groups) {
        Some(true) => {}
        Some(false) => return Err("user is denied by group policy".to_string()),
        None => {
            return Err("group membership required by server policy".to_string())
        }
    }
    Ok(options)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountPatternMatch {
    No,
    Yes,
    Unresolved,
}

fn account_pattern_match(
    pattern: &str,
    username: &str,
    peer: Option<&str>,
) -> AccountPatternMatch {
    let Some((user_pattern, host_pattern)) = pattern.split_once('@') else {
        return if wildcard_match(pattern.as_bytes(), username.as_bytes()) {
            AccountPatternMatch::Yes
        } else {
            AccountPatternMatch::No
        };
    };
    if !wildcard_match(user_pattern.as_bytes(), username.as_bytes()) {
        return AccountPatternMatch::No;
    }
    source_pattern_match(host_pattern, peer)
}

fn source_pattern_match(
    patterns: &str,
    peer: Option<&str>,
) -> AccountPatternMatch {
    let mut matched = false;
    let mut positive_unresolved = false;
    let mut negative_unresolved = false;
    for item in patterns.split(',').filter(|item| !item.is_empty()) {
        let (negated, pattern) = item
            .strip_prefix('!')
            .map(|pattern| (true, pattern))
            .unwrap_or((false, item));
        let result =
            if peer.is_some_and(|peer| source_pattern_matches(pattern, peer)) {
                AccountPatternMatch::Yes
            } else if peer.is_none() || !source_pattern_is_numeric(pattern) {
                AccountPatternMatch::Unresolved
            } else {
                AccountPatternMatch::No
            };
        match (negated, result) {
            (true, AccountPatternMatch::Yes) => return AccountPatternMatch::No,
            (true, AccountPatternMatch::Unresolved) => {
                negative_unresolved = true
            }
            (false, AccountPatternMatch::Yes) => matched = true,
            (false, AccountPatternMatch::Unresolved) => {
                positive_unresolved = true
            }
            (_, AccountPatternMatch::No) => {}
        }
    }
    if negative_unresolved {
        AccountPatternMatch::Unresolved
    } else if matched {
        AccountPatternMatch::Yes
    } else if positive_unresolved {
        AccountPatternMatch::Unresolved
    } else {
        AccountPatternMatch::No
    }
}

fn source_pattern_is_numeric(pattern: &str) -> bool {
    if pattern.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((network, prefix)) = pattern.split_once('/') {
        let Ok(network) = network.parse::<std::net::IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix.parse::<u8>() else {
            return false;
        };
        return match network {
            std::net::IpAddr::V4(_) => prefix <= 32,
            std::net::IpAddr::V6(_) => prefix <= 128,
        };
    }
    let has_wildcard = pattern.contains(['*', '?']);
    if has_wildcard && pattern.contains('.') {
        return pattern.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'.' | b'*' | b'?')
        });
    }
    has_wildcard
        && pattern.contains(':')
        && pattern.bytes().all(|byte| {
            byte.is_ascii_hexdigit() || matches!(byte, b':' | b'*' | b'?')
        })
}

fn authorized_keys_paths(
    username: &str,
    account: &LocalAccount,
    options: &ServerOptions,
) -> Result<Vec<PathBuf>, String> {
    let templates = if let Ok(value) = env::var(SSHKEY_AUTHORIZED_KEYS_ENV) {
        return parse_path_list(&value);
    } else {
        options.authorized_keys_files.clone().unwrap_or_default()
    };
    Ok(templates
        .into_iter()
        .filter(|path| !path.eq_ignore_ascii_case("none"))
        .map(|path| {
            let path = path
                .replace("%%", "\0")
                .replace("%u", username)
                .replace("%h", account.home.to_string_lossy().as_ref())
                .replace('\0', "%");
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                account.home.join(path)
            }
        })
        .collect())
}

fn safe_authorization_path(
    path: &Path,
    metadata: &fs::Metadata,
    account: &LocalAccount,
) -> bool {
    if (metadata.uid() != 0 && metadata.uid() != account.uid)
        || metadata.permissions().mode() & 0o022 != 0
    {
        return false;
    }

    let Ok(canonical_path) = fs::canonicalize(path) else {
        return false;
    };
    let canonical_home = fs::canonicalize(&account.home).ok();
    let Some(mut directory) = canonical_path.parent() else {
        return false;
    };

    loop {
        let Ok(metadata) = fs::metadata(directory) else {
            return false;
        };
        if (metadata.uid() != 0 && metadata.uid() != account.uid)
            || metadata.permissions().mode() & 0o022 != 0
        {
            return false;
        }
        if canonical_home.as_deref() == Some(directory)
            || directory == Path::new("/")
            || directory == Path::new(".")
        {
            return true;
        }
        let Some(parent) = directory.parent() else {
            return false;
        };
        directory = parent;
    }
}

fn open_authorization_file(
    path: &Path,
    account: &LocalAccount,
    strict_modes: bool,
) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }

    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags >= 0 {
        unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            );
        }
    }

    if strict_modes && !safe_authorization_path(path, &metadata, account) {
        return None;
    }
    Some(file)
}

fn authorized_key_public_key(entry: &AuthorizedKeyEntry) -> Option<PublicKey> {
    PublicKey::from_openssh(&format!("{} {}", entry.key_type, entry.key_data))
        .ok()
}

fn authorized_key_options_allow(entry: &AuthorizedKeyEntry, now: u64) -> bool {
    entry.options.iter().all(|option| match option {
        AuthorizedKeyOption::ExpiryTime(valid_before) => *valid_before >= now,
        AuthorizedKeyOption::Other { .. } => false,
    })
}

fn source_pattern_matches(pattern: &str, peer: &str) -> bool {
    if let Some((network, prefix)) = pattern.split_once('/') {
        return cidr_matches(network, prefix, peer);
    }
    wildcard_match(pattern.as_bytes(), peer.as_bytes())
}

fn cidr_matches(network: &str, prefix: &str, peer: &str) -> bool {
    let Ok(network) = network.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(peer) = peer.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match (network, peer) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(peer))
            if prefix <= 32 =>
        {
            let mask = u32::MAX.checked_shl((32 - prefix) as u32).unwrap_or(0);
            u32::from(network) & mask == u32::from(peer) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(peer))
            if prefix <= 128 =>
        {
            let mask =
                u128::MAX.checked_shl((128 - prefix) as u32).unwrap_or(0);
            u128::from(network) & mask == u128::from(peer) & mask
        }
        _ => false,
    }
}

fn key_is_revoked(path: &Path, key_blob: &[u8]) -> Result<bool, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read revoked keys: {error}"))?;
    if bytes.starts_with(b"SSHKRL\n") {
        return Err("KRL revocation is not supported".to_string());
    }
    let text = core::str::from_utf8(&bytes)
        .map_err(|_| "revoked keys file is not UTF-8".to_string())?;
    Ok(text.lines().any(|line| {
        parse_authorized_key_line(line)
            .ok()
            .flatten()
            .and_then(|entry| authorized_key_public_key(&entry))
            .and_then(|key| key.to_bytes().ok())
            .is_some_and(|candidate| candidate == key_blob)
    }))
}

fn authorize_user_key(
    username: &[u8],
    key_blob: &[u8],
    signature_algorithm: &[u8],
    peer: Option<&str>,
) -> Result<(), String> {
    let username = core::str::from_utf8(username)
        .ok()
        .filter(|username| valid_username(username))
        .ok_or_else(|| "invalid requested username".to_string())?;
    let account = local_account(username)
        .ok_or_else(|| "requested account does not exist".to_string())?;
    let options = server_options(username, &account, peer)?;
    validate_user_key_policy(key_blob, signature_algorithm, &options)?;
    if let Some(path) = options.revoked_keys_file.as_deref() {
        if !path.eq_ignore_ascii_case("none")
            && key_is_revoked(Path::new(path), key_blob)?
        {
            return Err("user key is revoked".to_string());
        }
    }
    let now = unix_time_seconds()
        .ok_or_else(|| "cannot determine authorization time".to_string())?;

    for path in authorized_keys_paths(username, &account, &options)? {
        let Some(mut file) = open_authorization_file(
            &path,
            &account,
            options.strict_modes.unwrap_or(true),
        ) else {
            continue;
        };
        let mut text = String::new();
        if file.read_to_string(&mut text).is_err() {
            continue;
        }
        for line in text.lines() {
            let Ok(Some(entry)) = parse_authorized_key_line(line) else {
                continue;
            };
            let Some(key) = authorized_key_public_key(&entry) else {
                continue;
            };
            let Ok(candidate) = key.to_bytes() else {
                continue;
            };
            if candidate == key_blob
                && authorized_key_options_allow(&entry, now)
            {
                return Ok(());
            }
        }
    }
    Err("user key is not authorized".to_string())
}

fn validate_user_key_policy(
    key_blob: &[u8],
    signature_algorithm: &[u8],
    options: &ServerOptions,
) -> Result<(), String> {
    if !options
        .pubkey_accepted_algorithms
        .as_ref()
        .is_some_and(|algorithms| {
            algorithms
                .iter()
                .any(|algorithm| algorithm.as_bytes() == signature_algorithm)
        })
    {
        return Err("user signature algorithm is disabled".to_string());
    }
    let key = PublicKey::from_bytes(key_blob)
        .map_err(|_| "user public key is invalid".to_string())?;
    if !key_meets_required_rsa_size(
        &key,
        options
            .required_rsa_size
            .unwrap_or(ssh_config::server::REQUIRED_RSA_SIZE_DEFAULT),
    ) {
        return Err("user RSA key is smaller than RequiredRSASize".to_string());
    }
    Ok(())
}

fn alg_list_contains(list: &[u8], alg: &[u8]) -> bool {
    list.split(|byte| *byte == b',').any(|item| item == alg)
}

fn host_signature_input(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_ssh_string(&mut out, HOSTAUTH_TRANSCRIPT_LABEL)?;
    push_ssh_string(&mut out, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut out, KEX_ALG)?;
    push_ssh_string(&mut out, ENC_ALG)?;
    push_ssh_string(&mut out, initiator_sigtypes)?;
    push_ssh_string(&mut out, acceptor_sigtypes)?;
    push_ssh_string(&mut out, initiator_public)?;
    push_ssh_string(&mut out, acceptor_public)?;
    push_ssh_string(&mut out, initiator_nonce)?;
    push_ssh_string(&mut out, acceptor_nonce)?;
    push_ssh_string(&mut out, acceptor_name)?;
    push_ssh_string(&mut out, channel_bindings)?;
    Some(out)
}

fn host_challenge_signature_input(
    acceptor_sigtypes: &[u8],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_ssh_string(&mut out, HOSTCHALLENGE_TRANSCRIPT_LABEL)?;
    push_ssh_string(&mut out, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut out, KEX_ALG)?;
    push_ssh_string(&mut out, ENC_ALG)?;
    push_ssh_string(&mut out, acceptor_sigtypes)?;
    push_ssh_string(&mut out, acceptor_public)?;
    push_ssh_string(&mut out, acceptor_nonce)?;
    push_ssh_string(&mut out, acceptor_name)?;
    push_ssh_string(&mut out, channel_bindings)?;
    Some(out)
}

fn user_signature_input(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    username: &[u8],
    keytype: &[u8],
    key: &[u8],
    sigtype: &[u8],
    channel_bindings: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_ssh_string(&mut out, USERAUTH_TRANSCRIPT_LABEL)?;
    push_ssh_string(&mut out, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut out, KEX_ALG)?;
    push_ssh_string(&mut out, ENC_ALG)?;
    push_ssh_string(&mut out, initiator_sigtypes)?;
    push_ssh_string(&mut out, acceptor_sigtypes)?;
    push_ssh_string(&mut out, initiator_public)?;
    push_ssh_string(&mut out, acceptor_public)?;
    push_ssh_string(&mut out, initiator_nonce)?;
    push_ssh_string(&mut out, acceptor_nonce)?;
    push_ssh_string(&mut out, acceptor_name)?;
    push_ssh_string(&mut out, username)?;
    push_ssh_string(&mut out, keytype)?;
    push_ssh_string(&mut out, key)?;
    push_ssh_string(&mut out, sigtype)?;
    push_ssh_string(&mut out, channel_bindings)?;
    Some(out)
}

fn handshake_transcript_hash(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
) -> Option<[u8; 32]> {
    let mut input = Vec::new();
    push_ssh_string(&mut input, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut input, KEX_ALG)?;
    push_ssh_string(&mut input, ENC_ALG)?;
    push_ssh_string(&mut input, initiator_sigtypes)?;
    push_ssh_string(&mut input, acceptor_sigtypes)?;
    push_ssh_string(&mut input, initiator_public)?;
    push_ssh_string(&mut input, acceptor_public)?;
    push_ssh_string(&mut input, initiator_nonce)?;
    push_ssh_string(&mut input, acceptor_nonce)?;
    push_ssh_string(&mut input, acceptor_name)?;
    push_ssh_string(&mut input, channel_bindings)?;
    Some(Sha256::digest(input).into())
}

fn userauth_retry_transcript_hash(
    handshake_hash: &[u8; 32],
    rejected_userauth: &[u8],
    server_context: &[u8],
) -> Option<[u8; 32]> {
    let mut input = Vec::new();
    push_ssh_string(&mut input, USERAUTH_RETRY_TRANSCRIPT_LABEL)?;
    push_ssh_string(&mut input, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut input, handshake_hash)?;
    push_ssh_string(&mut input, rejected_userauth)?;
    push_ssh_string(&mut input, server_context)?;
    Some(Sha256::digest(input).into())
}

unsafe fn finished_mac(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    label: &[u8],
    transcript_hash: &[u8; 32],
    peer_nonce: &[u8],
) -> Option<Vec<u8>> {
    let finished_key = hmac_sha256(session_key, FINISHED_KEY_LABEL)?;
    let mut input = Vec::new();
    push_ssh_string(&mut input, label)?;
    push_ssh_string(&mut input, transcript_hash)?;
    push_ssh_string(&mut input, peer_nonce)?;
    Some(hmac_sha256(&finished_key, &input)?.to_vec())
}

unsafe fn make_finished(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    label: &[u8],
    transcript_hash: &[u8; 32],
    peer_nonce: &[u8],
) -> Option<SshKeyFinished> {
    let mac = finished_mac(session_key, label, transcript_hash, peer_nonce)?;
    Some(SshKeyFinished::new(OctetString::from(mac)))
}

unsafe fn verify_finished(
    finished: &SshKeyFinished,
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    label: &[u8],
    transcript_hash: &[u8; 32],
    peer_nonce: &[u8],
) -> bool {
    let Some(expected) =
        finished_mac(session_key, label, transcript_hash, peer_nonce)
    else {
        return false;
    };
    finished.mac.as_ref() == expected.as_slice()
}

fn read_private_key_from_env(name: &str) -> Option<PrivateKey> {
    let path = env::var_os(name)?;
    let bytes = fs::read(path).ok()?;
    PrivateKey::from_openssh(bytes).ok()
}

fn sign_ssh_data(
    private_key: &PrivateKey,
    data: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    if !direct_private_key_signing_supported(&private_key.algorithm()) {
        return None;
    }
    let signature: SshSignature = Signer::try_sign(private_key, data).ok()?;
    let sigtype = signature.algorithm().as_str().as_bytes().to_vec();
    let public_key = private_key.public_key();
    let keytype = public_key.algorithm().as_str().as_bytes().to_vec();
    let key = public_key.to_bytes().ok()?;
    let sig = Vec::<u8>::try_from(signature).ok()?;
    Some((keytype, key, sigtype, sig))
}

fn direct_private_key_signing_supported(algorithm: &Algorithm) -> bool {
    !matches!(algorithm, Algorithm::Rsa { .. })
}

fn verify_ssh_signature(
    key: &[u8],
    sigtype: &[u8],
    sig: &[u8],
    data: &[u8],
) -> bool {
    let Ok(public_key) = PublicKey::from_bytes(key) else {
        return false;
    };
    let Ok(signature) = SshSignature::try_from(sig) else {
        return false;
    };
    if signature.algorithm().as_str().as_bytes() != sigtype {
        return false;
    }
    Verifier::verify(&public_key, data, &signature).is_ok()
}

fn parse_hex_context_key(value: &str) -> Option<[u8; CONTEXT_KEY_LEN]> {
    let value = value.trim();
    if value.len() != CONTEXT_KEY_LEN * 2 {
        return None;
    }

    let mut key = [0u8; CONTEXT_KEY_LEN];
    for (idx, byte) in key.iter_mut().enumerate() {
        let start = idx * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16).ok()?;
    }
    Some(key)
}

fn fill_random(bytes: &mut [u8]) -> bool {
    let Ok(mut file) = fs::File::open("/dev/urandom") else {
        return false;
    };
    file.read_exact(bytes).is_ok()
}

fn server_context_key() -> Option<[u8; CONTEXT_KEY_LEN]> {
    static KEY: OnceLock<Option<[u8; CONTEXT_KEY_LEN]>> = OnceLock::new();

    *KEY.get_or_init(|| {
        if let Ok(value) = env::var(SSHKEY_CTX_KEY_ENV) {
            return parse_hex_context_key(&value);
        }

        let mut key = [0u8; CONTEXT_KEY_LEN];
        if !fill_random(&mut key) {
            return None;
        }
        Some(key)
    })
}

unsafe fn derive_context_key(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    label: &[u8],
) -> Option<[u8; CONTEXT_KEY_LEN]> {
    hmac_sha256(session_key, label)
}

unsafe fn private_seal_key(
    key: &[u8; CONTEXT_KEY_LEN],
    label: &[u8],
) -> Option<[u8; PRIVATE_SEAL_KEY_LEN]> {
    let digest = hmac_sha256(key, label)?;
    let mut out = [0u8; PRIVATE_SEAL_KEY_LEN];
    out.copy_from_slice(&digest[..PRIVATE_SEAL_KEY_LEN]);
    Some(out)
}

unsafe fn seal_private(
    key: &[u8; CONTEXT_KEY_LEN],
    label: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let profile =
        Aes128CtsHmacSha256128Profile::new(private_seal_key(key, label)?);
    profile.seal(Role::Initiator, 0, label, plaintext).ok()
}

unsafe fn open_private(
    key: &[u8; CONTEXT_KEY_LEN],
    label: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let profile =
        Aes128CtsHmacSha256128Profile::new(private_seal_key(key, label)?);
    profile.open(Role::Initiator, 0, label, ciphertext).ok()
}

unsafe fn seal_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_context_key(session_key, USERAUTH_LABEL)?;
    seal_private(&key, USERAUTH_LABEL, plaintext)
}

unsafe fn open_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_context_key(session_key, USERAUTH_LABEL)?;
    open_private(&key, USERAUTH_LABEL, ciphertext)
}

unsafe fn seal_server_context(
    context: &SshKeyServerContext,
) -> Option<Vec<u8>> {
    let now = unix_time_seconds()?;
    if !validate_server_context_fields(context)
        || !server_context_is_current(context, now)
    {
        return None;
    }
    let plaintext = rasn::der::encode(context).ok()?;
    let key = server_context_key()?;
    seal_private(&key, SERVER_CONTEXT_LABEL, &plaintext)
}

unsafe fn open_server_context(
    ciphertext: &[u8],
) -> Option<SshKeyServerContext> {
    if ciphertext.len() > MAX_ENCRYPTED_FIELD_LEN {
        return None;
    }
    let key = server_context_key()?;
    let plaintext = open_private(&key, SERVER_CONTEXT_LABEL, ciphertext)?;
    let context = rasn::der::decode::<SshKeyServerContext>(&plaintext).ok()?;
    let now = unix_time_seconds()?;
    (validate_server_context_fields(&context)
        && server_context_is_current(&context, now))
    .then_some(context)
}

fn unix_time_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn server_context_issued_at(now: u64) -> Integer {
    Integer::from(now)
}

fn server_context_is_current(context: &SshKeyServerContext, now: u64) -> bool {
    let Ok(issued_at) = u64::try_from(&context.issued_at) else {
        return false;
    };
    let Some(server_deadline) =
        issued_at.checked_add(SERVER_CONTEXT_MAX_AGE_SECONDS)
    else {
        return false;
    };

    issued_at <= now.saturating_add(SERVER_CONTEXT_CLOCK_SKEW_SECONDS)
        && now < server_deadline
}

fn append_userauth_candidates(
    candidates: &mut Vec<UserAuthCandidate>,
    public_key: &PublicKey,
    key: &[u8],
    signer: UserAuthSigner,
    policy: &ClientPolicy,
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
) {
    if !key_meets_required_rsa_size(public_key, policy.required_rsa_size) {
        return;
    }
    let supported = signature_algorithms(&public_key.algorithm());
    let keytype = public_key.algorithm().as_str().as_bytes().to_vec();
    for configured in &policy.accepted_algorithms {
        let sigtype = configured.as_bytes();
        if !supported.iter().any(|candidate| candidate == sigtype)
            || !alg_list_contains(initiator_sigtypes, sigtype)
            || !alg_list_contains(acceptor_sigtypes, sigtype)
            || candidates.iter().any(|candidate| {
                candidate.key == key && candidate.sigtype == sigtype
            })
        {
            continue;
        }
        candidates.push(UserAuthCandidate {
            keytype: keytype.clone(),
            key: key.to_vec(),
            sigtype: sigtype.to_vec(),
            signer: signer.clone(),
        });
    }
}

fn userauth_candidates(
    policy: &ClientPolicy,
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
) -> Vec<UserAuthCandidate> {
    struct ConfiguredIdentity {
        path: PathBuf,
        public_key: PublicKey,
        key: Vec<u8>,
        agent_backed: bool,
    }

    let mut configured: Vec<ConfiguredIdentity> = policy
        .identity_files
        .iter()
        .filter_map(|path| {
            let public_key = identity_public_key(path)?;
            let key = public_key.to_bytes().ok()?;
            Some(ConfiguredIdentity {
                path: path.clone(),
                public_key,
                key,
                agent_backed: false,
            })
        })
        .collect();
    let agents = policy
        .agent_socket
        .as_deref()
        .and_then(agent_identities)
        .unwrap_or_default();
    let mut configured_agents = Vec::new();
    let mut other_agents = Vec::new();

    if let Some(socket) = policy.agent_socket.as_ref() {
        for identity in agents {
            if let Some(configured) = configured.iter_mut().find(|configured| {
                !configured.agent_backed && configured.key == identity.key
            }) {
                configured.agent_backed = true;
                append_userauth_candidates(
                    &mut configured_agents,
                    &identity.public_key,
                    &identity.key,
                    UserAuthSigner::Agent(socket.clone()),
                    policy,
                    initiator_sigtypes,
                    acceptor_sigtypes,
                );
            } else if !policy.identities_only {
                append_userauth_candidates(
                    &mut other_agents,
                    &identity.public_key,
                    &identity.key,
                    UserAuthSigner::Agent(socket.clone()),
                    policy,
                    initiator_sigtypes,
                    acceptor_sigtypes,
                );
            }
        }
    }

    for candidate in other_agents {
        if !configured_agents.iter().any(|existing| {
            existing.key == candidate.key
                && existing.sigtype == candidate.sigtype
        }) {
            configured_agents.push(candidate);
        }
    }
    for identity in configured {
        if identity.agent_backed {
            continue;
        }
        let Some(private_key) = read_private_key(&identity.path) else {
            continue;
        };
        if !direct_private_key_signing_supported(&private_key.algorithm()) {
            continue;
        }
        append_userauth_candidates(
            &mut configured_agents,
            &identity.public_key,
            &identity.key,
            UserAuthSigner::IdentityFile(identity.path),
            policy,
            initiator_sigtypes,
            acceptor_sigtypes,
        );
    }
    configured_agents
}

unsafe fn encrypted_userauth_for_candidate(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    candidate: &UserAuthCandidate,
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
    policy: &ClientPolicy,
) -> Option<EncSshKeyUserAuth> {
    let input = user_signature_input(
        initiator_sigtypes,
        acceptor_sigtypes,
        initiator_public,
        acceptor_public,
        initiator_nonce,
        acceptor_nonce,
        acceptor_name,
        &policy.username,
        &candidate.keytype,
        &candidate.key,
        &candidate.sigtype,
        channel_bindings,
    )?;
    let sig = match &candidate.signer {
        UserAuthSigner::Agent(socket) => {
            agent_sign(socket, &candidate.key, &input, &candidate.sigtype)?
        }
        UserAuthSigner::IdentityFile(path) => {
            let private_key = read_private_key(path)?;
            let (keytype, key, sigtype, sig) =
                sign_ssh_data(&private_key, &input)?;
            if keytype != candidate.keytype
                || key != candidate.key
                || sigtype != candidate.sigtype
            {
                return None;
            }
            sig
        }
    };
    let signature = SshSignature::try_from(sig.as_slice()).ok()?;
    if signature.algorithm().as_str().as_bytes() != candidate.sigtype
        || !verify_ssh_signature(
            &candidate.key,
            &candidate.sigtype,
            &sig,
            &input,
        )
    {
        return None;
    }
    encrypt_userauth(
        session_key,
        &policy.username,
        &candidate.keytype,
        &candidate.key,
        &candidate.sigtype,
        &sig,
    )
}

unsafe fn next_encrypted_userauth(
    candidates: &[UserAuthCandidate],
    start: usize,
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
    policy: &ClientPolicy,
) -> Option<(usize, EncSshKeyUserAuth)> {
    candidates
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, candidate)| {
            encrypted_userauth_for_candidate(
                session_key,
                candidate,
                initiator_sigtypes,
                acceptor_sigtypes,
                initiator_public,
                acceptor_public,
                initiator_nonce,
                acceptor_nonce,
                acceptor_name,
                channel_bindings,
                policy,
            )
            .map(|userauth| (index, userauth))
        })
}

fn identity_public_key(path: &Path) -> Option<PublicKey> {
    if let Some(private_key) = read_private_key(path) {
        return Some(private_key.public_key().clone());
    }
    let text = fs::read_to_string(path.with_extension("pub")).ok()?;
    PublicKey::from_openssh(text.trim()).ok()
}

fn read_private_key(path: &Path) -> Option<PrivateKey> {
    PrivateKey::from_openssh(fs::read(path).ok()?).ok()
}

unsafe fn encrypt_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    username: &[u8],
    keytype: &[u8],
    key: &[u8],
    sigtype: &[u8],
    sig: &[u8],
) -> Option<EncSshKeyUserAuth> {
    let userauth = SshKeyUserAuth::new(
        OctetString::from(username),
        OctetString::from(keytype),
        OctetString::from(key),
        OctetString::from(sigtype),
        OctetString::from(sig),
    );
    let plaintext = rasn::der::encode(&userauth).ok()?;
    let ciphertext = seal_userauth(session_key, &plaintext)?;
    Some(EncSshKeyUserAuth(OctetString::from(ciphertext)))
}

fn hostauth_token(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
) -> Option<SshKeyHostAuth> {
    let private_key = read_private_key_from_env(SSHKEY_HOST_KEY_ENV)?;
    if !direct_private_key_signing_supported(&private_key.algorithm()) {
        return None;
    }
    let input = host_signature_input(
        initiator_sigtypes,
        acceptor_sigtypes,
        initiator_public,
        acceptor_public,
        initiator_nonce,
        acceptor_nonce,
        acceptor_name,
        channel_bindings,
    )?;
    let (keytype, key, sigtype, sig) = sign_ssh_data(&private_key, &input)?;
    Some(SshKeyHostAuth::new(
        OctetString::from(keytype),
        OctetString::from(key),
        OctetString::from(sigtype),
        OctetString::from(sig),
    ))
}

fn host_challenge_auth_token(
    acceptor_sigtypes: &[u8],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_nonce: &[u8],
    acceptor_name: &[u8],
    channel_bindings: &[u8],
) -> Option<SshKeyHostAuth> {
    let private_key = read_private_key_from_env(SSHKEY_HOST_KEY_ENV)?;
    if !direct_private_key_signing_supported(&private_key.algorithm()) {
        return None;
    }
    let input = host_challenge_signature_input(
        acceptor_sigtypes,
        acceptor_public,
        acceptor_nonce,
        acceptor_name,
        channel_bindings,
    )?;
    let (keytype, key, sigtype, sig) = sign_ssh_data(&private_key, &input)?;
    Some(SshKeyHostAuth::new(
        OctetString::from(keytype),
        OctetString::from(key),
        OctetString::from(sigtype),
        OctetString::from(sig),
    ))
}

unsafe fn decrypt_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    ciphertext: &EncSshKeyUserAuth,
) -> Option<SshKeyUserAuth> {
    if ciphertext.0.len() > MAX_ENCRYPTED_FIELD_LEN {
        return None;
    }
    let plaintext = open_userauth(session_key, ciphertext.0.as_ref())?;
    let userauth = rasn::der::decode::<SshKeyUserAuth>(&plaintext).ok()?;
    validate_userauth_fields(&userauth).then_some(userauth)
}

unsafe fn generate_x25519_keypair(
) -> Option<(OpenSslPkey, [u8; X25519_PUBLIC_LEN])> {
    let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, ptr::null_mut());
    if ctx.is_null() {
        return None;
    }

    let mut pkey = ptr::null_mut();
    let ok =
        EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &mut pkey) == 1;
    EVP_PKEY_CTX_free(ctx);
    if !ok || pkey.is_null() {
        if !pkey.is_null() {
            EVP_PKEY_free(pkey);
        }
        return None;
    }

    let key = OpenSslPkey { ptr: pkey };
    let mut public = [0u8; X25519_PUBLIC_LEN];
    let mut public_len = public.len();
    if EVP_PKEY_get_raw_public_key(
        key.ptr,
        public.as_mut_ptr(),
        &mut public_len,
    ) != 1
        || public_len != public.len()
    {
        drop(key);
        return None;
    }

    Some((key, public))
}

unsafe fn x25519_private_key(
    key: &OpenSslPkey,
) -> Option<[u8; X25519_SHARED_LEN]> {
    let mut private = [0u8; X25519_SHARED_LEN];
    let mut private_len = private.len();
    if EVP_PKEY_get_raw_private_key(
        key.ptr,
        private.as_mut_ptr(),
        &mut private_len,
    ) != 1
        || private_len != private.len()
    {
        return None;
    }

    Some(private)
}

unsafe fn x25519_key_from_private(
    private: &[u8; X25519_SHARED_LEN],
) -> Option<OpenSslPkey> {
    let ptr = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519,
        ptr::null_mut(),
        private.as_ptr(),
        private.len(),
    );
    if ptr.is_null() {
        return None;
    }
    Some(OpenSslPkey { ptr })
}

unsafe fn x25519_shared_secret(
    private_key: &OpenSslPkey,
    peer_public: &[u8; X25519_PUBLIC_LEN],
) -> Option<Zeroizing<[u8; X25519_SHARED_LEN]>> {
    let peer = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        ptr::null_mut(),
        peer_public.as_ptr(),
        peer_public.len(),
    );
    if peer.is_null() {
        return None;
    }

    let ctx = EVP_PKEY_CTX_new(private_key.ptr, ptr::null_mut());
    if ctx.is_null() {
        EVP_PKEY_free(peer);
        return None;
    }

    let mut shared = Zeroizing::new([0u8; X25519_SHARED_LEN]);
    let mut shared_len = shared.len();
    let ok = EVP_PKEY_derive_init(ctx) == 1
        && EVP_PKEY_derive_set_peer(ctx, peer) == 1
        && EVP_PKEY_derive(ctx, shared.as_mut_ptr(), &mut shared_len) == 1
        && shared_len == shared.len();

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);

    ok.then_some(shared)
}

unsafe fn derive_anonymous_session_key(
    shared: &[u8; X25519_SHARED_LEN],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    flags: OM_uint32,
    channel_binding_application_data: &[u8],
) -> Option<Zeroizing<[u8; SANON_SESSION_KEY_LEN]>> {
    let mut context = Vec::with_capacity(
        (2 * X25519_PUBLIC_LEN) + 8 + channel_binding_application_data.len(),
    );
    context.extend_from_slice(initiator_public);
    context.extend_from_slice(acceptor_public);
    context.extend_from_slice(&0u32.to_be_bytes());
    context.extend_from_slice(&flags.to_be_bytes());
    context.extend_from_slice(channel_binding_application_data);
    sp800_108_hmac_sha256::<SANON_SESSION_KEY_LEN>(
        shared,
        SANON_KDF_LABEL,
        &context,
    )
    .map(Zeroizing::new)
}

unsafe fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<[u8; CFX_HMAC_LEN]> {
    let mut out = [0u8; CFX_HMAC_LEN];
    let mut out_len = 0u32;
    let ret = HMAC(
        EVP_sha256(),
        key.as_ptr().cast(),
        key.len().try_into().ok()?,
        data.as_ptr(),
        data.len(),
        out.as_mut_ptr(),
        &mut out_len,
    );
    if ret.is_null() || out_len as usize != out.len() {
        return None;
    }
    Some(out)
}

unsafe fn sp800_108_hmac_sha256<const N: usize>(
    key: &[u8],
    label: &[u8],
    context: &[u8],
) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let blocks = N / CFX_HMAC_LEN;
    let mut offset = 0usize;

    for i in 0..=blocks {
        if offset == N {
            break;
        }

        let mut input =
            Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        input.extend_from_slice(&((i + 1) as u32).to_be_bytes());
        input.extend_from_slice(label);
        input.push(0);
        input.extend_from_slice(context);
        input.extend_from_slice(&((N * 8) as u32).to_be_bytes());

        let block = hmac_sha256(key, &input)?;
        let len = core::cmp::min(CFX_HMAC_LEN, N - offset);
        out[offset..offset + len].copy_from_slice(&block[..len]);
        offset += len;
    }

    Some(out)
}

type SshKeyRfc4121Profile = Aes128CtsHmacSha256128Profile;

impl Rfc4121Context for SshKeyCtx {
    type Profile = SshKeyRfc4121Profile;

    fn role(&self) -> Role {
        cfx_role(self.is_initiator)
    }

    fn send_seq(&self) -> u64 {
        self.send_seq
    }

    fn receive_state(&self) -> Rfc4121ReceiveState {
        self.receive_state
    }

    fn set_send_seq(&mut self, seq: u64) {
        self.send_seq = seq;
    }

    fn set_receive_state(&mut self, state: Rfc4121ReceiveState) {
        self.receive_state = state;
    }

    fn profile(&self) -> Result<&Self::Profile, Status> {
        if !self.complete {
            return Err(Status::new(GSS_S_NO_CONTEXT, EINVAL));
        }
        self.message_profile
            .as_ref()
            .ok_or_else(|| Status::new(GSS_S_NO_CONTEXT, EINVAL))
    }
}

fn cfx_role(is_initiator: bool) -> Role {
    if is_initiator {
        Role::Initiator
    } else {
        Role::Acceptor
    }
}

fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }

    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    out.push(0x80 | (bytes.len() - first) as u8);
    out.extend_from_slice(&bytes[first..]);
}

fn encapsulate_initial_token(inner: &[u8]) -> Vec<u8> {
    let oid_len = SSHKEY_OID_ELEMENTS.len();
    let body_len = 2 + oid_len + inner.len();
    let mut out = Vec::with_capacity(body_len + 6);

    out.push(0x60);
    encode_der_length(&mut out, body_len);
    out.push(0x06);
    encode_der_length(&mut out, oid_len);
    out.extend_from_slice(&SSHKEY_OID_ELEMENTS);
    out.extend_from_slice(inner);
    out
}

fn read_der_length(input: &[u8], offset: &mut usize) -> Option<usize> {
    let first = *input.get(*offset)?;
    *offset += 1;

    if first & 0x80 == 0 {
        return Some(first as usize);
    }

    let count = (first & 0x7f) as usize;
    if count == 0 || count > core::mem::size_of::<usize>() {
        return None;
    }
    if input.len().checked_sub(*offset)? < count {
        return None;
    }

    let mut len = 0usize;
    for byte in &input[*offset..*offset + count] {
        len = len.checked_mul(256)?.checked_add(*byte as usize)?;
    }
    *offset += count;
    Some(len)
}

fn decapsulate_initial_token(input: &[u8]) -> Option<&[u8]> {
    if input.first().copied()? != 0x60 {
        return None;
    }

    let mut offset = 1usize;
    let body_len = read_der_length(input, &mut offset)?;
    let body_end = offset.checked_add(body_len)?;
    if body_end != input.len() || input.get(offset).copied()? != 0x06 {
        return None;
    }
    offset += 1;

    let oid_len = read_der_length(input, &mut offset)?;
    let oid_end = offset.checked_add(oid_len)?;
    if oid_end > body_end
        || input.get(offset..oid_end)? != SSHKEY_OID_ELEMENTS.as_slice()
    {
        return None;
    }

    Some(&input[oid_end..body_end])
}

fn bounded(value: &OctetString, limit: usize) -> bool {
    value.len() <= limit
}

fn validate_userauth_fields(userauth: &SshKeyUserAuth) -> bool {
    bounded(&userauth.username, MAX_NAME_LEN)
        && bounded(&userauth.keytype, MAX_ALGORITHM_LIST_LEN)
        && bounded(&userauth.key, MAX_KEY_BLOB_LEN)
        && bounded(&userauth.sigtype, MAX_ALGORITHM_LIST_LEN)
        && bounded(&userauth.sig, MAX_SIGNATURE_LEN)
}

fn validate_server_context_fields(context: &SshKeyServerContext) -> bool {
    context
        .initiator_pk
        .as_ref()
        .is_none_or(|value| bounded(value, X25519_PUBLIC_LEN))
        && bounded(&context.acceptor_pk, X25519_PUBLIC_LEN)
        && context
            .session_key
            .as_ref()
            .is_none_or(|value| bounded(value, SANON_SESSION_KEY_LEN))
        && context
            .initiator_sigtypes
            .as_ref()
            .is_none_or(|value| bounded(value, MAX_ALGORITHM_LIST_LEN))
        && bounded(&context.acceptor_sigtypes, MAX_ALGORITHM_LIST_LEN)
        && context
            .acceptor_sk
            .as_ref()
            .is_none_or(|value| bounded(value, X25519_SHARED_LEN))
        && context
            .initiator_nonce
            .as_ref()
            .is_none_or(|value| bounded(value, HANDSHAKE_NONCE_LEN))
        && bounded(&context.acceptor_nonce, HANDSHAKE_NONCE_LEN)
        && bounded(&context.acceptor_name, MAX_NAME_LEN)
}

fn validate_context_token_fields(token: &SshKeyToken) -> bool {
    token.kex.as_ref().is_none_or(|kex| {
        bounded(&kex.kextypes, MAX_ALGORITHM_LIST_LEN)
            && bounded(&kex.enctypes, MAX_ALGORITHM_LIST_LEN)
            && bounded(&kex.sigtypes, MAX_ALGORITHM_LIST_LEN)
            && kex
                .kextype
                .as_ref()
                .is_none_or(|value| bounded(value, MAX_ALGORITHM_LIST_LEN))
            && kex
                .pk
                .as_ref()
                .is_none_or(|value| bounded(value, MAX_KEY_BLOB_LEN))
            && kex
                .enctype
                .as_ref()
                .is_none_or(|value| bounded(value, MAX_ALGORITHM_LIST_LEN))
            && kex
                .nonce
                .as_ref()
                .is_none_or(|value| bounded(value, HANDSHAKE_NONCE_LEN))
            && kex
                .acceptor_name
                .as_ref()
                .is_none_or(|value| bounded(value, MAX_NAME_LEN))
    }) && token.hostauth.as_ref().is_none_or(|hostauth| {
        bounded(&hostauth.keytype, MAX_ALGORITHM_LIST_LEN)
            && bounded(&hostauth.key, MAX_KEY_BLOB_LEN)
            && bounded(&hostauth.sigtype, MAX_ALGORITHM_LIST_LEN)
            && bounded(&hostauth.sig, MAX_SIGNATURE_LEN)
    }) && token
        .encuserauth
        .as_ref()
        .is_none_or(|value| bounded(&value.0, MAX_ENCRYPTED_FIELD_LEN))
        && token.cctx.as_ref().is_none_or(|value| {
            bounded(&value.enc_part, MAX_ENCRYPTED_FIELD_LEN)
        })
        && token.sctx.as_ref().is_none_or(|value| {
            bounded(&value.enc_part, MAX_ENCRYPTED_FIELD_LEN)
        })
        && token
            .finished
            .as_ref()
            .is_none_or(|finished| bounded(&finished.mac, MAX_FINISHED_MAC_LEN))
}

fn decode_context_token_bytes(input: &[u8]) -> Option<SshKeyToken> {
    if input.is_empty() || input.len() > MAX_CONTEXT_TOKEN_LEN {
        return None;
    }
    let encoded = decapsulate_initial_token(input).unwrap_or(input);
    let token = rasn::der::decode::<SshKeyToken>(encoded).ok()?;
    validate_context_token_fields(&token).then_some(token)
}

unsafe fn decode_context_token(
    minor: *mut OM_uint32,
    input: gss_buffer_t,
) -> Result<SshKeyToken, OM_uint32> {
    if input.is_null() || (*input).length == 0 || (*input).value.is_null() {
        set_minor(minor, EINVAL);
        return Err(GSS_S_DEFECTIVE_TOKEN);
    }

    let bytes = core::slice::from_raw_parts(
        (*input).value.cast::<u8>(),
        (*input).length,
    );
    match decode_context_token_bytes(bytes) {
        Some(token) => Ok(token),
        None => {
            set_minor(minor, EINVAL);
            Err(GSS_S_DEFECTIVE_TOKEN)
        }
    }
}

unsafe fn encode_output_token(
    minor: *mut OM_uint32,
    output_token: gss_buffer_t,
    token: Result<Vec<u8>, rasn::error::EncodeError>,
) -> OM_uint32 {
    match token {
        Ok(bytes) if bytes.len() <= MAX_CONTEXT_TOKEN_LEN => {
            set_buffer_bytes(minor, output_token, &bytes)
        }
        Err(_) => {
            clear_buffer(output_token);
            set_minor(minor, EINVAL);
            GSS_S_FAILURE
        }
        Ok(_) => {
            clear_buffer(output_token);
            set_minor(minor, libc::EOVERFLOW as OM_uint32);
            GSS_S_FAILURE
        }
    }
}

unsafe fn continue_userauth_after_retry(
    minor: *mut OM_uint32,
    ctx: &mut SshKeyCtx,
    token: &SshKeyToken,
    channel_bindings: &[u8],
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
) -> OM_uint32 {
    let Some(kex) = token.kex.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let Some(sctx) = token.sctx.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let Some(finished) = token.finished.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    if !token_has_status(token, SSH_KEY_CONTINUE_NEEDED)
        || token.hostauth.is_some()
        || token.encuserauth.is_some()
        || token.cctx.is_some()
        || kex.kextypes.as_ref() != KEX_ALG
        || kex.enctypes.as_ref() != ENC_ALG
        || kex.sigtypes.as_ref() != ctx.acceptor_sigtypes
        || kex.kextype.is_some()
        || kex.pk.is_some()
        || kex.enctype.is_some()
        || kex.nonce.is_some()
        || kex.acceptor_name.is_some()
        || ctx.server_context.as_deref() != Some(sctx.enc_part.as_ref())
    {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    }

    let Some(session_key) = ctx.session_key.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(initiator_public) = ctx.public_key else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(acceptor_public) = ctx.peer_public_key else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(initiator_nonce) = ctx.initiator_nonce.as_deref() else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(acceptor_nonce) = ctx.acceptor_nonce.as_deref() else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(acceptor_name) = ctx.acceptor_name.as_deref() else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    let Some(rejected_userauth) = ctx.pending_userauth.as_deref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let Some(handshake_hash) = handshake_transcript_hash(
        &ctx.initiator_sigtypes,
        &ctx.acceptor_sigtypes,
        &initiator_public,
        &acceptor_public,
        initiator_nonce,
        acceptor_nonce,
        acceptor_name,
        channel_bindings,
    ) else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    let Some(retry_hash) = userauth_retry_transcript_hash(
        &handshake_hash,
        rejected_userauth,
        sctx.enc_part.as_ref(),
    ) else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    if !verify_finished(
        finished,
        session_key,
        ACCEPTOR_RETRY_FINISHED_LABEL,
        &retry_hash,
        initiator_nonce,
    ) {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_SIG;
    }

    let Some(policy) = ctx.client_policy.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    };
    if !ctx.userauth_candidates_ready {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }
    let Some((candidate_index, encuserauth)) = next_encrypted_userauth(
        &ctx.userauth_candidates,
        ctx.next_userauth_candidate,
        session_key,
        &ctx.initiator_sigtypes,
        &ctx.acceptor_sigtypes,
        &initiator_public,
        &acceptor_public,
        initiator_nonce,
        acceptor_nonce,
        acceptor_name,
        channel_bindings,
        policy,
    ) else {
        ctx.complete = false;
        ctx.pending_userauth = None;
        set_minor(minor, libc::EACCES as OM_uint32);
        return GSS_S_UNAUTHORIZED;
    };
    let Some(client_finished) = make_finished(
        session_key,
        INITIATOR_FINISHED_LABEL,
        &handshake_hash,
        acceptor_nonce,
    ) else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    let response_kex = ctx.server_first.then(|| {
        initiator_response_kex(
            &ctx.initiator_sigtypes,
            &initiator_public,
            initiator_nonce,
            acceptor_name,
        )
    });
    let pending_userauth = encuserauth.0.as_ref().to_vec();
    let ret = encode_output_token(
        minor,
        output_token,
        initiator_final_token(
            response_kex,
            encuserauth,
            EncCtx::new(OctetString::from(sctx.enc_part.as_ref())),
            client_finished,
        ),
    );
    if ret != GSS_S_COMPLETE {
        return ret;
    }
    ctx.next_userauth_candidate = candidate_index + 1;
    ctx.pending_userauth = Some(pending_userauth);
    ctx.complete = true;
    if !ret_flags.is_null() {
        *ret_flags = sshkey_context_flags(ctx.channel_bound);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn sshkey_init_sec_context(
    minor: *mut OM_uint32,
    _cred: gss_const_cred_id_t,
    context: *mut gss_ctx_id_t,
    _target_name: gss_const_name_t,
    _mech_type: gss_const_OID,
    _req_flags: OM_uint32,
    _time_req: OM_uint32,
    channel_bindings: &[u8],
    channel_bound: bool,
    _input_token: gss_buffer_t,
    _actual_mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    _time_rec: *mut OM_uint32,
) -> OM_uint32 {
    clear_buffer(output_token);

    if context.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    if (*context).is_null() {
        *context = Box::into_raw(Box::new(SshKeyCtx::new(true))).cast();
    }
    let ctx = &mut *((*context).cast::<SshKeyCtx>());
    if remember_channel_bindings(ctx, channel_bindings, channel_bound).is_err()
    {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_BINDINGS;
    }
    if ctx.client_policy.is_none() {
        let Some((service, original_host)) =
            target_service_and_host_from_name(_target_name)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_NAME;
        };
        let policy = match ClientPolicy::resolve(
            &original_host,
            &service,
            take_client_context(),
        ) {
            Ok(policy) => policy,
            Err(error) => {
                trace(&format!("client policy: {error}"));
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            }
        };
        ctx.acceptor_name = Some(policy.acceptor_name.clone());
        ctx.client_policy = Some(policy);
    }
    if !_input_token.is_null() && (*_input_token).length != 0 {
        let token = match decode_context_token(minor, _input_token) {
            Ok(token) => token,
            Err(major) => return major,
        };
        if !token_has_status(&token, SSH_KEY_CONTINUE_NEEDED)
            && !token_has_status(&token, SSH_KEY_COMPLETE)
        {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        }
        if ctx.pending_userauth.is_some() {
            return continue_userauth_after_retry(
                minor,
                ctx,
                &token,
                channel_bindings,
                output_token,
                ret_flags,
            );
        }

        let Some(kex) = token.kex.as_ref() else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(acceptor_public) = validate_acceptor_kex(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(acceptor_nonce) = kex_nonce(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(acceptor_name) = kex_acceptor_name(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        if ctx.acceptor_name.as_deref() != Some(acceptor_name.as_slice()) {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_NAME;
        }
        let server_first = ctx.public_key.is_none() || ctx.ecdh_key.is_none();
        if server_first {
            let Some((private_key, public_key)) = generate_x25519_keypair()
            else {
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            };
            let Some(nonce) = generate_handshake_nonce() else {
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            };
            ctx.ecdh_key = Some(private_key);
            ctx.public_key = Some(public_key);
            ctx.initiator_sigtypes = SIG_ALGS.to_vec();
            ctx.initiator_nonce = Some(nonce);
        }
        let initiator_public = ctx.public_key.unwrap();
        let Some(initiator_nonce) = ctx.initiator_nonce.clone() else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let private_key = ctx.ecdh_key.as_ref().unwrap();
        let Some(shared) = x25519_shared_secret(private_key, &acceptor_public)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(session_key) = derive_anonymous_session_key(
            &shared,
            &initiator_public,
            &acceptor_public,
            0,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let acceptor_sigtypes = kex.sigtypes.as_ref().to_vec();
        let initiator_sigtypes = ctx.initiator_sigtypes.clone();
        let Some(transcript_hash) = handshake_transcript_hash(
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            &acceptor_name,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };

        if let Some(hostauth) = token.hostauth.as_ref() {
            let input = if server_first {
                host_challenge_signature_input(
                    &acceptor_sigtypes,
                    &acceptor_public,
                    &acceptor_nonce,
                    &acceptor_name,
                    &channel_bindings,
                )
            } else {
                host_signature_input(
                    &initiator_sigtypes,
                    &acceptor_sigtypes,
                    &initiator_public,
                    &acceptor_public,
                    &initiator_nonce,
                    &acceptor_nonce,
                    &acceptor_name,
                    &channel_bindings,
                )
            };
            let Some(input) = input else {
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            };
            if !verify_ssh_signature(
                hostauth.key.as_ref(),
                hostauth.sigtype.as_ref(),
                hostauth.sig.as_ref(),
                &input,
            ) {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_SIG;
            }
            let Some(policy) = ctx.client_policy.as_ref() else {
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            };
            if !host_key_is_trusted(
                policy,
                hostauth.key.as_ref(),
                hostauth.sigtype.as_ref(),
            ) {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_SIG;
            }
        } else {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_SIG;
        }
        if !server_first {
            let Some(finished) = token.finished.as_ref() else {
                set_minor(minor, EINVAL);
                return GSS_S_DEFECTIVE_TOKEN;
            };
            if !verify_finished(
                finished,
                &session_key,
                ACCEPTOR_FINISHED_LABEL,
                &transcript_hash,
                &initiator_nonce,
            ) {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_SIG;
            }
        }
        let Some(sctx) = token.sctx.as_ref() else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let server_context = sctx.enc_part.as_ref().to_vec();
        let Some(policy) = ctx.client_policy.as_ref() else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let candidates = userauth_candidates(
            policy,
            &initiator_sigtypes,
            &acceptor_sigtypes,
        );
        let Some((candidate_index, encuserauth)) = next_encrypted_userauth(
            &candidates,
            0,
            &session_key,
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            &acceptor_name,
            &channel_bindings,
            policy,
        ) else {
            set_minor(minor, libc::EACCES as OM_uint32);
            return GSS_S_UNAUTHORIZED;
        };
        let username = policy.username.clone();

        ctx.peer_public_key = Some(acceptor_public);
        ctx.set_session_key(*session_key);
        ctx.ecdh_key = None;
        ctx.acceptor_sigtypes = acceptor_sigtypes;
        ctx.server_context = Some(server_context.clone());
        ctx.acceptor_nonce = Some(acceptor_nonce.clone());
        ctx.display_name = username;
        ctx.server_first = server_first;
        ctx.userauth_candidates_ready = true;
        ctx.userauth_candidates = candidates;
        ctx.next_userauth_candidate = candidate_index + 1;
        ctx.pending_userauth = Some(encuserauth.0.as_ref().to_vec());
        ctx.send_seq = 0;
        ctx.receive_state = Rfc4121ReceiveState::new(0);
        ctx.complete = true;

        let response_kex = if server_first {
            Some(initiator_response_kex(
                &initiator_sigtypes,
                &initiator_public,
                &initiator_nonce,
                &acceptor_name,
            ))
        } else {
            None
        };
        let Some(finished) = make_finished(
            &session_key,
            INITIATOR_FINISHED_LABEL,
            &transcript_hash,
            &acceptor_nonce,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let ret = encode_output_token(
            minor,
            output_token,
            initiator_final_token(
                response_kex,
                encuserauth,
                EncCtx::new(OctetString::from(server_context.as_slice())),
                finished,
            ),
        );
        if ret != GSS_S_COMPLETE {
            return ret;
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(ctx.channel_bound);
        }
        set_minor(minor, 0);
        return GSS_S_COMPLETE;
    }

    let Some((private_key, public_key)) = generate_x25519_keypair() else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    let Some(nonce) = generate_handshake_nonce() else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    ctx.ecdh_key = Some(private_key);
    ctx.public_key = Some(public_key);
    ctx.peer_public_key = None;
    ctx.clear_session_key();
    ctx.initiator_sigtypes = SIG_ALGS.to_vec();
    ctx.acceptor_sigtypes = SIG_ALGS.to_vec();
    ctx.server_context = None;
    ctx.initiator_nonce = Some(nonce.clone());
    ctx.acceptor_nonce = None;
    ctx.server_first = false;
    ctx.userauth_candidates_ready = false;
    ctx.userauth_candidates.clear();
    ctx.next_userauth_candidate = 0;
    ctx.pending_userauth = None;
    ctx.send_seq = 0;
    ctx.receive_state = Rfc4121ReceiveState::new(0);
    ctx.complete = false;

    let ret = encode_output_token(
        minor,
        output_token,
        initial_context_token(
            &public_key,
            &nonce,
            ctx.acceptor_name.as_deref().unwrap_or_default(),
        ),
    );
    if ret != GSS_S_COMPLETE {
        return ret;
    }

    GSS_S_CONTINUE_NEEDED
}

unsafe fn sshkey_accept_sec_context(
    minor: *mut OM_uint32,
    context: *mut gss_ctx_id_t,
    _cred: gss_const_cred_id_t,
    _input_token: gss_buffer_t,
    channel_bindings: &[u8],
    channel_bound: bool,
    src_name: *mut gss_name_t,
    mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    _time_rec: *mut OM_uint32,
    _delegated_cred: *mut gss_cred_id_t,
) -> OM_uint32 {
    clear_buffer(output_token);
    let credential_acceptor_name = if _cred.is_null() {
        None
    } else {
        let credential = &*(_cred.cast::<SshKeyCredential>());
        if credential.usage == 1 {
            set_minor(minor, libc::EACCES as OM_uint32);
            return GSS_S_NO_CRED_LOCAL;
        }
        credential.name.as_ref().map(|name| name.value.clone())
    };
    if !src_name.is_null() {
        *src_name = ptr::null_mut();
    }
    if !mech_type.is_null() {
        *mech_type = ptr::null_mut();
    }
    trace("accept start");
    let staged_peer_address = take_server_context().peer_address;
    if !context.is_null() && !(*context).is_null() {
        let ctx = &mut *((*context).cast::<SshKeyCtx>());
        if ctx.server_peer_address.is_none() {
            ctx.server_peer_address = staged_peer_address;
        }
        if remember_channel_bindings(ctx, channel_bindings, channel_bound)
            .is_err()
        {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_BINDINGS;
        }
    }

    if _input_token.is_null() || (*_input_token).length == 0 {
        trace("accept server-first challenge");
        let Some(acceptor_name) = credential_acceptor_name.as_deref() else {
            trace("accept server-first requires a named acceptor credential");
            set_minor(minor, libc::EACCES as OM_uint32);
            return GSS_S_NO_CRED_LOCAL;
        };
        let Some((private_key, acceptor_public)) = generate_x25519_keypair()
        else {
            trace("accept server-first X25519 generation failed");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(acceptor_private) = x25519_private_key(&private_key) else {
            trace("accept server-first private-key export failed");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(acceptor_nonce) = generate_handshake_nonce() else {
            trace("accept server-first nonce generation failed");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let acceptor_sigtypes = SIG_ALGS.to_vec();
        let Some(issued_at) = unix_time_seconds().map(server_context_issued_at)
        else {
            trace("accept server-first system time unavailable");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let server_context = SshKeyServerContext::new(
            None,
            OctetString::from(acceptor_public.as_slice()),
            None,
            None,
            OctetString::from(acceptor_sigtypes.as_slice()),
            Some(OctetString::from(acceptor_private.as_slice())),
            None,
            OctetString::from(acceptor_nonce.as_slice()),
            OctetString::from(acceptor_name),
            issued_at,
        );
        let Some(sealed_sctx) = seal_server_context(&server_context) else {
            trace("accept server-first context sealing failed");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let sctx = EncCtx::new(OctetString::from(sealed_sctx.clone()));
        let Some(hostauth) = host_challenge_auth_token(
            &acceptor_sigtypes,
            &acceptor_public,
            &acceptor_nonce,
            acceptor_name,
            &channel_bindings,
        ) else {
            trace("accept server-first host signing failed");
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };

        if !context.is_null() && (*context).is_null() {
            let ctx = Box::new(SshKeyCtx::new(false));
            *context = Box::into_raw(ctx).cast();
        }
        if !context.is_null() {
            let ctx = &mut *((*context).cast::<SshKeyCtx>());
            ctx.ecdh_key = Some(private_key);
            ctx.public_key = Some(acceptor_public);
            ctx.peer_public_key = None;
            ctx.clear_session_key();
            ctx.acceptor_sigtypes = acceptor_sigtypes.clone();
            ctx.server_context = Some(sealed_sctx);
            ctx.initiator_nonce = None;
            ctx.acceptor_nonce = Some(acceptor_nonce.clone());
            ctx.acceptor_name = Some(acceptor_name.to_vec());
            if remember_channel_bindings(ctx, channel_bindings, channel_bound)
                .is_err()
            {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_BINDINGS;
            }
            ctx.send_seq = 0;
            ctx.receive_state = Rfc4121ReceiveState::new(0);
            ctx.complete = false;
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(channel_bound);
        }

        let ret = encode_output_token(
            minor,
            output_token,
            acceptor_context_token(
                &acceptor_public,
                &acceptor_sigtypes,
                Some(hostauth),
                sctx,
                &acceptor_nonce,
                acceptor_name,
                None,
            ),
        );
        if ret != GSS_S_COMPLETE {
            return ret;
        }
        return GSS_S_CONTINUE_NEEDED;
    }

    let token = match decode_context_token(minor, _input_token) {
        Ok(token) => token,
        Err(major) => return major,
    };
    trace("accept decoded token");
    if let Some(kex) = token
        .kex
        .as_ref()
        .filter(|kex| kex.pk.is_some() && token.sctx.is_none())
    {
        trace("accept initial token");
        if !token_has_status(&token, SSH_KEY_CONTINUE_NEEDED) {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        }
        let Some(initiator_public) = validate_initiator_kex(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(initiator_nonce) = kex_nonce(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(acceptor_name) = kex_acceptor_name(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        if credential_acceptor_name
            .as_deref()
            .is_some_and(|name| name != acceptor_name)
        {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_NAME;
        }
        let Some((private_key, acceptor_public)) = generate_x25519_keypair()
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(acceptor_nonce) = generate_handshake_nonce() else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(shared) =
            x25519_shared_secret(&private_key, &initiator_public)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(session_key) = derive_anonymous_session_key(
            &shared,
            &initiator_public,
            &acceptor_public,
            0,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let initiator_sigtypes = kex.sigtypes.as_ref().to_vec();
        let acceptor_sigtypes = SIG_ALGS.to_vec();
        let Some(transcript_hash) = handshake_transcript_hash(
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            &acceptor_name,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(finished) = make_finished(
            &session_key,
            ACCEPTOR_FINISHED_LABEL,
            &transcript_hash,
            &initiator_nonce,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(issued_at) = unix_time_seconds().map(server_context_issued_at)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let server_context = SshKeyServerContext::new(
            Some(OctetString::from(initiator_public.as_slice())),
            OctetString::from(acceptor_public.as_slice()),
            Some(OctetString::from(session_key.as_slice())),
            Some(OctetString::from(initiator_sigtypes.as_slice())),
            OctetString::from(acceptor_sigtypes.as_slice()),
            None,
            Some(OctetString::from(initiator_nonce.as_slice())),
            OctetString::from(acceptor_nonce.as_slice()),
            OctetString::from(acceptor_name.as_slice()),
            issued_at,
        );
        let Some(sealed_sctx) = seal_server_context(&server_context) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let sctx = EncCtx::new(OctetString::from(sealed_sctx.clone()));
        let Some(hostauth) = hostauth_token(
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            &acceptor_name,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };

        if !context.is_null() && (*context).is_null() {
            let ctx = Box::new(SshKeyCtx::new(false));
            *context = Box::into_raw(ctx).cast();
        }
        if !context.is_null() {
            let ctx = &mut *((*context).cast::<SshKeyCtx>());
            ctx.public_key = Some(acceptor_public);
            ctx.peer_public_key = Some(initiator_public);
            ctx.set_session_key(*session_key);
            ctx.initiator_sigtypes = initiator_sigtypes.clone();
            ctx.acceptor_sigtypes = acceptor_sigtypes.clone();
            ctx.server_context = Some(sealed_sctx);
            ctx.ecdh_key = None;
            ctx.initiator_nonce = Some(initiator_nonce.clone());
            ctx.acceptor_nonce = Some(acceptor_nonce.clone());
            ctx.acceptor_name = Some(acceptor_name.clone());
            if remember_channel_bindings(ctx, channel_bindings, channel_bound)
                .is_err()
            {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_BINDINGS;
            }
            ctx.send_seq = 0;
            ctx.receive_state = Rfc4121ReceiveState::new(0);
            ctx.complete = false;
        }
        if !mech_type.is_null() {
            *mech_type = gss_mech_builder::static_gss_oid(&SSHKEY_OID_DESC);
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(channel_bound);
        }

        let ret = encode_output_token(
            minor,
            output_token,
            acceptor_context_token(
                &acceptor_public,
                &acceptor_sigtypes,
                Some(hostauth),
                sctx,
                &acceptor_nonce,
                &acceptor_name,
                Some(finished),
            ),
        );
        if ret != GSS_S_COMPLETE {
            return ret;
        }

        trace("accept returning continue");
        return GSS_S_CONTINUE_NEEDED;
    }

    trace("accept final token");
    let Some(sctx) = token.sctx.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let Some(server_context) = open_server_context(sctx.enc_part.as_ref())
    else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let acceptor_name = match canonicalize_acceptor_credential_name(
        server_context.acceptor_name.as_ref(),
    ) {
        Ok(name) => name,
        Err(()) => {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        }
    };
    if credential_acceptor_name
        .as_deref()
        .is_some_and(|name| name != acceptor_name)
    {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_NAME;
    }
    if let Some(kex) = token.kex.as_ref() {
        let Some(token_name) = kex_acceptor_name(kex) else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        if token_name != acceptor_name {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_NAME;
        }
    }
    let Some(acceptor_public) =
        server_context.acceptor_pk.as_ref().try_into().ok()
    else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let token_initiator_public =
        token.kex.as_ref().and_then(validate_initiator_kex);
    let initiator_public =
        if let Some(value) = server_context.initiator_pk.as_ref() {
            let Some(public) = value.as_ref().try_into().ok() else {
                set_minor(minor, EINVAL);
                return GSS_S_DEFECTIVE_TOKEN;
            };
            public
        } else {
            let Some(public) = token_initiator_public else {
                set_minor(minor, EINVAL);
                return GSS_S_DEFECTIVE_TOKEN;
            };
            public
        };
    let initiator_nonce =
        if let Some(value) = server_context.initiator_nonce.as_ref() {
            value.as_ref().to_vec()
        } else if let Some(kex) = token.kex.as_ref() {
            let Some(nonce) = kex_nonce(kex) else {
                set_minor(minor, EINVAL);
                return GSS_S_DEFECTIVE_TOKEN;
            };
            nonce
        } else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
    let acceptor_nonce = server_context.acceptor_nonce.as_ref().to_vec();
    if acceptor_nonce.len() != HANDSHAKE_NONCE_LEN {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    }
    let session_key = if let Some(value) = server_context.session_key.as_ref() {
        let Some(session_key) =
            <[u8; SANON_SESSION_KEY_LEN]>::try_from(value.as_ref()).ok()
        else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        Zeroizing::new(session_key)
    } else {
        let Some(value) = server_context.acceptor_sk.as_ref() else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(acceptor_private) = value.as_ref().try_into().ok() else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        let Some(private_key) = x25519_key_from_private(&acceptor_private)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(shared) =
            x25519_shared_secret(&private_key, &initiator_public)
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(session_key) = derive_anonymous_session_key(
            &shared,
            &initiator_public,
            &acceptor_public,
            0,
            &channel_bindings,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        session_key
    };
    let initiator_sigtypes =
        if let Some(value) = server_context.initiator_sigtypes.as_ref() {
            value.as_ref().to_vec()
        } else if let Some(kex) = token.kex.as_ref() {
            kex.sigtypes.as_ref().to_vec()
        } else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
    let acceptor_sigtypes = server_context.acceptor_sigtypes.as_ref().to_vec();
    let Some(transcript_hash) = handshake_transcript_hash(
        &initiator_sigtypes,
        &acceptor_sigtypes,
        &initiator_public,
        &acceptor_public,
        &initiator_nonce,
        &acceptor_nonce,
        &acceptor_name,
        &channel_bindings,
    ) else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    let Some(finished) = token.finished.as_ref() else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    if !verify_finished(
        finished,
        &session_key,
        INITIATOR_FINISHED_LABEL,
        &transcript_hash,
        &acceptor_nonce,
    ) {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_SIG;
    }
    let encuserauth = match required_userauth(&token) {
        Ok(encuserauth) => encuserauth,
        Err(major) => {
            set_minor(minor, libc::EACCES as OM_uint32);
            return major;
        }
    };
    let Some(userauth) = decrypt_userauth(&session_key, encuserauth) else {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_SIG;
    };
    if !alg_list_contains(&acceptor_sigtypes, userauth.sigtype.as_ref()) {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    }
    let Some(input) = user_signature_input(
        &initiator_sigtypes,
        &acceptor_sigtypes,
        &initiator_public,
        &acceptor_public,
        &initiator_nonce,
        &acceptor_nonce,
        &acceptor_name,
        userauth.username.as_ref(),
        userauth.keytype.as_ref(),
        userauth.key.as_ref(),
        userauth.sigtype.as_ref(),
        &channel_bindings,
    ) else {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    };
    if !verify_ssh_signature(
        userauth.key.as_ref(),
        userauth.sigtype.as_ref(),
        userauth.sig.as_ref(),
        &input,
    ) {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_SIG;
    }
    if let Err(error) = authorize_user_key(
        userauth.username.as_ref(),
        userauth.key.as_ref(),
        userauth.sigtype.as_ref(),
        if context.is_null() || (*context).is_null() {
            None
        } else {
            (*((*context).cast::<SshKeyCtx>()))
                .server_peer_address
                .as_deref()
        },
    ) {
        trace(&format!("server authorization: {error}"));
        let Some(retry_hash) = userauth_retry_transcript_hash(
            &transcript_hash,
            encuserauth.0.as_ref(),
            sctx.enc_part.as_ref(),
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(retry_finished) = make_finished(
            &session_key,
            ACCEPTOR_RETRY_FINISHED_LABEL,
            &retry_hash,
            &initiator_nonce,
        ) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let ret = encode_output_token(
            minor,
            output_token,
            userauth_retry_token(
                &acceptor_sigtypes,
                EncCtx::new(OctetString::from(sctx.enc_part.as_ref())),
                retry_finished,
            ),
        );
        return if ret == GSS_S_COMPLETE {
            GSS_S_CONTINUE_NEEDED
        } else {
            ret
        };
    }
    let display_name = userauth.username.as_ref().to_vec();
    let authorized_user = Some(display_name.clone());

    if !context.is_null() && (*context).is_null() {
        let ctx = Box::new(SshKeyCtx::new(false));
        *context = Box::into_raw(ctx).cast();
    }
    if !context.is_null() {
        let ctx = &mut *((*context).cast::<SshKeyCtx>());
        ctx.public_key = Some(acceptor_public);
        ctx.peer_public_key = Some(initiator_public);
        ctx.set_session_key(*session_key);
        ctx.initiator_sigtypes = initiator_sigtypes;
        ctx.acceptor_sigtypes = acceptor_sigtypes;
        ctx.server_context = Some(sctx.enc_part.as_ref().to_vec());
        ctx.display_name = display_name.clone();
        ctx.authorized_user = authorized_user.clone();
        ctx.ecdh_key = None;
        ctx.initiator_nonce = Some(initiator_nonce);
        ctx.acceptor_nonce = Some(acceptor_nonce);
        ctx.acceptor_name = Some(acceptor_name);
        if remember_channel_bindings(ctx, channel_bindings, channel_bound)
            .is_err()
        {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_BINDINGS;
        }
        ctx.send_seq = 0;
        ctx.receive_state = Rfc4121ReceiveState::new(0);
        ctx.complete = true;
    }
    if !src_name.is_null() {
        *src_name = Box::into_raw(Box::new(SshKeyName {
            value: display_name.clone(),
            authorized_user: authorized_user.clone(),
        }))
        .cast();
    }
    if !mech_type.is_null() {
        *mech_type = gss_mech_builder::static_gss_oid(&SSHKEY_OID_DESC);
    }
    if !ret_flags.is_null() {
        *ret_flags = sshkey_context_flags(channel_bound);
    }

    set_minor(minor, 0);
    GSS_S_COMPLETE
}

fn input_buffer(input: Option<&[u8]>) -> gss_buffer_desc {
    let input = input.unwrap_or_default();
    gss_buffer_desc {
        length: input.len(),
        value: input.as_ptr() as *mut c_void,
    }
}

unsafe fn take_output_buffer(output: &mut gss_buffer_desc) -> Option<Vec<u8>> {
    let value = if output.length == 0 || output.value.is_null() {
        None
    } else {
        Some(
            core::slice::from_raw_parts(
                output.value.cast::<u8>(),
                output.length,
            )
            .to_vec(),
        )
    };
    gss_mech_builder::release_buffer(output);
    value
}

impl EstablishmentMechanism for SshKeyMechanism {
    type Credential = SshKeyCredential;

    fn create_context(locally_initiated: bool) -> Self::Context {
        SshKeyCtx::new(locally_initiated)
    }

    fn init_sec_context(
        ctx: &mut Self::Context,
        cred: Option<&Self::Credential>,
        target_name: &Self::Name,
        mech_type: Option<&[u8]>,
        req_flags: OM_uint32,
        time_req: OM_uint32,
        channel_bindings: Option<ChannelBindings<'_>>,
        input_token: Option<&[u8]>,
    ) -> Result<InitSecContextResult, Status> {
        trace("init mechanism context");
        if cred.is_some_and(|cred| cred.usage == 2) {
            return Err(Status::new(GSS_S_FAILURE, libc::EACCES as u32));
        }
        let mut minor = 0;
        let mut context = (ctx as *mut SshKeyCtx).cast();
        let target = (target_name as *const SshKeyName).cast_mut().cast();
        let mech = mech_type
            .map(|oid| unsafe { gss_mech_builder::alloc_oid_desc(oid) })
            .unwrap_or(ptr::null_mut());
        let mut input = input_buffer(input_token);
        let mut output = gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };
        let channel_bound = channel_bindings.is_some();
        let channel_bindings = canonical_channel_bindings(channel_bindings)?;
        let major = unsafe {
            sshkey_init_sec_context(
                &mut minor,
                ptr::null(),
                &mut context,
                target,
                mech.cast_const(),
                req_flags,
                time_req,
                &channel_bindings,
                channel_bound,
                &mut input,
                ptr::null_mut(),
                &mut output,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if !mech.is_null() {
            unsafe {
                let mut mech = mech;
                let _ =
                    gss_mech_builder::release_oid(ptr::null_mut(), &mut mech);
            }
        }
        let output_token = unsafe { take_output_buffer(&mut output) };
        if major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED {
            return Err(Status::new(major, minor));
        }
        Ok(InitSecContextResult {
            status: Status::new(major, minor),
            output_token,
        })
    }

    fn accept_sec_context(
        ctx: &mut Self::Context,
        cred: Option<&Self::Credential>,
        input_token: &[u8],
        channel_bindings: Option<ChannelBindings<'_>>,
        _ret_deleg_cred: bool,
    ) -> Result<AcceptSecContextResult<Self::Credential>, Status> {
        if cred.is_some_and(|cred| cred.usage == 1) {
            return Err(Status::new(GSS_S_FAILURE, libc::EACCES as u32));
        }
        let mut minor = 0;
        let mut context = (ctx as *mut SshKeyCtx).cast();
        let mut input = input_buffer(Some(input_token));
        let mut output = gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };
        let channel_bound = channel_bindings.is_some();
        let channel_bindings = canonical_channel_bindings(channel_bindings)?;
        let credential = cred
            .map(|credential| {
                (credential as *const SshKeyCredential).cast::<c_void>()
            })
            .unwrap_or(ptr::null());
        let major = unsafe {
            sshkey_accept_sec_context(
                &mut minor,
                &mut context,
                credential,
                &mut input,
                &channel_bindings,
                channel_bound,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut output,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let output_token = unsafe { take_output_buffer(&mut output) };
        if major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED {
            return Err(Status::new(major, minor));
        }
        Ok(AcceptSecContextResult {
            status: Status::new(major, minor),
            output_token,
            delegated_cred: None,
        })
    }
}

#[repr(C)]
pub struct gss_sshkey_context_field {
    name: *const libc::c_char,
    value: gss_buffer_desc,
}

unsafe fn context_field_value<'a>(
    field: &gss_sshkey_context_field,
) -> Result<&'a [u8], Status> {
    if field.value.length == 0 {
        return Ok(&[]);
    }
    if field.value.value.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }
    Ok(core::slice::from_raw_parts(
        field.value.value.cast::<u8>(),
        field.value.length,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn gss_sshkey_set_context_fields(
    minor: *mut OM_uint32,
    role: OM_uint32,
    version: OM_uint32,
    fields: *const gss_sshkey_context_field,
    field_count: usize,
) -> OM_uint32 {
    if version != CONTEXT_VERSION
        || !matches!(role, CONTEXT_CLIENT | CONTEXT_SERVER)
        || (field_count != 0 && fields.is_null())
    {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }
    let fields = if field_count == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(fields, field_count)
    };
    match role {
        CONTEXT_CLIENT => {
            let mut context = ClientContextInput::default();
            for field in fields {
                if field.name.is_null() {
                    set_minor(minor, EINVAL);
                    return GSS_S_FAILURE;
                }
                let name = CStr::from_ptr(field.name).to_bytes();
                let value = match context_field_value(field) {
                    Ok(value) => value,
                    Err(status) => {
                        set_minor(minor, status.minor);
                        return status.major;
                    }
                };
                match name {
                    b"user" => {
                        let Ok(user) = core::str::from_utf8(value) else {
                            set_minor(minor, EINVAL);
                            return GSS_S_FAILURE;
                        };
                        if !valid_username(user) {
                            set_minor(minor, EINVAL);
                            return GSS_S_FAILURE;
                        }
                        context.user = Some(user.to_string());
                    }
                    b"host-key" => {
                        if PublicKey::from_bytes(value).is_err() {
                            set_minor(minor, EINVAL);
                            return GSS_S_FAILURE;
                        }
                        context.verified_host_key = Some(value.to_vec());
                    }
                    _ => {
                        set_minor(minor, EINVAL);
                        return GSS_S_FAILURE;
                    }
                }
            }
            PENDING_CLIENT_CONTEXT
                .with(|pending| *pending.borrow_mut() = Some(context));
        }
        CONTEXT_SERVER => {
            let mut context = ServerContextInput::default();
            for field in fields {
                if field.name.is_null() {
                    set_minor(minor, EINVAL);
                    return GSS_S_FAILURE;
                }
                let name = CStr::from_ptr(field.name).to_bytes();
                let value = match context_field_value(field) {
                    Ok(value) => value,
                    Err(status) => {
                        set_minor(minor, status.minor);
                        return status.major;
                    }
                };
                match name {
                    b"peer-address" => {
                        let Ok(address) = core::str::from_utf8(value) else {
                            set_minor(minor, EINVAL);
                            return GSS_S_FAILURE;
                        };
                        if address.parse::<std::net::IpAddr>().is_err() {
                            set_minor(minor, EINVAL);
                            return GSS_S_FAILURE;
                        }
                        context.peer_address = Some(address.to_string());
                    }
                    _ => {
                        set_minor(minor, EINVAL);
                        return GSS_S_FAILURE;
                    }
                }
            }
            PENDING_SERVER_CONTEXT
                .with(|pending| *pending.borrow_mut() = Some(context));
        }
        _ => unreachable!(),
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_sshkey_clear_context_fields(
    minor: *mut OM_uint32,
    role: OM_uint32,
) -> OM_uint32 {
    if role == CONTEXT_CLIENT || role == CONTEXT_ALL {
        PENDING_CLIENT_CONTEXT.with(|pending| {
            pending.borrow_mut().take();
        });
    }
    if role == CONTEXT_SERVER || role == CONTEXT_ALL {
        PENDING_SERVER_CONTEXT.with(|pending| {
            pending.borrow_mut().take();
        });
    }
    if !matches!(role, CONTEXT_CLIENT | CONTEXT_SERVER | CONTEXT_ALL) {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

gss_mech_builder::export_gssapi_name_ops!(SshKeyMechanism);
gss_mech_builder::export_gssapi_localname_ops!(SshKeyMechanism);
gss_mech_builder::export_gssapi_mechanism_info_ops!(SshKeyMechanism);
gss_mech_builder::export_gssapi_credential_ops!(
    SshKeyMechanism,
    SshKeyMechanism
);
gss_mech_builder::export_gssapi_establishment_ops!(SshKeyMechanism);
gss_mech_builder::export_gssapi_context_lifecycle_ops!(SshKeyMechanism);
gss_mech_builder::export_rfc4121_per_message!(SshKeyCtx);
gss_mech_builder::export_gssapi_entrypoint!(gss_export_sec_context =>
    gss_mech_builder::export_sec_context_unavailable; (
    minor: *mut OM_uint32,
    context: *mut gss_ctx_id_t,
    token: gss_buffer_t,
));
gss_mech_builder::export_gssapi_entrypoint!(gss_import_sec_context =>
    gss_mech_builder::import_sec_context_unavailable; (
    minor: *mut OM_uint32,
    token: gss_buffer_t,
    context: *mut gss_ctx_id_t,
));

#[cfg(test)]
mod tests {
    use super::*;
    use gss_mech_builder::test_harness::{
        AcceptorResult, MechanismFixture, ObservedServices, PreparedExchange,
        SetupGss, TestChannelBindings,
    };
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread::{self, JoinHandle};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat()
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            loop {
                let sequence =
                    NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!(
                    "gss-sshkey-{name}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(
                            &path,
                            fs::Permissions::from_mode(0o700),
                        )
                        .unwrap();
                        return Self(path);
                    }
                    Err(error)
                        if error.kind()
                            == std::io::ErrorKind::AlreadyExists =>
                    {
                        continue;
                    }
                    Err(error) => {
                        panic!("cannot create test directory: {error}")
                    }
                }
            }
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct EnvironmentGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvironmentGuard {
        fn set(values: &[(&'static str, &std::ffi::OsStr)]) -> Self {
            let mut saved = Vec::with_capacity(values.len());
            for (name, value) in values {
                saved.push((*name, env::var_os(name)));
                env::set_var(name, value);
            }
            Self { saved }
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..).rev() {
                if let Some(value) = value {
                    env::set_var(name, value);
                } else {
                    env::remove_var(name);
                }
            }
        }
    }

    struct SshKeyConformanceFixture {
        _environment: EnvironmentGuard,
        _directory: TestDirectory,
        username: String,
    }

    impl MechanismFixture for SshKeyConformanceFixture {
        fn mechanism_oid(&self) -> &[u8] {
            &SSHKEY_OID_ELEMENTS
        }

        fn prepare(
            &mut self,
            setup: &mut SetupGss,
        ) -> Result<PreparedExchange, String> {
            let target = setup
                .import_hostbased_name(b"sshkey@localhost")
                .map_err(|error| error.to_string())?;
            let acceptor_credential = setup
                .acquire_credential(None, GSS_C_ACCEPT)
                .map_err(|error| error.to_string())?;
            let required_flags = GSS_C_MUTUAL_FLAG
                | GSS_C_REPLAY_FLAG
                | GSS_C_SEQUENCE_FLAG
                | GSS_C_CONF_FLAG
                | GSS_C_INTEG_FLAG
                | GSS_C_CHANNEL_BOUND_FLAG;
            let mut exchange = PreparedExchange::new(target);
            exchange.acceptor_credential = acceptor_credential.into();
            exchange.requested_flags = required_flags;
            exchange.required_flags = required_flags;
            exchange.forbidden_flags = GSS_C_ANON_FLAG | GSS_C_TRANS_FLAG;
            exchange.local_username = Some(self.username.clone());
            exchange.set_channel_bindings(TestChannelBindings::new(
                b"gss-sshkey conformance bindings".to_vec(),
            ));
            Ok(exchange)
        }

        fn validate_acceptor(
            &mut self,
            result: &AcceptorResult,
        ) -> Result<(), String> {
            if result.source_name != self.username.as_bytes() {
                return Err(
                    "authenticated source name is not the requested username"
                        .into(),
                );
            }
            if result.target_name != b"sshkey@localhost" {
                return Err(
                    "acceptor context returned the wrong target name".into()
                );
            }
            if result.actual_mechanism != SSHKEY_OID_ELEMENTS {
                return Err("acceptor returned the wrong mechanism OID".into());
            }
            if result.delegated_credential {
                return Err("SSHKEY unexpectedly delegated a credential".into());
            }
            Ok(())
        }

        fn validate_services(
            &mut self,
            services: &ObservedServices,
        ) -> Result<(), String> {
            if !services.iov || !services.aead || !services.pseudo_random {
                return Err("SSHKEY did not provide its complete message protection surface".into());
            }
            if services.context_transfer {
                return Err(
                    "SSHKEY unexpectedly reported context transfer support"
                        .into(),
                );
            }
            Ok(())
        }
    }

    fn sshkey_conformance_fixture() -> SshKeyConformanceFixture {
        let directory = TestDirectory::new("gss-conformance");
        let host_key = seeded_ed25519_private_key(0x51);
        let user_key = seeded_ed25519_private_key(0x52);
        let host_key_path = directory.path().join("host_ed25519");
        let identity_path = directory.path().join("id_ed25519");
        let known_hosts_path = directory.path().join("known_hosts");
        let authorized_keys_path = directory.path().join("authorized_keys");
        let client_config_path = directory.path().join("ssh_config");
        let server_config_path = directory.path().join("sshd_config");
        let username = env::var("USER").expect("USER is required by tests");

        let encoded_host = host_key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize host key");
        fs::write(&host_key_path, encoded_host.as_bytes()).unwrap();
        let encoded_user = user_key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize user key");
        fs::write(&identity_path, encoded_user.as_bytes()).unwrap();
        fs::write(
            &known_hosts_path,
            format!(
                "localhost {}\n",
                host_key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        fs::write(
            &authorized_keys_path,
            format!("{}\n", user_key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        fs::write(
            &client_config_path,
            format!(
                "Host *\n\
                 User {username}\n\
                 IdentityAgent none\n\
                 IdentitiesOnly yes\n\
                 IdentityFile {}\n\
                 UserKnownHostsFile {}\n\
                 GlobalKnownHostsFile none\n\
                 GSSAPIAuthentication yes\n\
                 PreferredAuthentications gssapi-with-mic\n",
                identity_path.display(),
                known_hosts_path.display(),
            ),
        )
        .unwrap();
        fs::write(
            &server_config_path,
            "GSSAPIAuthentication yes\nStrictModes no\n",
        )
        .unwrap();

        let context_key = std::ffi::OsStr::new(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let environment = EnvironmentGuard::set(&[
            (SSHKEY_HOST_KEY_ENV, host_key_path.as_os_str()),
            (SSHKEY_AUTHORIZED_KEYS_ENV, authorized_keys_path.as_os_str()),
            (SSHKEY_SSH_CONFIG_ENV, client_config_path.as_os_str()),
            (SSHKEY_SSHD_CONFIG_ENV, server_config_path.as_os_str()),
            (SSHKEY_CTX_KEY_ENV, context_key),
        ]);

        SshKeyConformanceFixture {
            _environment: environment,
            _directory: directory,
            username,
        }
    }

    gss_mech_builder::gss_mechanism_conformance_tests!(
        sshkey_conformance_fixture
    );

    fn authorization_file_fixture(
        name: &str,
    ) -> (TestDirectory, LocalAccount, PathBuf, PathBuf) {
        let temp = TestDirectory::new(name);
        let home = temp.path().join("home");
        let keys = home.join("keys");
        let ssh = keys.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        for directory in [&home, &keys, &ssh] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let path = ssh.join("authorized_keys");
        fs::write(&path, b"original authorized key\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let account = LocalAccount {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            home,
        };
        (temp, account, keys, path)
    }

    #[test]
    fn context_session_keys_are_zeroized_before_clear_or_drop() {
        let mut ctx = SshKeyCtx::new(true);
        ctx.set_session_key([0x5a; SANON_SESSION_KEY_LEN]);
        ctx.zeroize_secrets();
        assert_eq!(
            ctx.session_key.as_deref(),
            Some(&[0; SANON_SESSION_KEY_LEN]),
        );

        ctx.set_session_key([0xa5; SANON_SESSION_KEY_LEN]);
        ctx.clear_session_key();
        assert!(ctx.session_key.is_none());
        assert!(ctx.message_profile.is_none());
    }

    fn ed25519_private_key() -> PrivateKey {
        let pem = concat!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
            "AAAAMwAAAAtzc2gtZW\n",
            "QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1x",
            "UqrYgAAAJgAIAxdACAM\n",
            "XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2X",
            "xtSmk9D7RQyf1xUqrYg\n",
            "AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM",
            "+rvN+ot98qgEN796jTiQf\n",
            "ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
        );
        PrivateKey::from_openssh(pem).unwrap()
    }

    fn seeded_ed25519_private_key(seed: u8) -> PrivateKey {
        use ssh_key::private::Ed25519Keypair;

        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }

    fn rsa_private_key() -> PrivateKey {
        let pem = concat!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
            "AAABFwAAAAdzc2gtcn\n",
            "NhAAAAAwEAAQAAAQEAs/sUZhfUAUFsu2Pz2ztiE8z7EM35ZH43c",
            "M10OKkNVqzh2W7TmYZk\n",
            "OU3OLyQL1Vq/j0c5ok0bVGaS8NwxVZ5rX5IPc54KXUGVuOe7rc",
            "bXrO8rU5xiihftgQAYQ7\n",
            "BLSod8rd1JufkLCHtc2qD48jXCFRuFX+qA1SrnVWa4dFKt4+6W",
            "96UC48nXG6qHQEDAHjaj\n",
            "MOyVplklepPPFISAeqKtGtvM+SYjAJhzn8+DSa/PYrcZ4zG8MoS",
            "npTR65D5WBSlHLjefCC\n",
            "bI01ZqvTzpJs5mZBTvb4v51jwbVXnoh7PvToCeXvwiXJEqXFKcR",
            "qLZNUB7prls6lHi+cjI\n",
            "cre+c7jfrwAAA8Aw7tEsMO7RLAAAAAdzc2gtcnNhAAABAQCz+xRm",
            "F9QBQWy7Y/PbO2ITzP\n",
            "sQzflkfjdwzXQ4qQ1WrOHZbtOZhmQ5Tc4vJAvVWr+PRzmiTRtUZ",
            "pLw3DFVnmtfkg9zngpd\n",
            "QZW457utxtes7ytTnGKKF+2BABhDsEtKh3yt3Um5+QsIe1zaoPj",
            "yNcIVG4Vf6oDVKudVZr\n",
            "h0Uq3j7pb3pQLjydcbqodAQMAeNqMw7JWmWSV6k88UhIB6oq0a",
            "28z5JiMAmHOfz4NJr89i\n",
            "txnjMbwyhKelNHrkPlYFKUcuN58IJsjTVmq9POkmzmZkFO9vi/n",
            "WPBtVeeiHs+9OgJ5e/C\n",
            "JckSpcUpxGotk1QHumuWzqUeL5yMhyt75zuN+vAAAAAwEAAQAAAQ",
            "AB427lMVVpSuUCZnel\n",
            "UGSPSG0kfH7oWzCrhvVnHqhMiZ3nB6MXVYVIr/i8jY2z9xTkD4",
            "fjYMOJNlYs0rmQDrcZ5Z\n",
            "MQh5dpP2ompkiZ7zVFHGjp717kYSts4cdFzCTGF+qzWLYDwbAF+0",
            "JyHooQR7qVn4MACquM\n",
            "yH/TWFWrUoP1svahnEl9yP62xcjGUH504Ec8sAfh9bj4jwpDkRe",
            "Vq+1zSX96zeCrM/iuVm\n",
            "JWQnUPMhB8LikxfeyLZmdmbFig/lkAXDLUBBrmG3xs6pT+cHXgIs",
            "o4rbTuQjgVlooqGXP0\n",
            "/Cak0J6MSZk2Monukp+6nM3tT5E7mLcStwslP88C5T/ZAAAAgA",
            "wp/DVGq4aP+HXa9wJokW\n",
            "03KcGP1yLbIg2dTeQGb86fviZs9PmAoxK4CIv97hSM+RbNve1v",
            "Zv9Lm3M6JNwjhyYQ6Iz3\n",
            "hh5KQEm8hXd04lmk1zKPExKWHysr9BTiVKGjiI7oePilWIveITh",
            "tX4FEStzUkVQ1fpy31N\n",
            "G1bhbmXr0LAAAAgQDWuWddprvDIp+QP9E5ehcjo+lmuw/n2/9aA",
            "cREnCj12hsZ+fGalshb\n",
            "0jmStyXL3/mbzpY/f7Jl6+ZWK8/qI6xIrh5NvUPAtJkXiw/Sldj",
            "XgoMxq1JchWPGJoVvjX\n",
            "XVeSmxxBxouP2hvBeMddmceNrZu5jpQXPj4u54CC0aCRF6RwAAA",
            "IEA1pPypyKXFOQL1zu6\n",
            "gPsjsBXkIgEJ0/hZAZ+ErEPSMF3GArD3Ju4JK9Q85aw95dtMq6t",
            "nz3n6dosGF7R3wkmKP+\n",
            "WMX1KOWs0mu7jeTrZXg9AiVJGVO2QmAGXI2GTGBBPRy2WZr6WIO",
            "o7TbgNvJF/ewuwyRM4z\n",
            "269/nSK+XkNRO1kAAAAIdGVzdC1yc2EBAgM=\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
        );
        PrivateKey::from_openssh(pem).unwrap()
    }

    fn test_client_policy(
        agent_socket: PathBuf,
        accepted_algorithms: &[&str],
    ) -> ClientPolicy {
        ClientPolicy {
            host: "host.example".to_string(),
            acceptor_name: b"sshkey@host.example".to_vec(),
            known_hosts_name: "host.example".to_string(),
            username: b"alice".to_vec(),
            agent_socket: Some(agent_socket),
            identity_files: Vec::new(),
            identities_only: false,
            accepted_algorithms: accepted_algorithms
                .iter()
                .map(|algorithm| (*algorithm).to_string())
                .collect(),
            host_key_algorithms: default_signature_algorithms(),
            required_rsa_size: 2048,
            known_hosts_files: Vec::new(),
            verified_host_key: None,
            verify_host_key_dns: false,
        }
    }

    fn test_agent_signature(
        private_key: &PrivateKey,
        data: &[u8],
        flags: u32,
    ) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use signature::{SignatureEncoding, Signer as _};
        use ssh_key::HashAlg;

        let signature = match flags {
            SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512 => {
                let keypair = private_key.key_data().rsa().unwrap();
                let bigint = |value: &ssh_key::Mpint| {
                    rsa::BigUint::from_bytes_be(
                        value.as_positive_bytes().unwrap(),
                    )
                };
                let private_key = rsa::RsaPrivateKey::from_components(
                    bigint(&keypair.public.n),
                    bigint(&keypair.public.e),
                    bigint(&keypair.private.d),
                    vec![
                        bigint(&keypair.private.p),
                        bigint(&keypair.private.q),
                    ],
                )
                .expect("valid RSA test key");
                let (algorithm, data) = if flags == SSH_AGENT_RSA_SHA2_256 {
                    let signature =
                        SigningKey::<Sha256>::new(private_key).sign(data);
                    (
                        Algorithm::Rsa {
                            hash: Some(HashAlg::Sha256),
                        },
                        signature.to_vec(),
                    )
                } else {
                    let signature =
                        SigningKey::<sha2::Sha512>::new(private_key).sign(data);
                    (
                        Algorithm::Rsa {
                            hash: Some(HashAlg::Sha512),
                        },
                        signature.to_vec(),
                    )
                };
                SshSignature::new(algorithm, data).unwrap()
            }
            0 => Signer::try_sign(private_key, data).unwrap(),
            _ => panic!("unexpected agent signature flags {flags:#x}"),
        };
        Vec::<u8>::try_from(signature).unwrap()
    }

    fn spawn_test_agent(
        temp: &TestDirectory,
        private_keys: Vec<PrivateKey>,
        request_count: usize,
    ) -> (PathBuf, JoinHandle<()>) {
        let path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let thread = thread::spawn(move || {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).unwrap();
                let mut request = vec![0; u32::from_be_bytes(len) as usize];
                stream.read_exact(&mut request).unwrap();

                let mut reply = Vec::new();
                match request.first().copied() {
                    Some(SSH2_AGENTC_REQUEST_IDENTITIES) => {
                        assert_eq!(request.len(), 1);
                        reply.push(SSH2_AGENT_IDENTITIES_ANSWER);
                        push_ssh_u32(
                            &mut reply,
                            private_keys.len().try_into().unwrap(),
                        );
                        for private_key in &private_keys {
                            push_ssh_string(
                                &mut reply,
                                &private_key.public_key().to_bytes().unwrap(),
                            )
                            .unwrap();
                            push_ssh_string(&mut reply, b"test key").unwrap();
                        }
                    }
                    Some(SSH2_AGENTC_SIGN_REQUEST) => {
                        let mut body = &request[1..];
                        let key = read_ssh_string(&mut body).unwrap();
                        let data = read_ssh_string(&mut body).unwrap();
                        let flags = read_ssh_u32(&mut body).unwrap();
                        assert!(body.is_empty());
                        let private_key = private_keys
                            .iter()
                            .find(|candidate| {
                                candidate.public_key().to_bytes().unwrap()
                                    == key
                            })
                            .expect("agent was asked for an unknown key");
                        let signature =
                            test_agent_signature(private_key, &data, flags);
                        reply.push(SSH2_AGENT_SIGN_RESPONSE);
                        push_ssh_string(&mut reply, &signature).unwrap();
                    }
                    message => panic!("unexpected agent request {message:?}"),
                }
                stream
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        });
        (path, thread)
    }

    unsafe fn exercise_agent_retry(
        private_keys: Vec<PrivateKey>,
        accepted_algorithms: &[&str],
    ) -> (SshKeyUserAuth, SshKeyUserAuth) {
        let temp = TestDirectory::new("agent-retry");
        let (socket, agent) = spawn_test_agent(&temp, private_keys, 3);
        let policy = test_client_policy(socket, accepted_algorithms);
        let signature_algorithms = accepted_algorithms.join(",").into_bytes();
        let session_key = [0x42; SANON_SESSION_KEY_LEN];
        let initiator_public = [0x11; X25519_PUBLIC_LEN];
        let acceptor_public = [0x22; X25519_PUBLIC_LEN];
        let initiator_nonce = [0x33; HANDSHAKE_NONCE_LEN];
        let acceptor_nonce = [0x44; HANDSHAKE_NONCE_LEN];
        let acceptor_name = b"sshkey@host.example";
        let channel_bindings = b"test channel bindings";
        let server_context = b"sealed server context";
        let candidates = userauth_candidates(
            &policy,
            &signature_algorithms,
            &signature_algorithms,
        );
        assert!(candidates.len() >= 2);

        let (first_index, first_encrypted) = next_encrypted_userauth(
            &candidates,
            0,
            &session_key,
            &signature_algorithms,
            &signature_algorithms,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            acceptor_name,
            channel_bindings,
            &policy,
        )
        .unwrap();
        let first = decrypt_userauth(&session_key, &first_encrypted).unwrap();
        let transcript_hash = handshake_transcript_hash(
            &signature_algorithms,
            &signature_algorithms,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            acceptor_name,
            channel_bindings,
        )
        .unwrap();
        let retry_hash = userauth_retry_transcript_hash(
            &transcript_hash,
            first_encrypted.0.as_ref(),
            server_context,
        )
        .unwrap();
        let retry_finished = make_finished(
            &session_key,
            ACCEPTOR_RETRY_FINISHED_LABEL,
            &retry_hash,
            &initiator_nonce,
        )
        .unwrap();
        let retry = rasn::der::decode::<SshKeyToken>(
            &userauth_retry_token(
                &signature_algorithms,
                EncCtx::new(OctetString::from(server_context.as_slice())),
                retry_finished,
            )
            .unwrap(),
        )
        .unwrap();

        let mut ctx = SshKeyCtx::new(true);
        ctx.complete = true;
        ctx.public_key = Some(initiator_public);
        ctx.peer_public_key = Some(acceptor_public);
        ctx.set_session_key(session_key);
        ctx.initiator_sigtypes = signature_algorithms.clone();
        ctx.acceptor_sigtypes = signature_algorithms;
        ctx.server_context = Some(server_context.to_vec());
        ctx.acceptor_name = Some(acceptor_name.to_vec());
        ctx.client_policy = Some(policy);
        ctx.initiator_nonce = Some(initiator_nonce.to_vec());
        ctx.acceptor_nonce = Some(acceptor_nonce.to_vec());
        ctx.userauth_candidates_ready = true;
        ctx.userauth_candidates = candidates;
        ctx.next_userauth_candidate = first_index + 1;
        ctx.pending_userauth = Some(first_encrypted.0.as_ref().to_vec());

        let mut output = gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };
        let mut minor = 0;
        let mut flags = 0;
        assert_eq!(
            continue_userauth_after_retry(
                &mut minor,
                &mut ctx,
                &retry,
                channel_bindings,
                &mut output,
                &mut flags,
            ),
            GSS_S_COMPLETE
        );
        assert_eq!(minor, 0);
        let output = take_output_buffer(&mut output).unwrap();
        let token = rasn::der::decode::<SshKeyToken>(&output).unwrap();
        let second =
            decrypt_userauth(&session_key, token.encuserauth.as_ref().unwrap())
                .unwrap();
        agent.join().unwrap();
        (first, second)
    }

    #[test]
    fn userauth_candidates_follow_openssh_agent_order() {
        let temp = TestDirectory::new("agent-order");
        let other = seeded_ed25519_private_key(1);
        let configured = seeded_ed25519_private_key(2);
        let other_key = other.public_key().to_bytes().unwrap();
        let configured_key = configured.public_key().to_bytes().unwrap();
        let identity = temp.path().join("id_configured");
        fs::write(
            identity.with_extension("pub"),
            configured.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        let (socket, agent) =
            spawn_test_agent(&temp, vec![other, configured], 1);
        let mut policy = test_client_policy(socket, &["ssh-ed25519"]);
        policy.identity_files.push(identity);

        let candidates =
            userauth_candidates(&policy, b"ssh-ed25519", b"ssh-ed25519");

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].key, configured_key);
        assert_eq!(candidates[1].key, other_key);
        assert!(candidates.iter().all(|candidate| matches!(
            candidate.signer,
            UserAuthSigner::Agent(_)
        )));
        agent.join().unwrap();
    }

    #[test]
    fn retry_advances_to_the_next_agent_identity() {
        unsafe {
            let first_key = seeded_ed25519_private_key(3);
            let second_key = seeded_ed25519_private_key(4);
            let expected_first = first_key.public_key().to_bytes().unwrap();
            let expected_second = second_key.public_key().to_bytes().unwrap();

            let (first, second) = exercise_agent_retry(
                vec![first_key, second_key],
                &["ssh-ed25519"],
            );

            assert_eq!(first.key.as_ref(), expected_first);
            assert_eq!(second.key.as_ref(), expected_second);
            assert_eq!(second.username.as_ref(), b"alice");
        }
    }

    #[test]
    fn retry_falls_back_to_another_algorithm_for_the_same_rsa_key() {
        unsafe {
            let private_key = rsa_private_key();
            let expected_key = private_key.public_key().to_bytes().unwrap();

            let (first, second) = exercise_agent_retry(
                vec![private_key],
                &["rsa-sha2-512", "rsa-sha2-256"],
            );

            assert_eq!(first.key.as_ref(), expected_key);
            assert_eq!(second.key.as_ref(), expected_key);
            assert_eq!(first.sigtype.as_ref(), b"rsa-sha2-512");
            assert_eq!(second.sigtype.as_ref(), b"rsa-sha2-256");
        }
    }

    #[test]
    fn retry_finished_binds_the_rejected_attempt_and_server_context() {
        unsafe {
            let session_key = [0x42; SANON_SESSION_KEY_LEN];
            let transcript_hash = [0x24; 32];
            let initiator_nonce = [0x11; HANDSHAKE_NONCE_LEN];
            let rejected = b"encrypted first userauth";
            let server_context = b"sealed server context";
            let retry_hash = userauth_retry_transcript_hash(
                &transcript_hash,
                rejected,
                server_context,
            )
            .unwrap();
            let finished = make_finished(
                &session_key,
                ACCEPTOR_RETRY_FINISHED_LABEL,
                &retry_hash,
                &initiator_nonce,
            )
            .unwrap();

            for changed_hash in [
                userauth_retry_transcript_hash(
                    &transcript_hash,
                    b"different userauth",
                    server_context,
                )
                .unwrap(),
                userauth_retry_transcript_hash(
                    &transcript_hash,
                    rejected,
                    b"different server context",
                )
                .unwrap(),
            ] {
                assert!(!verify_finished(
                    &finished,
                    &session_key,
                    ACCEPTOR_RETRY_FINISHED_LABEL,
                    &changed_hash,
                    &initiator_nonce,
                ));
            }
        }
    }

    #[test]
    fn authenticated_retry_fails_when_candidates_are_exhausted() {
        unsafe {
            let session_key = [0x42; SANON_SESSION_KEY_LEN];
            let initiator_public = [0x11; X25519_PUBLIC_LEN];
            let acceptor_public = [0x22; X25519_PUBLIC_LEN];
            let initiator_nonce = [0x33; HANDSHAKE_NONCE_LEN];
            let acceptor_nonce = [0x44; HANDSHAKE_NONCE_LEN];
            let acceptor_name = b"sshkey@host.example";
            let server_context = b"sealed server context";
            let rejected = b"encrypted final userauth";
            let transcript_hash = handshake_transcript_hash(
                b"ssh-ed25519",
                b"ssh-ed25519",
                &initiator_public,
                &acceptor_public,
                &initiator_nonce,
                &acceptor_nonce,
                acceptor_name,
                b"",
            )
            .unwrap();
            let retry_hash = userauth_retry_transcript_hash(
                &transcript_hash,
                rejected,
                server_context,
            )
            .unwrap();
            let finished = make_finished(
                &session_key,
                ACCEPTOR_RETRY_FINISHED_LABEL,
                &retry_hash,
                &initiator_nonce,
            )
            .unwrap();
            let token = rasn::der::decode::<SshKeyToken>(
                &userauth_retry_token(
                    b"ssh-ed25519",
                    EncCtx::new(OctetString::from(server_context.as_slice())),
                    finished,
                )
                .unwrap(),
            )
            .unwrap();
            let mut ctx = SshKeyCtx::new(true);
            ctx.complete = true;
            ctx.public_key = Some(initiator_public);
            ctx.peer_public_key = Some(acceptor_public);
            ctx.set_session_key(session_key);
            ctx.initiator_sigtypes = b"ssh-ed25519".to_vec();
            ctx.acceptor_sigtypes = b"ssh-ed25519".to_vec();
            ctx.server_context = Some(server_context.to_vec());
            ctx.acceptor_name = Some(acceptor_name.to_vec());
            ctx.client_policy = Some(test_client_policy(
                PathBuf::from("/nonexistent"),
                &["ssh-ed25519"],
            ));
            ctx.initiator_nonce = Some(initiator_nonce.to_vec());
            ctx.acceptor_nonce = Some(acceptor_nonce.to_vec());
            ctx.userauth_candidates_ready = true;
            ctx.pending_userauth = Some(rejected.to_vec());

            let mut output = gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            };
            let mut minor = 0;
            assert_eq!(
                continue_userauth_after_retry(
                    &mut minor,
                    &mut ctx,
                    &token,
                    b"",
                    &mut output,
                    ptr::null_mut(),
                ),
                GSS_S_UNAUTHORIZED
            );
            assert_eq!(minor, libc::EACCES as OM_uint32);
            assert!(!ctx.complete);
            assert!(ctx.pending_userauth.is_none());
            assert_eq!(output.length, 0);
            assert!(output.value.is_null());
        }
    }

    #[test]
    fn authorization_file_matches_openssh_strict_modes() {
        let (_temp, account, keys, path) =
            authorization_file_fixture("strict-modes");

        assert!(open_authorization_file(&path, &account, true).is_some());

        fs::set_permissions(&keys, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(open_authorization_file(&path, &account, true).is_none());
        assert!(open_authorization_file(&path, &account, false).is_some());

        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(open_authorization_file(&path, &account, true).is_none());
        assert!(open_authorization_file(&path, &account, false).is_some());

        assert!(open_authorization_file(
            path.parent().unwrap(),
            &account,
            false
        )
        .is_none());
    }

    #[test]
    fn authorization_file_is_read_through_checked_descriptor() {
        let (_temp, account, _keys, path) =
            authorization_file_fixture("descriptor");
        let mut file = open_authorization_file(&path, &account, true).unwrap();
        let opened_path = path.with_extension("opened");

        fs::rename(&path, &opened_path).unwrap();
        fs::write(&path, b"replacement authorized key\n").unwrap();

        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text, "original authorized key\n");
    }

    fn parsed_authorized_key(options: &str) -> AuthorizedKeyEntry {
        parse_authorized_key_line(&format!("{options}ssh-ed25519 AAAAC3Nz"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn authorized_key_options_fail_closed() {
        let now = 1_893_542_400;

        assert!(authorized_key_options_allow(
            &parsed_authorized_key(""),
            now
        ));
        assert!(authorized_key_options_allow(
            &parsed_authorized_key("expiry-time=\"20300102000000Z\" "),
            now
        ));
        assert!(!authorized_key_options_allow(
            &parsed_authorized_key("expiry-time=\"20290102000000Z\" "),
            now
        ));

        for options in [
            "from=\"10.0.0.0/8\" ",
            "cert-authority ",
            "command=\"echo restricted command\" ",
            "restrict ",
            "future-option=\"value\" ",
        ] {
            assert!(
                !authorized_key_options_allow(
                    &parsed_authorized_key(options),
                    now
                ),
                "accepted unsupported option {options}"
            );
        }
    }

    fn server_context_with_issued_at(
        issued_at: Integer,
    ) -> SshKeyServerContext {
        SshKeyServerContext::new(
            None,
            OctetString::from(vec![1; X25519_PUBLIC_LEN]),
            None,
            None,
            OctetString::from_static(SIG_ALGS),
            Some(OctetString::from(vec![2; X25519_SHARED_LEN])),
            None,
            OctetString::from(vec![3; HANDSHAKE_NONCE_LEN]),
            OctetString::from_static(b"sshkey@host.example"),
            issued_at,
        )
    }

    #[test]
    fn exported_name_round_trips() {
        let value = b"alice";
        let token =
            gss_mech_builder::export_name_token(&SSHKEY_OID_ELEMENTS, value)
                .unwrap();

        assert_eq!(
            gss_mech_builder::import_exported_name_token(
                &token,
                &SSHKEY_OID_ELEMENTS
            )
            .unwrap(),
            value
        );

        let mut trailing = token;
        trailing.push(0);
        assert!(gss_mech_builder::import_exported_name_token(
            &trailing,
            &SSHKEY_OID_ELEMENTS
        )
        .is_err());
    }

    #[test]
    fn completed_context_source_name_is_requested_username() {
        let mut context = SshKeyCtx::new(false);
        context.complete = true;
        context.display_name = b"alice".to_vec();
        context.authorized_user = Some(b"alice".to_vec());

        let source = SshKeyMechanism::source_name(&context).unwrap();
        assert_eq!(source.value, b"alice");
        assert_eq!(
            source.authorized_user.as_deref(),
            Some(b"alice".as_slice())
        );
    }

    #[test]
    fn default_credential_acquisition_remains_available() {
        let credential = SshKeyMechanism::acquire_cred(
            None,
            &[SSHKEY_OID_ELEMENTS.to_vec()],
            1,
        )
        .unwrap();

        assert_eq!(credential.usage, 1);
        assert!(SshKeyMechanism::credential_name(&credential).is_none());
    }

    #[test]
    fn named_initiator_credential_acquisition_is_unavailable() {
        let name = SshKeyName {
            value: b"requested-credential".to_vec(),
            authorized_user: None,
        };
        let expected = Status::new(GSS_S_UNAVAILABLE, ENOTSUP);

        assert!(matches!(
            SshKeyMechanism::acquire_cred(
                Some(&name),
                &[SSHKEY_OID_ELEMENTS.to_vec()],
                1,
            ),
            Err(status) if status == expected
        ));
        assert!(matches!(
            SshKeyMechanism::add_cred(
                None,
                Some(&name),
                &SSHKEY_OID_ELEMENTS,
                1,
            ),
            Err(status) if status == expected
        ));
        assert!(matches!(
            SshKeyMechanism::acquire_cred(
                Some(&name),
                &[SSHKEY_OID_ELEMENTS.to_vec()],
                GSS_C_BOTH,
            ),
            Err(status) if status == expected
        ));
    }

    #[test]
    fn named_acceptor_credential_acquisition_remains_available() {
        let name = SshKeyName {
            value: b"sshkey@localhost".to_vec(),
            authorized_user: None,
        };
        let credential = SshKeyMechanism::acquire_cred(
            Some(&name),
            &[SSHKEY_OID_ELEMENTS.to_vec()],
            2,
        )
        .unwrap();

        assert_eq!(credential.usage, 2);
        assert!(credential
            .name
            .as_ref()
            .is_some_and(|value| value.value == name.value));
    }

    #[test]
    fn final_token_requires_user_authentication() {
        let token = SshKeyToken::new(
            token_status(SSH_KEY_COMPLETE),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(matches!(required_userauth(&token), Err(GSS_S_UNAUTHORIZED)));
    }

    #[test]
    fn context_token_rejects_oversized_input_before_decoding() {
        let input = vec![0; MAX_CONTEXT_TOKEN_LEN + 1];

        assert!(decode_context_token_bytes(&input).is_none());
    }

    #[test]
    fn client_resolution_uses_effective_host_and_final_pass() {
        let config = ClientConfig::parse_str(
            "Host alias\n\
                 HostName real.example\n\
             Match host real.example\n\
                 User matched\n\
             Match final\n\
                 IdentityFile ~/.ssh/id_final\n",
        );
        let defaults = client_defaults("local");

        let resolved = config
            .resolve_connection_with_context(
                ConnectionResolveContext {
                    original_host: "alias",
                    local_user: Some("local"),
                },
                &ClientOptions::default(),
                &defaults,
                ClientConfigContext::empty(),
            )
            .unwrap();

        assert_eq!(resolved.host, "real.example");
        assert_eq!(resolved.options.user.as_deref(), Some("matched"));
        assert!(resolved
            .options
            .identity_files
            .iter()
            .any(|path| path.ends_with("/.ssh/id_final")));
    }

    #[test]
    fn unsupported_hostname_canonicalization_fails_closed() {
        let config = ClientConfig::parse_str(
            "Host alias\n\
                 CanonicalizeHostname yes\n",
        );
        let defaults = client_defaults("local");

        let error = config
            .resolve_connection_with_context(
                ConnectionResolveContext {
                    original_host: "alias",
                    local_user: Some("local"),
                },
                &ClientOptions::default(),
                &defaults,
                ClientConfigContext::empty(),
            )
            .unwrap_err();

        assert!(error.contains("unavailable hostname canonicalization"));
    }

    #[test]
    fn unsupported_host_trust_hooks_fail_closed() {
        let mut options = ClientOptions {
            revoked_host_keys: Some("/etc/ssh/revoked-host-keys".to_string()),
            ..ClientOptions::default()
        };
        assert!(validate_supported_host_trust_options(&options)
            .unwrap_err()
            .contains("RevokedHostKeys"));

        options.revoked_host_keys = Some("none".to_string());
        options.known_hosts_command = Some(vec!["/bin/check-host".to_string()]);
        assert!(validate_supported_host_trust_options(&options)
            .unwrap_err()
            .contains("KnownHostsCommand"));

        options.known_hosts_command = Some(Vec::new());
        validate_supported_host_trust_options(&options).unwrap();
    }

    #[test]
    fn host_key_policy_enforces_algorithm_and_rsa_size() {
        use ssh_key::public::{KeyData, RsaPublicKey};
        use ssh_key::Mpint;

        let ed25519 = ed25519_private_key().public_key().to_bytes().unwrap();
        let ed25519_algorithms = vec!["ssh-ed25519".to_string()];
        assert!(host_key_meets_policy(
            &ed25519,
            b"ssh-ed25519",
            &ed25519_algorithms,
            4096,
        ));
        assert!(!host_key_meets_policy(
            &ed25519,
            b"ssh-ed25519",
            &["rsa-sha2-512".to_string()],
            0,
        ));

        let mut modulus = vec![0; 256];
        modulus[0] = 0x80;
        let rsa = PublicKey::new(
            KeyData::Rsa(RsaPublicKey {
                e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
                n: Mpint::from_positive_bytes(&modulus).unwrap(),
            }),
            "",
        )
        .to_bytes()
        .unwrap();
        let rsa_algorithms = vec!["rsa-sha2-512".to_string()];
        assert!(host_key_meets_policy(
            &rsa,
            b"rsa-sha2-512",
            &rsa_algorithms,
            2048,
        ));
        assert!(!host_key_meets_policy(
            &rsa,
            b"rsa-sha2-512",
            &rsa_algorithms,
            3072,
        ));
    }

    #[test]
    fn user_key_policy_enforces_required_rsa_size() {
        use ssh_key::public::{KeyData, RsaPublicKey};
        use ssh_key::Mpint;

        let mut modulus = vec![0; 256];
        modulus[0] = 0x80;
        let rsa = PublicKey::new(
            KeyData::Rsa(RsaPublicKey {
                e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
                n: Mpint::from_positive_bytes(&modulus).unwrap(),
            }),
            "",
        )
        .to_bytes()
        .unwrap();
        let mut options = ServerOptions {
            pubkey_accepted_algorithms: Some(vec!["rsa-sha2-512".to_string()]),
            required_rsa_size: Some(2048),
            ..ServerOptions::default()
        };

        validate_user_key_policy(&rsa, b"rsa-sha2-512", &options).unwrap();
        options.required_rsa_size = Some(3072);
        assert!(validate_user_key_policy(&rsa, b"rsa-sha2-512", &options)
            .unwrap_err()
            .contains("RequiredRSASize"));

        let ed25519 = ed25519_private_key().public_key().to_bytes().unwrap();
        options.pubkey_accepted_algorithms =
            Some(vec!["ssh-ed25519".to_string()]);
        validate_user_key_policy(&ed25519, b"ssh-ed25519", &options).unwrap();
    }

    #[test]
    fn server_group_policy_uses_supplied_memberships() {
        let config = ServerConfig::parse_str(
            "AllowGroups ops*\n\
             DenyGroups blocked\n\
             Match Group administrators\n\
                 RequiredRSASize 4096\n",
        );
        let account = LocalAccount {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
        };
        let allowed =
            vec!["ops-team".to_string(), "administrators".to_string()];
        let blocked = vec!["ops-team".to_string(), "blocked".to_string()];
        let other = vec!["users".to_string()];

        let options = resolve_server_options(
            &config,
            "alice",
            &account,
            Some(&allowed),
            None,
        )
        .unwrap();
        assert_eq!(options.required_rsa_size, Some(4096));
        assert!(resolve_server_options(
            &config,
            "alice",
            &account,
            Some(&blocked),
            None,
        )
        .unwrap_err()
        .contains("group policy"));
        assert!(resolve_server_options(
            &config,
            "alice",
            &account,
            Some(&other),
            None,
        )
        .unwrap_err()
        .contains("group policy"));
        assert!(
            resolve_server_options(&config, "alice", &account, None, None,)
                .unwrap_err()
                .contains("Match condition")
        );
    }

    #[test]
    fn server_source_policy_rejects_hostnames_and_uses_numeric_addresses() {
        let account = LocalAccount {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
        };
        let groups = vec!["users".to_string()];
        let hostname = ServerConfig::parse_str(
            "Match Host client.example\n\
                 RequiredRSASize 4096\n",
        );
        assert!(resolve_server_options(
            &hostname,
            "alice",
            &account,
            Some(&groups),
            Some("192.0.2.10"),
        )
        .unwrap_err()
        .contains("Match condition"));

        let address = ServerConfig::parse_str(
            "Match Address 192.0.2.0/24\n\
                 RequiredRSASize 4096\n",
        );
        let options = resolve_server_options(
            &address,
            "alice",
            &account,
            Some(&groups),
            Some("192.0.2.10"),
        )
        .unwrap();
        assert_eq!(options.required_rsa_size, Some(4096));
        assert!(resolve_server_options(
            &address,
            "alice",
            &account,
            Some(&groups),
            None,
        )
        .unwrap_err()
        .contains("Match condition"));

        let hostname_user =
            ServerConfig::parse_str("DenyUsers alice@client.example\n");
        assert!(resolve_server_options(
            &hostname_user,
            "alice",
            &account,
            Some(&groups),
            Some("192.0.2.10"),
        )
        .unwrap_err()
        .contains("source context"));

        let address_user =
            ServerConfig::parse_str("AllowUsers alice@192.0.2.0/24\n");
        resolve_server_options(
            &address_user,
            "alice",
            &account,
            Some(&groups),
            Some("192.0.2.10"),
        )
        .unwrap();
        assert!(resolve_server_options(
            &address_user,
            "alice",
            &account,
            Some(&groups),
            None,
        )
        .unwrap_err()
        .contains("source context"));
    }

    #[test]
    fn nss_group_lookup_includes_the_primary_group() {
        let username = env::var("USER").expect("USER is required by tests");
        let account = local_account(&username).expect("USER must exist");
        let primary =
            group_name(account.gid).expect("primary group must exist");
        let groups =
            local_account_groups(&username, &account).expect("group lookup");

        assert!(groups.iter().any(|group| group == &primary));
    }

    #[test]
    fn account_source_patterns_distinguish_addresses_and_hostnames() {
        assert_eq!(
            account_pattern_match(
                "alice@192.0.2.*",
                "alice",
                Some("192.0.2.10")
            ),
            AccountPatternMatch::Yes
        );
        assert_eq!(
            account_pattern_match(
                "alice@192.0.2.*",
                "alice",
                Some("198.51.100.10")
            ),
            AccountPatternMatch::No
        );
        assert_eq!(
            account_pattern_match("alice@192.0.2.*", "alice", None),
            AccountPatternMatch::Unresolved
        );
        assert_eq!(
            account_pattern_match(
                "alice@client.example",
                "alice",
                Some("192.0.2.10")
            ),
            AccountPatternMatch::Unresolved
        );
        assert_eq!(
            account_pattern_match(
                "bob@client.example",
                "alice",
                Some("192.0.2.10")
            ),
            AccountPatternMatch::No
        );
        assert_eq!(
            account_pattern_match("alice", "alice", None),
            AccountPatternMatch::Yes
        );
    }

    #[test]
    fn context_token_rejects_oversized_nested_field() {
        let token = SshKeyToken::new(
            token_status(SSH_KEY_CONTINUE_NEEDED),
            None,
            None,
            None,
            None,
            Some(EncCtx::new(OctetString::from(vec![
                0;
                MAX_ENCRYPTED_FIELD_LEN
                    + 1
            ]))),
            None,
        );
        let encoded = rasn::der::encode(&token).unwrap();
        assert!(encoded.len() < MAX_CONTEXT_TOKEN_LEN);

        assert!(decode_context_token_bytes(&encoded).is_none());
    }

    #[test]
    fn decrypted_userauth_fields_are_bounded() {
        let userauth = SshKeyUserAuth::new(
            OctetString::from(vec![b'a'; MAX_NAME_LEN + 1]),
            OctetString::from_static(b"ssh-ed25519"),
            OctetString::from_static(b"key"),
            OctetString::from_static(b"ssh-ed25519"),
            OctetString::from_static(b"signature"),
        );

        assert!(!validate_userauth_fields(&userauth));
    }

    #[test]
    fn typed_context_fields_are_staged_by_role() {
        let private_key = ed25519_private_key();
        let host_key = private_key.public_key().to_bytes().unwrap();
        let user_name = CString::new("user").unwrap();
        let host_key_name = CString::new("host-key").unwrap();
        let peer_name = CString::new("peer-address").unwrap();
        let user = b"alice";
        let peer = b"192.0.2.10";
        let client = [
            gss_sshkey_context_field {
                name: user_name.as_ptr(),
                value: gss_buffer_desc {
                    length: user.len(),
                    value: user.as_ptr().cast_mut().cast(),
                },
            },
            gss_sshkey_context_field {
                name: host_key_name.as_ptr(),
                value: gss_buffer_desc {
                    length: host_key.len(),
                    value: host_key.as_ptr().cast_mut().cast(),
                },
            },
        ];
        let server = [gss_sshkey_context_field {
            name: peer_name.as_ptr(),
            value: gss_buffer_desc {
                length: peer.len(),
                value: peer.as_ptr().cast_mut().cast(),
            },
        }];
        let mut minor = 99;

        unsafe {
            assert_eq!(
                gss_sshkey_set_context_fields(
                    &mut minor,
                    CONTEXT_CLIENT,
                    CONTEXT_VERSION,
                    client.as_ptr(),
                    client.len(),
                ),
                GSS_S_COMPLETE
            );
            assert_eq!(
                gss_sshkey_set_context_fields(
                    &mut minor,
                    CONTEXT_SERVER,
                    CONTEXT_VERSION,
                    server.as_ptr(),
                    server.len(),
                ),
                GSS_S_COMPLETE
            );
        }

        let client = take_client_context();
        assert_eq!(client.user.as_deref(), Some("alice"));
        assert_eq!(
            client.verified_host_key.as_deref(),
            Some(host_key.as_slice())
        );
        let server = take_server_context();
        assert_eq!(server.peer_address.as_deref(), Some("192.0.2.10"));
        assert!(take_client_context().user.is_none());
        assert!(take_server_context().peer_address.is_none());
    }

    #[test]
    fn typed_server_context_rejects_non_numeric_peer_address() {
        let peer_name = CString::new("peer-address").unwrap();
        let peer = b"client.example";
        let server = [gss_sshkey_context_field {
            name: peer_name.as_ptr(),
            value: gss_buffer_desc {
                length: peer.len(),
                value: peer.as_ptr().cast_mut().cast(),
            },
        }];
        let mut minor = 0;

        unsafe {
            assert_eq!(
                gss_sshkey_set_context_fields(
                    &mut minor,
                    CONTEXT_SERVER,
                    CONTEXT_VERSION,
                    server.as_ptr(),
                    server.len(),
                ),
                GSS_S_FAILURE
            );
        }
        assert_eq!(minor, EINVAL);
    }

    #[test]
    fn x25519_session_keys_match() {
        unsafe {
            let (initiator_key, initiator_public) =
                generate_x25519_keypair().unwrap();
            let (acceptor_key, acceptor_public) =
                generate_x25519_keypair().unwrap();

            let initiator_shared =
                x25519_shared_secret(&initiator_key, &acceptor_public).unwrap();
            let acceptor_shared =
                x25519_shared_secret(&acceptor_key, &initiator_public).unwrap();
            assert_eq!(initiator_shared, acceptor_shared);

            let initiator_session = derive_anonymous_session_key(
                &initiator_shared,
                &initiator_public,
                &acceptor_public,
                0,
                &[],
            )
            .unwrap();
            let acceptor_session = derive_anonymous_session_key(
                &acceptor_shared,
                &initiator_public,
                &acceptor_public,
                0,
                &[],
            )
            .unwrap();
            assert_eq!(initiator_session, acceptor_session);
        }
    }

    #[test]
    fn sp800_108_kdf_matches_sanon_vector() {
        unsafe {
            let shared: [u8; X25519_SHARED_LEN] =
                core::array::from_fn(|i| i as u8);
            let initiator_public: [u8; X25519_PUBLIC_LEN] =
                core::array::from_fn(|i| (i + 32) as u8);
            let acceptor_public: [u8; X25519_PUBLIC_LEN] =
                core::array::from_fn(|i| (i + 64) as u8);
            let expected = [
                0x70, 0xea, 0x75, 0xb3, 0x5a, 0x1d, 0x5e, 0x3e, 0x0f, 0x77,
                0x46, 0x5c, 0xd9, 0x7e, 0x42, 0xf3,
            ];

            let key = derive_anonymous_session_key(
                &shared,
                &initiator_public,
                &acceptor_public,
                0x1020_3040,
                b"cb",
            )
            .unwrap();
            assert_eq!(*key, expected);
        }
    }

    #[test]
    fn protocol_vectors_match_the_specification() {
        const USERAUTH_DER: &str = "302c8005616c696365810b7373682d6564\
3235353139820400010203830b7373682d656432353531398403040506";
        const HANDSHAKE_HASH: &str =
            "5c85ea298b49f648864af914d4288b3e1c36047ffafc8c8b48d5076d401b1cd3";
        const USER_SIGNATURE_INPUT_HASH: &str =
            "f33be51710e22ab7abf383c87f5ca999f9f104d5a85267d3b67ed3057d4450ff";
        let userauth = SshKeyUserAuth::new(
            OctetString::from_static(b"alice"),
            OctetString::from_static(b"ssh-ed25519"),
            OctetString::from_static(&[0, 1, 2, 3]),
            OctetString::from_static(b"ssh-ed25519"),
            OctetString::from_static(&[4, 5, 6]),
        );
        let der = rasn::der::encode(&userauth).unwrap();
        let initiator_public = core::array::from_fn(|i| i as u8);
        let acceptor_public = core::array::from_fn(|i| (i + 0x20) as u8);
        let initiator_nonce: [u8; HANDSHAKE_NONCE_LEN] =
            core::array::from_fn(|i| (i + 0x40) as u8);
        let acceptor_nonce: [u8; HANDSHAKE_NONCE_LEN] =
            core::array::from_fn(|i| (i + 0x60) as u8);
        let initiator_sigtypes = b"ssh-ed25519,rsa-sha2-512";
        let acceptor_sigtypes = b"ssh-ed25519";
        let acceptor_name = b"sshkey@host.example";
        let channel_bindings = [0];
        let handshake = handshake_transcript_hash(
            initiator_sigtypes,
            acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            acceptor_name,
            &channel_bindings,
        )
        .unwrap();
        let user = user_signature_input(
            initiator_sigtypes,
            acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            acceptor_name,
            b"alice",
            b"ssh-ed25519",
            &[0, 1, 2, 3],
            b"ssh-ed25519",
            &channel_bindings,
        )
        .unwrap();

        assert_eq!(test_hex(der), USERAUTH_DER);
        assert_eq!(test_hex(handshake), HANDSHAKE_HASH);
        assert_eq!(test_hex(Sha256::digest(user)), USER_SIGNATURE_INPUT_HASH);

        let draft =
            include_str!("../draft-dowdeswell-kitten-gss-sshkey-00.xml");
        let asn1 = include_str!("../sshkey.asn1");
        for vector in [USERAUTH_DER, HANDSHAKE_HASH, USER_SIGNATURE_INPUT_HASH]
        {
            assert!(draft.contains(vector));
        }
        assert!(draft.contains("aes128-cts-hmac-sha256-128"));
        assert!(!draft.contains("aes256-gcm-sha256"));
        assert!(asn1.contains(
            "the accepted GSS source name is the exact\n-- requested username"
        ));
    }

    #[test]
    fn private_fields_use_the_documented_encryption_profile() {
        unsafe {
            let session_key = [0x31; SANON_SESSION_KEY_LEN];
            let plaintext = b"DER private field";
            let mut ciphertext =
                seal_userauth(&session_key, plaintext).unwrap();

            assert_eq!(
                ciphertext.len(),
                plaintext.len()
                    + MESSAGE_PROTECTION_CONFOUNDER_LEN
                    + MESSAGE_PROTECTION_CHECKSUM_LEN
            );
            assert_eq!(
                open_userauth(&session_key, &ciphertext).as_deref(),
                Some(plaintext.as_slice())
            );

            let last = ciphertext.len() - 1;
            ciphertext[last] ^= 1;
            assert!(open_userauth(&session_key, &ciphertext).is_none());
        }
    }

    #[test]
    fn initial_token_carries_public_key() {
        let public_key = [7u8; X25519_PUBLIC_LEN];
        let nonce = vec![9u8; HANDSHAKE_NONCE_LEN];
        let acceptor_name = b"sshkey@host.example";
        let output =
            initial_context_token(&public_key, &nonce, acceptor_name).unwrap();
        let inner = decapsulate_initial_token(&output).unwrap();
        let token = rasn::der::decode::<SshKeyToken>(inner).unwrap();

        assert!(token_has_status(&token, SSH_KEY_CONTINUE_NEEDED));
        let kex = token.kex.as_ref().unwrap();
        assert_eq!(kex_public_key(kex), Some(public_key));
        assert_eq!(kex_nonce(kex), Some(nonce));
        assert_eq!(
            kex_acceptor_name(kex).as_deref(),
            Some(acceptor_name.as_slice())
        );
        assert!(kex_octets_match(&kex.kextype, KEX_ALG));
        assert!(kex_octets_match(&kex.enctype, ENC_ALG));
    }

    #[test]
    fn authentication_transcripts_bind_the_acceptor_name() {
        let initiator_public = [1; X25519_PUBLIC_LEN];
        let acceptor_public = [2; X25519_PUBLIC_LEN];
        let initiator_nonce = [3; HANDSHAKE_NONCE_LEN];
        let acceptor_nonce = [4; HANDSHAKE_NONCE_LEN];
        let first_name = b"sshkey@first.example";
        let second_name = b"sshkey@second.example";
        let bindings = b"channel bindings";

        let first_host = host_signature_input(
            SIG_ALGS,
            SIG_ALGS,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            first_name,
            bindings,
        )
        .unwrap();
        let second_host = host_signature_input(
            SIG_ALGS,
            SIG_ALGS,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            second_name,
            bindings,
        )
        .unwrap();
        assert_ne!(first_host, second_host);

        let first_user = user_signature_input(
            SIG_ALGS,
            SIG_ALGS,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            first_name,
            b"alice",
            b"ssh-ed25519",
            b"key",
            b"ssh-ed25519",
            bindings,
        )
        .unwrap();
        let second_user = user_signature_input(
            SIG_ALGS,
            SIG_ALGS,
            &initiator_public,
            &acceptor_public,
            &initiator_nonce,
            &acceptor_nonce,
            second_name,
            b"alice",
            b"ssh-ed25519",
            b"key",
            b"ssh-ed25519",
            bindings,
        )
        .unwrap();
        assert_ne!(first_user, second_user);

        assert_ne!(
            handshake_transcript_hash(
                SIG_ALGS,
                SIG_ALGS,
                &initiator_public,
                &acceptor_public,
                &initiator_nonce,
                &acceptor_nonce,
                first_name,
                bindings,
            ),
            handshake_transcript_hash(
                SIG_ALGS,
                SIG_ALGS,
                &initiator_public,
                &acceptor_public,
                &initiator_nonce,
                &acceptor_nonce,
                second_name,
                bindings,
            )
        );
    }

    #[test]
    fn acceptor_credential_names_are_canonicalized() {
        assert_eq!(
            canonicalize_acceptor_credential_name(b"sshkey@HOST.EXAMPLE."),
            Ok(b"sshkey@host.example".to_vec())
        );
        assert!(canonicalize_acceptor_credential_name(b"missing-host").is_err());
    }

    #[test]
    fn ssh_signature_blob_round_trips_and_rejects_tampering() {
        let private_key = ed25519_private_key();
        let input = b"gss-sshkey transcript bytes";
        let (keytype, key, sigtype, mut sig) =
            sign_ssh_data(&private_key, input).unwrap();

        assert_eq!(keytype, b"ssh-ed25519");
        assert_eq!(sigtype, b"ssh-ed25519");
        assert!(verify_ssh_signature(&key, &sigtype, &sig, input));

        *sig.last_mut().unwrap() ^= 0x01;
        assert!(!verify_ssh_signature(&key, &sigtype, &sig, input));
    }

    #[test]
    fn direct_rsa_private_key_signing_is_disabled() {
        use ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
        use ssh_key::public::RsaPublicKey;
        use ssh_key::Mpint;

        let algorithm = Algorithm::Rsa { hash: None };
        let mut modulus = vec![0; 256];
        modulus[0] = 0x80;
        let rsa = PrivateKey::new(
            KeypairData::Rsa(RsaKeypair {
                public: RsaPublicKey {
                    e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
                    n: Mpint::from_positive_bytes(&modulus).unwrap(),
                },
                private: RsaPrivateKey {
                    d: Mpint::from_positive_bytes(&[1]).unwrap(),
                    iqmp: Mpint::from_positive_bytes(&[1]).unwrap(),
                    p: Mpint::from_positive_bytes(&[1]).unwrap(),
                    q: Mpint::from_positive_bytes(&[1]).unwrap(),
                },
            }),
            "",
        )
        .unwrap();

        assert!(!direct_private_key_signing_supported(&algorithm));
        assert!(sign_ssh_data(&rsa, b"must not be signed").is_none());
        assert!(direct_private_key_signing_supported(&Algorithm::Ed25519));
        assert_eq!(
            signature_algorithms(&algorithm),
            vec![b"rsa-sha2-512".to_vec(), b"rsa-sha2-256".to_vec()]
        );
    }

    #[test]
    fn server_context_age_policy_is_enforced() {
        let now = 1_700_000_000;
        let context =
            server_context_with_issued_at(server_context_issued_at(now));

        assert!(server_context_is_current(&context, now));
        assert!(server_context_is_current(
            &context,
            now + SERVER_CONTEXT_MAX_AGE_SECONDS - 1,
        ));
        assert!(!server_context_is_current(
            &context,
            now + SERVER_CONTEXT_MAX_AGE_SECONDS,
        ));

        let tolerated_future = server_context_with_issued_at(Integer::from(
            now + SERVER_CONTEXT_CLOCK_SKEW_SECONDS,
        ));
        assert!(server_context_is_current(&tolerated_future, now));

        let future = server_context_with_issued_at(Integer::from(
            now + SERVER_CONTEXT_CLOCK_SKEW_SECONDS + 1,
        ));
        assert!(!server_context_is_current(&future, now));

        let negative = server_context_with_issued_at(Integer::from(-1));
        assert!(!server_context_is_current(&negative, now));

        let overflow = server_context_with_issued_at(Integer::from(u64::MAX));
        assert!(!server_context_is_current(&overflow, now));
    }

    #[test]
    fn agent_identity_parser_reads_public_keys() {
        let private_key = ed25519_private_key();
        let key = private_key.public_key().to_bytes().unwrap();
        let mut payload = vec![SSH2_AGENT_IDENTITIES_ANSWER];

        push_ssh_u32(&mut payload, 1);
        push_ssh_string(&mut payload, &key).unwrap();
        push_ssh_string(&mut payload, b"user@example.com").unwrap();

        let identities = parse_agent_identities(&payload).unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].key, key);
        assert_eq!(identities[0].public_key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn agent_signature_flags_match_openssh_rsa_values() {
        assert_eq!(agent_signature_flags(b"rsa-sha2-256"), 0x02);
        assert_eq!(agent_signature_flags(b"rsa-sha2-512"), 0x04);
        assert_eq!(agent_signature_flags(b"ssh-ed25519"), 0);
    }

    #[test]
    fn finished_mac_binds_role_and_peer_nonce() {
        unsafe {
            let session_key = [0x42u8; SANON_SESSION_KEY_LEN];
            let transcript_hash = [0x24u8; 32];
            let peer_nonce = vec![0x11u8; HANDSHAKE_NONCE_LEN];
            let other_nonce = vec![0x22u8; HANDSHAKE_NONCE_LEN];
            let finished = make_finished(
                &session_key,
                INITIATOR_FINISHED_LABEL,
                &transcript_hash,
                &peer_nonce,
            )
            .unwrap();

            assert!(verify_finished(
                &finished,
                &session_key,
                INITIATOR_FINISHED_LABEL,
                &transcript_hash,
                &peer_nonce,
            ));
            assert!(!verify_finished(
                &finished,
                &session_key,
                ACCEPTOR_FINISHED_LABEL,
                &transcript_hash,
                &peer_nonce,
            ));
            assert!(!verify_finished(
                &finished,
                &session_key,
                INITIATOR_FINISHED_LABEL,
                &transcript_hash,
                &other_nonce,
            ));
        }
    }
}
