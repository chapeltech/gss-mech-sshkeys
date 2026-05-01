#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use asn1::sshkey::{
    EncCtx, EncSshKeyUserAuth, SshKeyFinished, SshKeyHostAuth, SshKeyKEX,
    SshKeyServerContext, SshKeyStatus, SshKeyToken, SshKeyUserAuth,
};
use gss_mech_builder::sys::*;
use gss_mech_builder::{
    clear_buffer, set_buffer_bytes, set_minor, Rfc4121Context, Status,
};
use hmac::{Hmac, Mac};
use rasn::types::{Integer, OctetString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use ssh_key::{
    known_hosts::{HostPatterns, KnownHosts, Marker},
    Algorithm, PrivateKey, PublicKey, Signature as SshSignature,
};

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
struct EVP_CIPHER {
    _private: [u8; 0],
}

#[repr(C)]
struct EVP_CIPHER_CTX {
    _private: [u8; 0],
}

#[repr(C)]
struct EVP_MD {
    _private: [u8; 0],
}

const EVP_PKEY_X25519: c_int = 1034;
const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

const SSH_KEY_COMPLETE: u8 = 1;
const SSH_KEY_CONTINUE_NEEDED: u8 = 2;

static SSHKEY_OID_ELEMENTS: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01];

const KEX_ALG: &[u8] = b"curve25519-sha256";
const ENC_ALG: &[u8] = b"aes256-gcm-sha256";
const SIG_ALGS: &[u8] = b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss";
const SANON_KDF_LABEL: &[u8] = b"sanon-x25519";
const SANON_SESSION_KEY_LEN: usize = 16;
const X25519_PUBLIC_LEN: usize = 32;
const X25519_SHARED_LEN: usize = 32;
const CONTEXT_KEY_LEN: usize = 32;
const CFX_HEADER_LEN: usize = rfc4121::HEADER_LEN;
const CFX_HMAC_LEN: usize = 32;
const CFX_GCM_TAG_LEN: usize = 16;
const CFX_GCM_NONCE_LEN: usize = 12;
const HANDSHAKE_NONCE_LEN: usize = 32;
const SERVER_CONTEXT_LABEL: &[u8] = b"SSHKEY server context v1";
const USERAUTH_LABEL: &[u8] = b"SSHKEY userauth v1";
const FINISHED_KEY_LABEL: &[u8] = b"SSHKEY finished key v1";
const INITIATOR_FINISHED_LABEL: &[u8] = b"gss-sshkey initiator finished v1";
const ACCEPTOR_FINISHED_LABEL: &[u8] = b"gss-sshkey acceptor finished v1";
const HOSTAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey hostauth v1";
const HOSTCHALLENGE_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey hostchallenge v1";
const USERAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey userauth v1";
const SSHKEY_CTX_KEY_ENV: &str = "SSHKEY_CTX_KEY";
const SSHKEY_HOST_KEY_ENV: &str = "SSHKEY_HOST_KEY";
const SSHKEY_USER_ENV: &str = "SSHKEY_USER";
const SSH_AGENT_MAX_REPLY_LEN: usize = 16 * 1024 * 1024;
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
const DNS_CLASS_IN: c_int = 1;
const DNS_TYPE_SSHFP: c_int = 44;
const DNS_MAX_PACKET: usize = 65_535;
const DNS_FLAG_AD: u16 = 0x0020;
const SSHFP_KEY_RSA: u8 = 1;
const SSHFP_KEY_DSA: u8 = 2;
const SSHFP_KEY_ECDSA: u8 = 3;
const SSHFP_KEY_ED25519: u8 = 4;
const SSHFP_HASH_SHA1: u8 = 1;
const SSHFP_HASH_SHA256: u8 = 2;

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
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        input: *const c_uchar,
        inl: c_int,
    ) -> c_int;
    fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
    fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut c_void,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        input: *const c_uchar,
        inl: c_int,
    ) -> c_int;
    fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
    fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        ctrl_type: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;
}

#[link(name = "resolv")]
unsafe extern "C" {
    fn res_query(
        dname: *const libc::c_char,
        class: c_int,
        type_: c_int,
        answer: *mut c_uchar,
        anslen: c_int,
    ) -> c_int;
}

struct SshKeyCtx {
    is_initiator: bool,
    complete: bool,
    ecdh_key: Option<OpenSslPkey>,
    public_key: Option<[u8; X25519_PUBLIC_LEN]>,
    peer_public_key: Option<[u8; X25519_PUBLIC_LEN]>,
    session_key: Option<[u8; SANON_SESSION_KEY_LEN]>,
    initiator_sigtypes: Vec<u8>,
    acceptor_sigtypes: Vec<u8>,
    server_context: Option<Vec<u8>>,
    display_name: Vec<u8>,
    target_host: Option<String>,
    initiator_nonce: Option<Vec<u8>>,
    acceptor_nonce: Option<Vec<u8>>,
    authenticated: bool,
    send_seq: u64,
    recv_seq: u64,
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
            initiator_sigtypes: SIG_ALGS.to_vec(),
            acceptor_sigtypes: SIG_ALGS.to_vec(),
            server_context: None,
            display_name: b"sshkey".to_vec(),
            target_host: None,
            initiator_nonce: None,
            acceptor_nonce: None,
            authenticated: false,
            send_seq: 0,
            recv_seq: 0,
        }
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

unsafe fn malloc_copy(bytes: &[u8]) -> *mut c_void {
    if bytes.is_empty() {
        return ptr::null_mut();
    }

    let out = libc::malloc(bytes.len());
    if !out.is_null() {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), bytes.len());
    }
    out
}

unsafe fn set_buffer(minor: *mut OM_uint32, buf: gss_buffer_t, s: &str) -> u32 {
    set_buffer_bytes(minor, buf, s.as_bytes())
}

unsafe fn channel_binding_application_data(
    bindings: gss_channel_bindings_t,
) -> Result<Vec<u8>, OM_uint32> {
    if bindings.is_null() {
        return Ok(Vec::new());
    }

    let app = &(*bindings).application_data;
    if app.length == 0 {
        return Ok(Vec::new());
    }
    if app.value.is_null() {
        return Err(GSS_S_FAILURE);
    }

    Ok(
        core::slice::from_raw_parts(app.value.cast::<u8>(), app.length)
            .to_vec(),
    )
}

fn token_status(value: u8) -> SshKeyStatus {
    SshKeyStatus(Integer::from(value))
}

fn token_has_status(token: &SshKeyToken, value: u8) -> bool {
    token.status.0 == Integer::from(value)
}

fn trace(message: &str) {
    if env::var_os("SSHKEY_TRACE").is_some() {
        eprintln!("gss-sshkey: {message}");
    }
}

fn sshkey_context_flags(authenticated: bool) -> OM_uint32 {
    let mut flags = GSS_C_REPLAY_FLAG
        | GSS_C_SEQUENCE_FLAG
        | GSS_C_CONF_FLAG
        | GSS_C_INTEG_FLAG
        | GSS_C_TRANS_FLAG
        | GSS_C_CHANNEL_BOUND_FLAG;
    if !authenticated {
        flags |= GSS_C_ANON_FLAG;
    }
    flags
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

fn generate_handshake_nonce() -> Option<Vec<u8>> {
    let mut nonce = vec![0u8; HANDSHAKE_NONCE_LEN];
    fill_random(&mut nonce).then_some(nonce)
}

fn initial_context_token(
    public_key: &[u8; X25519_PUBLIC_LEN],
    nonce: &[u8],
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from_static(SIG_ALGS),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(public_key.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
        Some(OctetString::from(nonce)),
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
    encuserauth: Option<EncSshKeyUserAuth>,
    sctx: EncCtx,
    finished: SshKeyFinished,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let token = SshKeyToken::new(
        token_status(SSH_KEY_COMPLETE),
        kex,
        None,
        encuserauth,
        None,
        Some(sctx),
        Some(finished),
    );

    rasn::der::encode(&token)
}

fn signature_retry_token(
    acceptor_sigtypes: &[u8],
    sctx: EncCtx,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from(acceptor_sigtypes),
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
        None,
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
        Algorithm::Rsa { .. } => vec![
            b"rsa-sha2-512".to_vec(),
            b"rsa-sha2-256".to_vec(),
            b"ssh-rsa".to_vec(),
        ],
        Algorithm::Dsa => vec![b"ssh-dss".to_vec()],
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

struct AgentIdentity {
    key: Vec<u8>,
    public_key: PublicKey,
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

fn agent_request(payload: &[u8]) -> Option<Vec<u8>> {
    let path = env::var_os("SSH_AUTH_SOCK")?;
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

fn agent_identities() -> Option<Vec<AgentIdentity>> {
    let reply = agent_request(&[SSH2_AGENTC_REQUEST_IDENTITIES])?;
    parse_agent_identities(&reply)
}

fn agent_sign(key: &[u8], data: &[u8], sigtype: &[u8]) -> Option<Vec<u8>> {
    let mut request = vec![SSH2_AGENTC_SIGN_REQUEST];
    push_ssh_string(&mut request, key)?;
    push_ssh_string(&mut request, data)?;
    push_ssh_u32(&mut request, agent_signature_flags(sigtype));

    let mut reply = agent_request(&request)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostTrust {
    Trusted,
    Revoked,
    NotFound,
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

unsafe fn target_host_from_name(name: gss_const_name_t) -> Option<String> {
    if let Ok(host) = env::var(SSHKEY_HOST_ENV) {
        if let Some(host) = normalize_host(&host) {
            return Some(host);
        }
    }
    if name.is_null() || (*name).value.is_null() {
        return None;
    }
    let bytes = core::slice::from_raw_parts(
        (*name).value.cast::<u8>(),
        (*name).length as usize,
    );
    let value = core::str::from_utf8(bytes).ok()?;
    normalize_host(value)
}

fn known_hosts_paths() -> Vec<PathBuf> {
    if let Ok(paths) = env::var(SSHKEY_KNOWN_HOSTS_ENV) {
        return paths
            .split(':')
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect();
    }

    let mut paths = Vec::new();
    if let Ok(home) = env::var("HOME") {
        paths.push(PathBuf::from(format!("{home}/.ssh/known_hosts")));
        paths.push(PathBuf::from(format!("{home}/.ssh/known_hosts2")));
    }
    paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    paths.push(PathBuf::from("/etc/ssh/ssh_known_hosts2"));
    paths
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

fn known_host_plain_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = if pattern.starts_with('[') {
        pattern
            .find(']')
            .map(|end| &pattern[1..end])
            .unwrap_or(pattern)
    } else {
        pattern
    };
    wildcard_match(pattern.as_bytes(), host.as_bytes())
}

fn known_host_hash_matches(salt: &[u8], hash: &[u8; 20], host: &str) -> bool {
    type HmacSha1 = Hmac<Sha1>;

    let Ok(mut mac) = HmacSha1::new_from_slice(salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    let actual = mac.finalize().into_bytes();
    actual.as_slice() == hash
}

fn known_host_patterns_match(patterns: &HostPatterns, host: &str) -> bool {
    match patterns {
        HostPatterns::Patterns(patterns) => {
            let mut matched = false;
            for pattern in patterns {
                if let Some(pattern) = pattern.strip_prefix('!') {
                    if known_host_plain_pattern_matches(pattern, host) {
                        return false;
                    }
                    continue;
                }
                matched |= known_host_plain_pattern_matches(pattern, host);
            }
            matched
        }
        HostPatterns::HashedName { salt, hash } => {
            known_host_hash_matches(salt, hash, host)
        }
    }
}

fn known_hosts_trust_text(
    host: &str,
    key_blob: &[u8],
    text: &str,
) -> HostTrust {
    let mut trusted = false;
    for entry in KnownHosts::new(text).flatten() {
        if !known_host_patterns_match(entry.host_patterns(), host) {
            continue;
        }
        let Ok(entry_key) = entry.public_key().to_bytes() else {
            continue;
        };
        if entry_key != key_blob {
            continue;
        }
        if entry.marker() == Some(&Marker::Revoked) {
            return HostTrust::Revoked;
        }
        if entry.marker().is_none() {
            trusted = true;
        }
    }
    if trusted {
        HostTrust::Trusted
    } else {
        HostTrust::NotFound
    }
}

fn known_hosts_trust(host: &str, key_blob: &[u8]) -> HostTrust {
    let mut trusted = false;
    for path in known_hosts_paths() {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        match known_hosts_trust_text(host, key_blob, &text) {
            HostTrust::Trusted => trusted = true,
            HostTrust::Revoked => return HostTrust::Revoked,
            HostTrust::NotFound => {}
        }
    }
    if trusted {
        HostTrust::Trusted
    } else {
        HostTrust::NotFound
    }
}

fn dns_read_u16(packet: &[u8], offset: &mut usize) -> Option<u16> {
    if packet.len().checked_sub(*offset)? < 2 {
        return None;
    }
    let value =
        u16::from_be_bytes(packet[*offset..*offset + 2].try_into().ok()?);
    *offset += 2;
    Some(value)
}

fn dns_read_u32(packet: &[u8], offset: &mut usize) -> Option<u32> {
    if packet.len().checked_sub(*offset)? < 4 {
        return None;
    }
    let value =
        u32::from_be_bytes(packet[*offset..*offset + 4].try_into().ok()?);
    *offset += 4;
    Some(value)
}

fn dns_skip_name(packet: &[u8], offset: &mut usize) -> Option<()> {
    let mut jumps = 0usize;
    loop {
        let len = *packet.get(*offset)?;
        if len & 0xc0 == 0xc0 {
            if packet.len().checked_sub(*offset)? < 2 {
                return None;
            }
            *offset += 2;
            return Some(());
        }
        if len & 0xc0 != 0 {
            return None;
        }
        *offset += 1;
        if len == 0 {
            return Some(());
        }
        *offset = (*offset).checked_add(len as usize)?;
        if *offset > packet.len() {
            return None;
        }
        jumps += 1;
        if jumps > 255 {
            return None;
        }
    }
}

struct SshfpRecord {
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

fn parse_sshfp_response(packet: &[u8]) -> Option<Vec<SshfpRecord>> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes(packet[2..4].try_into().ok()?);
    if flags & DNS_FLAG_AD == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes(packet[4..6].try_into().ok()?);
    let ancount = u16::from_be_bytes(packet[6..8].try_into().ok()?);
    let mut offset = 12usize;

    for _ in 0..qdcount {
        dns_skip_name(packet, &mut offset)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        dns_skip_name(packet, &mut offset)?;
        let rr_type = dns_read_u16(packet, &mut offset)?;
        let rr_class = dns_read_u16(packet, &mut offset)?;
        let _ttl = dns_read_u32(packet, &mut offset)?;
        let rdlen = dns_read_u16(packet, &mut offset)? as usize;
        if packet.len().checked_sub(offset)? < rdlen {
            return None;
        }
        let rdata = &packet[offset..offset + rdlen];
        offset += rdlen;

        if rr_type == DNS_TYPE_SSHFP as u16
            && rr_class == DNS_CLASS_IN as u16
            && rdata.len() >= 2
        {
            records.push(SshfpRecord {
                algorithm: rdata[0],
                digest_type: rdata[1],
                digest: rdata[2..].to_vec(),
            });
        }
    }

    Some(records)
}

fn query_sshfp_records(host: &str) -> Option<Vec<SshfpRecord>> {
    let name = CString::new(host).ok()?;
    let mut answer = vec![0u8; DNS_MAX_PACKET];
    let len = unsafe {
        res_query(
            name.as_ptr(),
            DNS_CLASS_IN,
            DNS_TYPE_SSHFP,
            answer.as_mut_ptr(),
            answer.len() as c_int,
        )
    };
    if len <= 0 {
        return None;
    }
    answer.truncate(len as usize);
    parse_sshfp_response(&answer)
}

fn sshfp_algorithm(public_key: &PublicKey) -> Option<u8> {
    match public_key.algorithm() {
        Algorithm::Rsa { .. } => Some(SSHFP_KEY_RSA),
        Algorithm::Dsa => Some(SSHFP_KEY_DSA),
        Algorithm::Ecdsa { .. } => Some(SSHFP_KEY_ECDSA),
        Algorithm::Ed25519 => Some(SSHFP_KEY_ED25519),
        _ => None,
    }
}

fn sshfp_record_matches(
    record: &SshfpRecord,
    algorithm: u8,
    key_blob: &[u8],
) -> bool {
    if record.algorithm != algorithm {
        return false;
    }
    match record.digest_type {
        SSHFP_HASH_SHA1 => {
            let digest = Sha1::digest(key_blob);
            record.digest.as_slice() == digest.as_slice()
        }
        SSHFP_HASH_SHA256 => {
            let digest = Sha256::digest(key_blob);
            record.digest.as_slice() == digest.as_slice()
        }
        _ => false,
    }
}

fn sshfp_trust(host: &str, public_key: &PublicKey, key_blob: &[u8]) -> bool {
    let Some(algorithm) = sshfp_algorithm(public_key) else {
        return false;
    };
    let Some(records) = query_sshfp_records(host) else {
        return false;
    };
    records
        .iter()
        .any(|record| sshfp_record_matches(record, algorithm, key_blob))
}

fn host_key_is_trusted(host: &str, key_blob: &[u8]) -> bool {
    let Some(host) = normalize_host(host) else {
        return false;
    };
    let Ok(public_key) = PublicKey::from_bytes(key_blob) else {
        return false;
    };
    match known_hosts_trust(&host, key_blob) {
        HostTrust::Trusted => true,
        HostTrust::Revoked => false,
        HostTrust::NotFound => sshfp_trust(&host, &public_key, key_blob),
    }
}

fn alg_list_contains(list: &[u8], alg: &[u8]) -> bool {
    list.split(|byte| *byte == b',').any(|item| item == alg)
}

fn host_signature_input(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
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
    push_ssh_string(&mut out, channel_bindings)?;
    Some(out)
}

fn host_challenge_signature_input(
    acceptor_sigtypes: &[u8],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    channel_bindings: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    push_ssh_string(&mut out, HOSTCHALLENGE_TRANSCRIPT_LABEL)?;
    push_ssh_string(&mut out, &SSHKEY_OID_ELEMENTS)?;
    push_ssh_string(&mut out, KEX_ALG)?;
    push_ssh_string(&mut out, ENC_ALG)?;
    push_ssh_string(&mut out, acceptor_sigtypes)?;
    push_ssh_string(&mut out, acceptor_public)?;
    push_ssh_string(&mut out, channel_bindings)?;
    Some(out)
}

fn user_signature_input(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    username: &[u8],
    keytype: &[u8],
    key: &[u8],
    sigtype: &[u8],
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
    push_ssh_string(&mut out, username)?;
    push_ssh_string(&mut out, keytype)?;
    push_ssh_string(&mut out, key)?;
    push_ssh_string(&mut out, sigtype)?;
    Some(out)
}

fn handshake_transcript_hash(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    initiator_nonce: &[u8],
    acceptor_nonce: &[u8],
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
    push_ssh_string(&mut input, channel_bindings)?;
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
    let signature: SshSignature = Signer::try_sign(private_key, data).ok()?;
    let sigtype = signature.algorithm().as_str().as_bytes().to_vec();
    let public_key = private_key.public_key();
    let keytype = public_key.algorithm().as_str().as_bytes().to_vec();
    let key = public_key.to_bytes().ok()?;
    let sig = Vec::<u8>::try_from(signature).ok()?;
    Some((keytype, key, sigtype, sig))
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

fn server_context_key() -> [u8; CONTEXT_KEY_LEN] {
    static KEY: OnceLock<[u8; CONTEXT_KEY_LEN]> = OnceLock::new();

    *KEY.get_or_init(|| {
        if let Ok(value) = env::var(SSHKEY_CTX_KEY_ENV) {
            if let Some(key) = parse_hex_context_key(&value) {
                return key;
            }
        }

        let mut key = [0u8; CONTEXT_KEY_LEN];
        if !fill_random(&mut key) {
            key.copy_from_slice(b"sshkey fallback context key v1!!");
        }
        key
    })
}

unsafe fn derive_context_key(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    label: &[u8],
) -> Option<[u8; CONTEXT_KEY_LEN]> {
    hmac_sha256(session_key, label)
}

unsafe fn seal_aead(
    key: &[u8; CONTEXT_KEY_LEN],
    label: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let mut nonce = [0u8; CFX_GCM_NONCE_LEN];
    if !fill_random(&mut nonce) {
        return None;
    }
    let body = aes_256_gcm_encrypt(key, &nonce, label, plaintext)?;
    let mut out = Vec::with_capacity(nonce.len() + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Some(out)
}

unsafe fn open_aead(
    key: &[u8; CONTEXT_KEY_LEN],
    label: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext.len() < CFX_GCM_NONCE_LEN + CFX_GCM_TAG_LEN {
        return None;
    }
    let (nonce, body) = ciphertext.split_at(CFX_GCM_NONCE_LEN);
    let nonce = nonce.try_into().ok()?;
    aes_256_gcm_decrypt(key, nonce, label, body)
}

unsafe fn seal_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_context_key(session_key, USERAUTH_LABEL)?;
    seal_aead(&key, USERAUTH_LABEL, plaintext)
}

unsafe fn open_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_context_key(session_key, USERAUTH_LABEL)?;
    open_aead(&key, USERAUTH_LABEL, ciphertext)
}

unsafe fn seal_server_context(
    context: &SshKeyServerContext,
) -> Option<Vec<u8>> {
    let plaintext = rasn::der::encode(context).ok()?;
    let key = server_context_key();
    seal_aead(&key, SERVER_CONTEXT_LABEL, &plaintext)
}

unsafe fn open_server_context(
    ciphertext: &[u8],
) -> Option<SshKeyServerContext> {
    let key = server_context_key();
    let plaintext = open_aead(&key, SERVER_CONTEXT_LABEL, ciphertext)?;
    rasn::der::decode::<SshKeyServerContext>(&plaintext).ok()
}

unsafe fn encrypted_userauth(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
) -> Option<EncSshKeyUserAuth> {
    let username = env::var(SSHKEY_USER_ENV)
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "sshkey".to_string())
        .into_bytes();
    for identity in agent_identities()? {
        let key_alg = identity.public_key.algorithm();
        let keytype = key_alg.as_str().as_bytes().to_vec();
        for sigtype in signature_algorithms(&key_alg) {
            if !alg_list_contains(initiator_sigtypes, &sigtype)
                || !alg_list_contains(acceptor_sigtypes, &sigtype)
            {
                continue;
            }
            let input = user_signature_input(
                initiator_sigtypes,
                acceptor_sigtypes,
                initiator_public,
                acceptor_public,
                &username,
                &keytype,
                &identity.key,
                &sigtype,
            )?;
            let sig = agent_sign(&identity.key, &input, &sigtype)?;
            let signature = SshSignature::try_from(sig.as_slice()).ok()?;
            if signature.algorithm().as_str().as_bytes() != sigtype {
                continue;
            }
            if !verify_ssh_signature(&identity.key, &sigtype, &sig, &input) {
                continue;
            }

            let userauth = SshKeyUserAuth::new(
                OctetString::from(username),
                OctetString::from(keytype),
                OctetString::from(identity.key),
                OctetString::from(sigtype),
                OctetString::from(sig),
            );
            let plaintext = rasn::der::encode(&userauth).ok()?;
            let ciphertext = seal_userauth(session_key, &plaintext)?;
            return Some(EncSshKeyUserAuth(OctetString::from(ciphertext)));
        }
    }
    None
}

fn hostauth_token(
    initiator_sigtypes: &[u8],
    acceptor_sigtypes: &[u8],
    initiator_public: &[u8; X25519_PUBLIC_LEN],
    acceptor_public: &[u8; X25519_PUBLIC_LEN],
    channel_bindings: &[u8],
) -> Option<SshKeyHostAuth> {
    let private_key = read_private_key_from_env(SSHKEY_HOST_KEY_ENV)?;
    let input = host_signature_input(
        initiator_sigtypes,
        acceptor_sigtypes,
        initiator_public,
        acceptor_public,
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
    channel_bindings: &[u8],
) -> Option<SshKeyHostAuth> {
    let private_key = read_private_key_from_env(SSHKEY_HOST_KEY_ENV)?;
    let input = host_challenge_signature_input(
        acceptor_sigtypes,
        acceptor_public,
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
    let plaintext = open_userauth(session_key, ciphertext.0.as_ref())?;
    rasn::der::decode::<SshKeyUserAuth>(&plaintext).ok()
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
) -> Option<[u8; X25519_SHARED_LEN]> {
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

    let mut shared = [0u8; X25519_SHARED_LEN];
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
) -> Option<[u8; SANON_SESSION_KEY_LEN]> {
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

unsafe fn derive_cfx_key(
    session_key: &[u8; SANON_SESSION_KEY_LEN],
    sender_acceptor: bool,
    seal: bool,
) -> Option<[u8; CFX_HMAC_LEN]> {
    let label = match (sender_acceptor, seal) {
        (true, true) => b"RFC4121 KG-USAGE-ACCEPTOR-SEAL 22".as_slice(),
        (true, false) => b"RFC4121 KG-USAGE-ACCEPTOR-SIGN 23".as_slice(),
        (false, true) => b"RFC4121 KG-USAGE-INITIATOR-SEAL 24".as_slice(),
        (false, false) => b"RFC4121 KG-USAGE-INITIATOR-SIGN 25".as_slice(),
    };

    hmac_sha256(session_key, label)
}

unsafe fn derive_cfx_nonce(
    key: &[u8; CFX_HMAC_LEN],
    sender_acceptor: bool,
    seq: u64,
) -> Option<[u8; CFX_GCM_NONCE_LEN]> {
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(b"RFC4121 AES-256-GCM nonce");
    data.push(u8::from(sender_acceptor));
    data.extend_from_slice(&seq.to_be_bytes());

    let digest = hmac_sha256(key, &data)?;
    let mut nonce = [0u8; CFX_GCM_NONCE_LEN];
    nonce.copy_from_slice(&digest[..CFX_GCM_NONCE_LEN]);
    Some(nonce)
}

unsafe fn aes_256_gcm_encrypt(
    key: &[u8; CFX_HMAC_LEN],
    nonce: &[u8; CFX_GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let aad_len: c_int = aad.len().try_into().ok()?;
    let input_len: c_int = plaintext.len().try_into().ok()?;
    let ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        return None;
    }

    let mut out = vec![0u8; plaintext.len()];
    let mut len = 0;
    let mut total = 0usize;
    let mut tag = [0u8; CFX_GCM_TAG_LEN];
    let ok = EVP_EncryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        ptr::null_mut(),
        ptr::null(),
        ptr::null(),
    ) == 1
        && EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            CFX_GCM_NONCE_LEN as c_int,
            ptr::null_mut(),
        ) == 1
        && EVP_EncryptInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) == 1
        && (aad.is_empty()
            || EVP_EncryptUpdate(
                ctx,
                ptr::null_mut(),
                &mut len,
                aad.as_ptr(),
                aad_len,
            ) == 1)
        && EVP_EncryptUpdate(
            ctx,
            out.as_mut_ptr(),
            &mut len,
            plaintext.as_ptr(),
            input_len,
        ) == 1;
    if ok {
        total = len as usize;
    }
    let ok = ok
        && EVP_EncryptFinal_ex(ctx, out.as_mut_ptr().add(total), &mut len) == 1;
    if ok {
        total += len as usize;
    }
    let ok = ok
        && EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            CFX_GCM_TAG_LEN as c_int,
            tag.as_mut_ptr().cast(),
        ) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if !ok {
        return None;
    }
    out.truncate(total);
    out.extend_from_slice(&tag);
    Some(out)
}

unsafe fn aes_256_gcm_decrypt(
    key: &[u8; CFX_HMAC_LEN],
    nonce: &[u8; CFX_GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_and_tag.len() < CFX_GCM_TAG_LEN {
        return None;
    }

    let (ciphertext, tag) =
        ciphertext_and_tag.split_at(ciphertext_and_tag.len() - CFX_GCM_TAG_LEN);
    let aad_len: c_int = aad.len().try_into().ok()?;
    let input_len: c_int = ciphertext.len().try_into().ok()?;
    let ctx = EVP_CIPHER_CTX_new();
    if ctx.is_null() {
        return None;
    }

    let mut out = vec![0u8; ciphertext.len()];
    let mut len = 0;
    let mut total = 0usize;
    let ok = EVP_DecryptInit_ex(
        ctx,
        EVP_aes_256_gcm(),
        ptr::null_mut(),
        ptr::null(),
        ptr::null(),
    ) == 1
        && EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            CFX_GCM_NONCE_LEN as c_int,
            ptr::null_mut(),
        ) == 1
        && EVP_DecryptInit_ex(
            ctx,
            ptr::null(),
            ptr::null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) == 1
        && (aad.is_empty()
            || EVP_DecryptUpdate(
                ctx,
                ptr::null_mut(),
                &mut len,
                aad.as_ptr(),
                aad_len,
            ) == 1)
        && EVP_DecryptUpdate(
            ctx,
            out.as_mut_ptr(),
            &mut len,
            ciphertext.as_ptr(),
            input_len,
        ) == 1;
    if ok {
        total = len as usize;
    }

    let ok = ok
        && EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            CFX_GCM_TAG_LEN as c_int,
            tag.as_ptr() as *mut c_void,
        ) == 1
        && EVP_DecryptFinal_ex(ctx, out.as_mut_ptr().add(total), &mut len) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if !ok {
        return None;
    }
    total += len as usize;
    out.truncate(total);
    Some(out)
}

#[cfg(test)]
unsafe fn cfx_wrap_message(
    ctx: &mut SshKeyCtx,
    conf_req: bool,
    plaintext: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    cfx_wrap_message_with_aad(ctx, conf_req, plaintext, &[])
}

struct SshKeyRfc4121Profile {
    session_key: [u8; SANON_SESSION_KEY_LEN],
}

impl rfc4121::CryptoProfile for SshKeyRfc4121Profile {
    const CHECKSUM_LEN: usize = CFX_HMAC_LEN;
    const SEALED_OVERHEAD: usize = CFX_GCM_TAG_LEN;

    fn seal(
        &self,
        sender: rfc4121::Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, rfc4121::Error> {
        unsafe {
            let sender_acceptor = sender.is_acceptor();
            let key = derive_cfx_key(&self.session_key, sender_acceptor, true)
                .ok_or(rfc4121::Error::Failure)?;
            let nonce = derive_cfx_nonce(&key, sender_acceptor, seq)
                .ok_or(rfc4121::Error::Failure)?;
            aes_256_gcm_encrypt(&key, &nonce, aad, plaintext)
                .ok_or(rfc4121::Error::Failure)
        }
    }

    fn open(
        &self,
        sender: rfc4121::Role,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, rfc4121::Error> {
        unsafe {
            let sender_acceptor = sender.is_acceptor();
            let key = derive_cfx_key(&self.session_key, sender_acceptor, true)
                .ok_or(rfc4121::Error::Failure)?;
            let nonce = derive_cfx_nonce(&key, sender_acceptor, seq)
                .ok_or(rfc4121::Error::Failure)?;
            aes_256_gcm_decrypt(&key, &nonce, aad, ciphertext)
                .ok_or(rfc4121::Error::BadSignature)
        }
    }

    fn sign(
        &self,
        sender: rfc4121::Role,
        _seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; CFX_HEADER_LEN],
    ) -> Result<Vec<u8>, rfc4121::Error> {
        unsafe {
            let key =
                derive_cfx_key(&self.session_key, sender.is_acceptor(), false)
                    .ok_or(rfc4121::Error::Failure)?;
            let mut signed = Vec::with_capacity(
                aad.len() + plaintext.len() + CFX_HEADER_LEN,
            );
            signed.extend_from_slice(aad);
            signed.extend_from_slice(plaintext);
            signed.extend_from_slice(checksum_header);
            hmac_sha256(&key, &signed)
                .map(Vec::from)
                .ok_or(rfc4121::Error::Failure)
        }
    }

    fn verify(
        &self,
        sender: rfc4121::Role,
        seq: u64,
        aad: &[u8],
        plaintext: &[u8],
        checksum_header: &[u8; CFX_HEADER_LEN],
        checksum: &[u8],
    ) -> Result<(), rfc4121::Error> {
        let expected =
            self.sign(sender, seq, aad, plaintext, checksum_header)?;
        if rfc4121::constant_time_eq(checksum, &expected) {
            Ok(())
        } else {
            Err(rfc4121::Error::BadSignature)
        }
    }
}

impl Rfc4121Context for SshKeyCtx {
    type Profile = SshKeyRfc4121Profile;

    fn role(&self) -> rfc4121::Role {
        cfx_role(self.is_initiator)
    }

    fn send_seq(&self) -> u64 {
        self.send_seq
    }

    fn recv_seq(&self) -> u64 {
        self.recv_seq
    }

    fn set_send_seq(&mut self, seq: u64) {
        self.send_seq = seq;
    }

    fn set_recv_seq(&mut self, seq: u64) {
        self.recv_seq = seq;
    }

    fn profile(&self) -> Result<Self::Profile, Status> {
        if !self.complete {
            return Err(Status::new(GSS_S_NO_CONTEXT, EINVAL));
        }
        let Some(session_key) = self.session_key else {
            return Err(Status::new(GSS_S_NO_CONTEXT, EINVAL));
        };
        Ok(SshKeyRfc4121Profile { session_key })
    }
}

fn cfx_role(is_initiator: bool) -> rfc4121::Role {
    if is_initiator {
        rfc4121::Role::Initiator
    } else {
        rfc4121::Role::Acceptor
    }
}

#[cfg(test)]
unsafe fn cfx_wrap_message_with_aad(
    ctx: &mut SshKeyCtx,
    conf_req: bool,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    gss_mech_builder::protect_message(ctx, conf_req, plaintext, aad)
        .map_err(|status| status.major)
}

#[cfg(test)]
unsafe fn cfx_unwrap_message(
    ctx: &mut SshKeyCtx,
    token: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    cfx_unwrap_message_with_aad(ctx, token, &[])
}

#[cfg(test)]
unsafe fn cfx_unwrap_message_with_aad(
    ctx: &mut SshKeyCtx,
    token: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    gss_mech_builder::unprotect_message(ctx, token, aad)
        .map_err(|status| status.major)
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
    let token = decapsulate_initial_token(bytes).unwrap_or(bytes);
    match rasn::der::decode::<SshKeyToken>(token) {
        Ok(token) => Ok(token),
        Err(_) => {
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
        Ok(bytes) => set_buffer_bytes(minor, output_token, &bytes),
        Err(_) => {
            clear_buffer(output_token);
            set_minor(minor, EINVAL);
            GSS_S_FAILURE
        }
    }
}

unsafe fn make_oid_set(minor: *mut OM_uint32, out: *mut gss_OID_set) -> u32 {
    if out.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let set = libc::calloc(1, core::mem::size_of::<gss_OID_set_desc>())
        .cast::<gss_OID_set_desc>();
    if set.is_null() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    let elements = libc::calloc(1, core::mem::size_of::<gss_OID_desc>())
        .cast::<gss_OID_desc>();
    if elements.is_null() {
        libc::free(set.cast());
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    let oid_elements = malloc_copy(&SSHKEY_OID_ELEMENTS);
    if oid_elements.is_null() {
        libc::free(elements.cast());
        libc::free(set.cast());
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    (*elements).length = SSHKEY_OID_ELEMENTS.len() as OM_uint32;
    (*elements).elements = oid_elements;
    (*set).count = 1;
    (*set).elements = elements;
    *out = set;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn make_empty_oid_set(
    minor: *mut OM_uint32,
    out: *mut gss_OID_set,
) -> u32 {
    if out.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let set = libc::calloc(1, core::mem::size_of::<gss_OID_set_desc>())
        .cast::<gss_OID_set_desc>();
    if set.is_null() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    *out = set;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn import_buffer_name(
    minor: *mut OM_uint32,
    input: *const gss_buffer_desc,
    out: *mut gss_name_t,
) -> u32 {
    if out.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let name = libc::calloc(1, core::mem::size_of::<gss_name_t_desc>())
        .cast::<gss_name_t_desc>();
    if name.is_null() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    if !input.is_null() && (*input).length != 0 {
        if (*input).value.is_null() {
            libc::free(name.cast());
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        }

        let value = libc::malloc((*input).length + 1);
        if value.is_null() {
            libc::free(name.cast());
            set_minor(minor, ENOMEM);
            return GSS_S_FAILURE;
        }

        ptr::copy_nonoverlapping(
            (*input).value.cast::<u8>(),
            value.cast::<u8>(),
            (*input).length,
        );
        *value.cast::<u8>().add((*input).length) = 0;
        (*name).value = value;
        (*name).length = (*input).length as u32;
    }

    *out = name;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn duplicate_name(
    minor: *mut OM_uint32,
    input: gss_const_name_t,
    out: *mut gss_name_t,
) -> u32 {
    if input.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_NAME;
    }

    let buf = gss_buffer_desc {
        length: (*input).length as usize,
        value: (*input).value,
    };
    import_buffer_name(minor, &buf, out)
}

unsafe fn oid_desc() -> gss_OID {
    let oid = libc::calloc(1, core::mem::size_of::<gss_OID_desc>())
        .cast::<gss_OID_desc>();
    if !oid.is_null() {
        (*oid).length = SSHKEY_OID_ELEMENTS.len() as OM_uint32;
        (*oid).elements = SSHKEY_OID_ELEMENTS.as_ptr() as *mut c_void;
    }
    oid
}

#[no_mangle]
pub unsafe extern "C" fn gss_acquire_cred(
    minor: *mut OM_uint32,
    _desired_name: gss_const_name_t,
    _time_req: OM_uint32,
    _desired_mechs: gss_const_OID_set,
    _cred_usage: gss_cred_usage_t,
    output_cred: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if !output_cred.is_null() {
        let cred = libc::calloc(1, 1);
        if cred.is_null() {
            set_minor(minor, ENOMEM);
            return GSS_S_FAILURE;
        }
        *output_cred = cred;
    }

    if !actual_mechs.is_null() {
        let ret = make_oid_set(minor, actual_mechs);
        if ret != GSS_S_COMPLETE {
            if !output_cred.is_null() && !(*output_cred).is_null() {
                libc::free((*output_cred).cast());
                *output_cred = ptr::null_mut();
            }
            return ret;
        }
    }

    if !time_rec.is_null() {
        *time_rec = GSS_C_INDEFINITE;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_release_cred(
    minor: *mut OM_uint32,
    cred: *mut gss_cred_id_t,
) -> OM_uint32 {
    if !cred.is_null() && !(*cred).is_null() {
        libc::free((*cred).cast());
        *cred = ptr::null_mut();
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_import_name(
    minor: *mut OM_uint32,
    input: *const gss_buffer_desc,
    _input_name_type: gss_const_OID,
    output_name: *mut gss_name_t,
) -> OM_uint32 {
    import_buffer_name(minor, input, output_name)
}

#[no_mangle]
pub unsafe extern "C" fn gss_release_name(
    minor: *mut OM_uint32,
    name: *mut gss_name_t,
) -> OM_uint32 {
    if !name.is_null() && !(*name).is_null() {
        libc::free((**name).value);
        libc::free((*name).cast());
        *name = ptr::null_mut();
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_compare_name(
    minor: *mut OM_uint32,
    name1: gss_const_name_t,
    name2: gss_const_name_t,
    name_equal: *mut i32,
) -> OM_uint32 {
    if name_equal.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    *name_equal = 0;
    if !name1.is_null()
        && !name2.is_null()
        && (*name1).length == (*name2).length
    {
        let len = (*name1).length as usize;
        if len == 0 || libc::memcmp((*name1).value, (*name2).value, len) == 0 {
            *name_equal = 1;
        }
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_display_name(
    minor: *mut OM_uint32,
    input_name: gss_const_name_t,
    output_name: gss_buffer_t,
    output_name_type: *mut gss_OID,
) -> OM_uint32 {
    clear_buffer(output_name);
    if !output_name_type.is_null() {
        *output_name_type = ptr::null_mut();
    }
    if input_name.is_null() || output_name.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_BAD_NAME;
    }

    let src = core::slice::from_raw_parts(
        (*input_name).value.cast::<u8>(),
        (*input_name).length as usize,
    );
    let value = malloc_copy(src);
    if value.is_null() && !src.is_empty() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    (*output_name).length = src.len();
    (*output_name).value = value;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_export_name(
    minor: *mut OM_uint32,
    input_name: gss_const_name_t,
    exported_name: gss_buffer_t,
) -> OM_uint32 {
    gss_display_name(minor, input_name, exported_name, ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn gss_canonicalize_name(
    minor: *mut OM_uint32,
    input: gss_const_name_t,
    _mech_type: gss_const_OID,
    output: *mut gss_name_t,
) -> OM_uint32 {
    duplicate_name(minor, input, output)
}

#[no_mangle]
pub unsafe extern "C" fn gss_duplicate_name(
    minor: *mut OM_uint32,
    input: gss_const_name_t,
    output: *mut gss_name_t,
) -> OM_uint32 {
    duplicate_name(minor, input, output)
}

#[no_mangle]
pub unsafe extern "C" fn gss_indicate_mechs(
    minor: *mut OM_uint32,
    mech_set: *mut gss_OID_set,
) -> OM_uint32 {
    make_oid_set(minor, mech_set)
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_mechs_for_name(
    minor: *mut OM_uint32,
    _name: gss_const_name_t,
    mech_types: *mut gss_OID_set,
) -> OM_uint32 {
    make_oid_set(minor, mech_types)
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_names_for_mech(
    minor: *mut OM_uint32,
    _mechanism: gss_const_OID,
    name_types: *mut gss_OID_set,
) -> OM_uint32 {
    make_empty_oid_set(minor, name_types)
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_saslname_for_mech(
    minor: *mut OM_uint32,
    _desired_mech: gss_const_OID,
    sasl_name: gss_buffer_t,
    mech_name: gss_buffer_t,
    mech_description: gss_buffer_t,
) -> OM_uint32 {
    if !sasl_name.is_null()
        && set_buffer(minor, sasl_name, "SSHKEY") != GSS_S_COMPLETE
    {
        return GSS_S_FAILURE;
    }
    if !mech_name.is_null()
        && set_buffer(minor, mech_name, "sshkey") != GSS_S_COMPLETE
    {
        return GSS_S_FAILURE;
    }
    if !mech_description.is_null()
        && set_buffer(minor, mech_description, "SSH key GSS mechanism")
            != GSS_S_COMPLETE
    {
        return GSS_S_FAILURE;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_mech_for_saslname(
    minor: *mut OM_uint32,
    sasl_name: gss_buffer_t,
    mech_type: *mut gss_OID,
) -> OM_uint32 {
    if sasl_name.is_null()
        || (*sasl_name).length != 6
        || libc::strncasecmp(
            (*sasl_name).value.cast(),
            b"SSHKEY\0".as_ptr().cast(),
            6,
        ) != 0
    {
        set_minor(minor, 0);
        return GSS_S_BAD_MECH;
    }

    if mech_type.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let oid = oid_desc();
    if oid.is_null() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    *mech_type = oid;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_attrs_for_mech(
    minor: *mut OM_uint32,
    _mech: gss_const_OID,
    mech_attr: *mut gss_OID_set,
    known_mech_attrs: *mut gss_OID_set,
) -> OM_uint32 {
    if !mech_attr.is_null()
        && make_empty_oid_set(minor, mech_attr) != GSS_S_COMPLETE
    {
        return GSS_S_FAILURE;
    }
    if !known_mech_attrs.is_null()
        && make_empty_oid_set(minor, known_mech_attrs) != GSS_S_COMPLETE
    {
        return GSS_S_FAILURE;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_init_sec_context(
    minor: *mut OM_uint32,
    _cred: gss_const_cred_id_t,
    context: *mut gss_ctx_id_t,
    _target_name: gss_const_name_t,
    _mech_type: gss_const_OID,
    _req_flags: OM_uint32,
    _time_req: OM_uint32,
    bindings: gss_channel_bindings_t,
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
        let mut ctx = Box::new(SshKeyCtx::new(true));
        ctx.target_host = target_host_from_name(_target_name);
        *context = Box::into_raw(ctx).cast();
    }
    let ctx = &mut *((*context).cast::<SshKeyCtx>());
    if ctx.target_host.is_none() {
        ctx.target_host = target_host_from_name(_target_name);
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
        let channel_bindings = match channel_binding_application_data(bindings)
        {
            Ok(channel_bindings) => channel_bindings,
            Err(major) => {
                set_minor(minor, EINVAL);
                return major;
            }
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
                    &channel_bindings,
                )
            } else {
                host_signature_input(
                    &initiator_sigtypes,
                    &acceptor_sigtypes,
                    &initiator_public,
                    &acceptor_public,
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
            let Some(host) = ctx.target_host.as_deref() else {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_NAME;
            };
            if !host_key_is_trusted(host, hostauth.key.as_ref()) {
                set_minor(minor, EINVAL);
                return GSS_S_BAD_SIG;
            }
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
        let encuserauth = encrypted_userauth(
            &session_key,
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
        );

        ctx.peer_public_key = Some(acceptor_public);
        ctx.session_key = Some(session_key);
        ctx.ecdh_key = None;
        ctx.acceptor_sigtypes = acceptor_sigtypes;
        ctx.server_context = Some(server_context.clone());
        ctx.acceptor_nonce = Some(acceptor_nonce.clone());
        ctx.authenticated = encuserauth.is_some();
        ctx.send_seq = 0;
        ctx.recv_seq = 0;
        ctx.complete = true;

        let response_kex = if server_first {
            Some(SshKeyKEX::new(
                OctetString::from_static(KEX_ALG),
                OctetString::from_static(ENC_ALG),
                OctetString::from(initiator_sigtypes.as_slice()),
                Some(OctetString::from_static(KEX_ALG)),
                Some(OctetString::from(initiator_public.as_slice())),
                Some(OctetString::from_static(ENC_ALG)),
                Some(OctetString::from(initiator_nonce.as_slice())),
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
                EncCtx::new(OctetString::from(server_context)),
                finished,
            ),
        );
        if ret != GSS_S_COMPLETE {
            return ret;
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(ctx.authenticated);
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
    ctx.session_key = None;
    ctx.initiator_sigtypes = SIG_ALGS.to_vec();
    ctx.acceptor_sigtypes = SIG_ALGS.to_vec();
    ctx.server_context = None;
    ctx.initiator_nonce = Some(nonce.clone());
    ctx.acceptor_nonce = None;
    ctx.authenticated = false;
    ctx.send_seq = 0;
    ctx.recv_seq = 0;
    ctx.complete = false;

    let ret = encode_output_token(
        minor,
        output_token,
        initial_context_token(&public_key, &nonce),
    );
    if ret != GSS_S_COMPLETE {
        return ret;
    }

    GSS_S_CONTINUE_NEEDED
}

#[no_mangle]
pub unsafe extern "C" fn gss_accept_sec_context(
    minor: *mut OM_uint32,
    context: *mut gss_ctx_id_t,
    _cred: gss_const_cred_id_t,
    _input_token: gss_buffer_t,
    bindings: gss_channel_bindings_t,
    src_name: *mut gss_name_t,
    mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    _time_rec: *mut OM_uint32,
    _delegated_cred: *mut gss_cred_id_t,
) -> OM_uint32 {
    clear_buffer(output_token);
    if !src_name.is_null() {
        *src_name = ptr::null_mut();
    }
    if !mech_type.is_null() {
        *mech_type = ptr::null_mut();
    }
    trace("accept start");

    if _input_token.is_null() || (*_input_token).length == 0 {
        trace("accept server-first challenge");
        let Some((private_key, acceptor_public)) = generate_x25519_keypair()
        else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(acceptor_private) = x25519_private_key(&private_key) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let Some(acceptor_nonce) = generate_handshake_nonce() else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let channel_bindings = match channel_binding_application_data(bindings)
        {
            Ok(channel_bindings) => channel_bindings,
            Err(major) => {
                set_minor(minor, EINVAL);
                return major;
            }
        };
        let acceptor_sigtypes = SIG_ALGS.to_vec();
        let server_context = SshKeyServerContext::new(
            None,
            OctetString::from(acceptor_public.as_slice()),
            None,
            None,
            OctetString::from(acceptor_sigtypes.as_slice()),
            Some(OctetString::from(acceptor_private.as_slice())),
            None,
            OctetString::from(acceptor_nonce.as_slice()),
        );
        let Some(sealed_sctx) = seal_server_context(&server_context) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let sctx = EncCtx::new(OctetString::from(sealed_sctx.clone()));
        let hostauth = host_challenge_auth_token(
            &acceptor_sigtypes,
            &acceptor_public,
            &channel_bindings,
        );

        if !context.is_null() && (*context).is_null() {
            let ctx = Box::new(SshKeyCtx::new(false));
            *context = Box::into_raw(ctx).cast();
        }
        if !context.is_null() {
            let ctx = &mut *((*context).cast::<SshKeyCtx>());
            ctx.ecdh_key = Some(private_key);
            ctx.public_key = Some(acceptor_public);
            ctx.peer_public_key = None;
            ctx.session_key = None;
            ctx.acceptor_sigtypes = acceptor_sigtypes.clone();
            ctx.server_context = Some(sealed_sctx);
            ctx.initiator_nonce = None;
            ctx.acceptor_nonce = Some(acceptor_nonce.clone());
            ctx.authenticated = false;
            ctx.send_seq = 0;
            ctx.recv_seq = 0;
            ctx.complete = false;
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(false);
        }

        let ret = encode_output_token(
            minor,
            output_token,
            acceptor_context_token(
                &acceptor_public,
                &acceptor_sigtypes,
                hostauth,
                sctx,
                &acceptor_nonce,
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
        let channel_bindings = match channel_binding_application_data(bindings)
        {
            Ok(channel_bindings) => channel_bindings,
            Err(major) => {
                set_minor(minor, EINVAL);
                return major;
            }
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
        let server_context = SshKeyServerContext::new(
            Some(OctetString::from(initiator_public.as_slice())),
            OctetString::from(acceptor_public.as_slice()),
            Some(OctetString::from(session_key.as_slice())),
            Some(OctetString::from(initiator_sigtypes.as_slice())),
            OctetString::from(acceptor_sigtypes.as_slice()),
            None,
            Some(OctetString::from(initiator_nonce.as_slice())),
            OctetString::from(acceptor_nonce.as_slice()),
        );
        let Some(sealed_sctx) = seal_server_context(&server_context) else {
            set_minor(minor, EINVAL);
            return GSS_S_FAILURE;
        };
        let sctx = EncCtx::new(OctetString::from(sealed_sctx.clone()));
        let hostauth = hostauth_token(
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            &channel_bindings,
        );

        if !context.is_null() && (*context).is_null() {
            let ctx = Box::new(SshKeyCtx::new(false));
            *context = Box::into_raw(ctx).cast();
        }
        if !context.is_null() {
            let ctx = &mut *((*context).cast::<SshKeyCtx>());
            ctx.public_key = Some(acceptor_public);
            ctx.peer_public_key = Some(initiator_public);
            ctx.session_key = Some(session_key);
            ctx.initiator_sigtypes = initiator_sigtypes.clone();
            ctx.acceptor_sigtypes = acceptor_sigtypes.clone();
            ctx.server_context = Some(sealed_sctx);
            ctx.ecdh_key = None;
            ctx.initiator_nonce = Some(initiator_nonce.clone());
            ctx.acceptor_nonce = Some(acceptor_nonce.clone());
            ctx.authenticated = false;
            ctx.send_seq = 0;
            ctx.recv_seq = 0;
            ctx.complete = false;
        }
        if !mech_type.is_null() {
            *mech_type = oid_desc();
        }
        if !ret_flags.is_null() {
            *ret_flags = sshkey_context_flags(false);
        }

        let ret = encode_output_token(
            minor,
            output_token,
            acceptor_context_token(
                &acceptor_public,
                &acceptor_sigtypes,
                hostauth,
                sctx,
                &acceptor_nonce,
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
    let channel_bindings = match channel_binding_application_data(bindings) {
        Ok(channel_bindings) => channel_bindings,
        Err(major) => {
            set_minor(minor, EINVAL);
            return major;
        }
    };
    let session_key = if let Some(value) = server_context.session_key.as_ref() {
        let Some(session_key) = value.as_ref().try_into().ok() else {
            set_minor(minor, EINVAL);
            return GSS_S_DEFECTIVE_TOKEN;
        };
        session_key
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
    let mut display_name = b"sshkey".to_vec();
    let mut authenticated = false;

    if let Some(encuserauth) = token.encuserauth.as_ref() {
        let Some(userauth) = decrypt_userauth(&session_key, encuserauth) else {
            set_minor(minor, EINVAL);
            return GSS_S_BAD_SIG;
        };
        if !alg_list_contains(&acceptor_sigtypes, userauth.sigtype.as_ref()) {
            let ret = encode_output_token(
                minor,
                output_token,
                signature_retry_token(
                    &acceptor_sigtypes,
                    EncCtx::new(OctetString::from(sctx.enc_part.as_ref())),
                ),
            );
            return if ret == GSS_S_COMPLETE {
                GSS_S_CONTINUE_NEEDED
            } else {
                ret
            };
        }
        let Some(input) = user_signature_input(
            &initiator_sigtypes,
            &acceptor_sigtypes,
            &initiator_public,
            &acceptor_public,
            userauth.username.as_ref(),
            userauth.keytype.as_ref(),
            userauth.key.as_ref(),
            userauth.sigtype.as_ref(),
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
        display_name = userauth.username.as_ref().to_vec();
        authenticated = true;
    }

    if !context.is_null() && (*context).is_null() {
        let ctx = Box::new(SshKeyCtx::new(false));
        *context = Box::into_raw(ctx).cast();
    }
    if !context.is_null() {
        let ctx = &mut *((*context).cast::<SshKeyCtx>());
        ctx.public_key = Some(acceptor_public);
        ctx.peer_public_key = Some(initiator_public);
        ctx.session_key = Some(session_key);
        ctx.initiator_sigtypes = initiator_sigtypes;
        ctx.acceptor_sigtypes = acceptor_sigtypes;
        ctx.server_context = Some(sctx.enc_part.as_ref().to_vec());
        ctx.display_name = display_name.clone();
        ctx.ecdh_key = None;
        ctx.initiator_nonce = Some(initiator_nonce);
        ctx.acceptor_nonce = Some(acceptor_nonce);
        ctx.authenticated = authenticated;
        ctx.send_seq = 0;
        ctx.recv_seq = 0;
        ctx.complete = true;
    }
    if !src_name.is_null() {
        let buf = gss_buffer_desc {
            length: display_name.len(),
            value: display_name.as_ptr() as *mut c_void,
        };
        let ret = import_buffer_name(minor, &buf, src_name);
        if ret != GSS_S_COMPLETE {
            return ret;
        }
    }
    if !mech_type.is_null() {
        *mech_type = oid_desc();
    }
    if !ret_flags.is_null() {
        *ret_flags = sshkey_context_flags(authenticated);
    }

    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_process_context_token(
    minor: *mut OM_uint32,
    _ctx: gss_const_ctx_id_t,
    _token: gss_buffer_t,
) -> OM_uint32 {
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_delete_sec_context(
    minor: *mut OM_uint32,
    context: *mut gss_ctx_id_t,
    output_token: gss_buffer_t,
) -> OM_uint32 {
    clear_buffer(output_token);

    if !context.is_null() && !(*context).is_null() {
        drop(Box::from_raw((*context).cast::<SshKeyCtx>()));
        *context = ptr::null_mut();
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_context_time(
    minor: *mut OM_uint32,
    _ctx: gss_const_ctx_id_t,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if !time_rec.is_null() {
        *time_rec = GSS_C_INDEFINITE;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_get_mic(
    minor: *mut OM_uint32,
    _ctx: gss_const_ctx_id_t,
    _qop_req: gss_qop_t,
    _message: gss_buffer_t,
    token: gss_buffer_t,
) -> OM_uint32 {
    clear_buffer(token);
    set_minor(minor, ENOTSUP);
    GSS_S_UNAVAILABLE
}

#[no_mangle]
pub unsafe extern "C" fn gss_verify_mic(
    minor: *mut OM_uint32,
    _ctx: gss_const_ctx_id_t,
    _message: gss_buffer_t,
    _token: gss_buffer_t,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    if !qop_state.is_null() {
        *qop_state = 0;
    }
    set_minor(minor, ENOTSUP);
    GSS_S_UNAVAILABLE
}

#[no_mangle]
pub unsafe extern "C" fn gss_display_status(
    minor: *mut OM_uint32,
    _status: OM_uint32,
    _status_type: i32,
    _mech_type: gss_const_OID,
    message_context: *mut OM_uint32,
    status_string: gss_buffer_t,
) -> OM_uint32 {
    if !message_context.is_null() {
        *message_context = 0;
    }
    set_buffer(minor, status_string, "sshkey mechanism status")
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_cred(
    minor: *mut OM_uint32,
    _cred: gss_const_cred_id_t,
    name: *mut gss_name_t,
    lifetime: *mut OM_uint32,
    cred_usage: *mut gss_cred_usage_t,
    mechanisms: *mut gss_OID_set,
) -> OM_uint32 {
    if !name.is_null() {
        let buf = gss_buffer_desc {
            length: "sshkey".len(),
            value: b"sshkey".as_ptr() as *mut c_void,
        };
        let ret = import_buffer_name(minor, &buf, name);
        if ret != GSS_S_COMPLETE {
            return ret;
        }
    }
    if !lifetime.is_null() {
        *lifetime = GSS_C_INDEFINITE;
    }
    if !cred_usage.is_null() {
        *cred_usage = GSS_C_BOTH;
    }
    if !mechanisms.is_null() {
        return make_oid_set(minor, mechanisms);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_context(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    src_name: *mut gss_name_t,
    targ_name: *mut gss_name_t,
    lifetime: *mut OM_uint32,
    mech_type: *mut gss_OID,
    ctx_flags: *mut OM_uint32,
    locally_initiated: *mut i32,
    open_context: *mut i32,
) -> OM_uint32 {
    if !src_name.is_null() {
        let buf = gss_buffer_desc {
            length: "sshkey".len(),
            value: b"sshkey".as_ptr() as *mut c_void,
        };
        let ret = import_buffer_name(minor, &buf, src_name);
        if ret != GSS_S_COMPLETE {
            return ret;
        }
    }
    if !targ_name.is_null() {
        let buf = gss_buffer_desc {
            length: "sshkey".len(),
            value: b"sshkey".as_ptr() as *mut c_void,
        };
        let ret = import_buffer_name(minor, &buf, targ_name);
        if ret != GSS_S_COMPLETE {
            return ret;
        }
    }
    if !lifetime.is_null() {
        *lifetime = GSS_C_INDEFINITE;
    }
    if !mech_type.is_null() {
        *mech_type = oid_desc();
    }
    if !ctx_flags.is_null() {
        let authenticated =
            !ctx.is_null() && (*(ctx.cast::<SshKeyCtx>())).authenticated;
        *ctx_flags = sshkey_context_flags(authenticated);
    }
    if !locally_initiated.is_null() {
        let initiated =
            !ctx.is_null() && (*(ctx.cast::<SshKeyCtx>())).is_initiator;
        *locally_initiated = i32::from(initiated);
    }
    if !open_context.is_null() {
        let open = !ctx.is_null() && (*(ctx.cast::<SshKeyCtx>())).complete;
        *open_context = i32::from(open);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[no_mangle]
pub unsafe extern "C" fn gss_wrap_size_limit(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    req_output_size: OM_uint32,
    max_input_size: *mut OM_uint32,
) -> OM_uint32 {
    gss_mech_builder::wrap_size_limit::<SshKeyCtx>(
        minor,
        ctx,
        conf_req_flag,
        qop_req,
        req_output_size,
        max_input_size,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_add_cred(
    minor: *mut OM_uint32,
    _input_cred: gss_const_cred_id_t,
    desired_name: gss_const_name_t,
    _desired_mech: gss_const_OID,
    cred_usage: gss_cred_usage_t,
    _initiator_time_req: OM_uint32,
    _acceptor_time_req: OM_uint32,
    output_cred: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    initiator_time_rec: *mut OM_uint32,
    acceptor_time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if !initiator_time_rec.is_null() {
        *initiator_time_rec = GSS_C_INDEFINITE;
    }
    if !acceptor_time_rec.is_null() {
        *acceptor_time_rec = GSS_C_INDEFINITE;
    }
    gss_acquire_cred(
        minor,
        desired_name,
        0,
        ptr::null(),
        cred_usage,
        output_cred,
        actual_mechs,
        ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_inquire_cred_by_mech(
    minor: *mut OM_uint32,
    cred: gss_const_cred_id_t,
    _mech_type: gss_const_OID,
    name: *mut gss_name_t,
    initiator_lifetime: *mut OM_uint32,
    acceptor_lifetime: *mut OM_uint32,
    cred_usage: *mut gss_cred_usage_t,
) -> OM_uint32 {
    if !initiator_lifetime.is_null() {
        *initiator_lifetime = GSS_C_INDEFINITE;
    }
    if !acceptor_lifetime.is_null() {
        *acceptor_lifetime = GSS_C_INDEFINITE;
    }
    gss_inquire_cred(
        minor,
        cred,
        name,
        ptr::null_mut(),
        cred_usage,
        ptr::null_mut(),
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_export_sec_context(
    minor: *mut OM_uint32,
    _context: *mut gss_ctx_id_t,
    token: gss_buffer_t,
) -> OM_uint32 {
    clear_buffer(token);
    set_minor(minor, ENOTSUP);
    GSS_S_UNAVAILABLE
}

#[no_mangle]
pub unsafe extern "C" fn gss_import_sec_context(
    minor: *mut OM_uint32,
    _token: gss_buffer_t,
    context: *mut gss_ctx_id_t,
) -> OM_uint32 {
    if !context.is_null() {
        *context = ptr::null_mut();
    }
    set_minor(minor, ENOTSUP);
    GSS_S_UNAVAILABLE
}

#[no_mangle]
pub unsafe extern "C" fn gss_wrap(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    input: gss_buffer_t,
    conf_state: *mut i32,
    output: gss_buffer_t,
) -> OM_uint32 {
    gss_mech_builder::wrap::<SshKeyCtx>(
        minor,
        ctx,
        conf_req_flag,
        qop_req,
        input,
        conf_state,
        output,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_unwrap(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    input: gss_buffer_t,
    output: gss_buffer_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    gss_mech_builder::unwrap::<SshKeyCtx>(
        minor, ctx, input, output, conf_state, qop_state,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_wrap_iov_length(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_req_flag: i32,
    _qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    gss_mech_builder::wrap_iov_length::<SshKeyCtx>(
        minor,
        ctx,
        conf_req_flag,
        _qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_wrap_iov(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    gss_mech_builder::wrap_iov::<SshKeyCtx>(
        minor,
        ctx,
        conf_req_flag,
        qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_unwrap_iov(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    gss_mech_builder::unwrap_iov::<SshKeyCtx>(
        minor, ctx, conf_state, qop_state, iov, iov_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gss_release_iov_buffer(
    minor: *mut OM_uint32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    gss_mech_builder::release_iov_buffer(minor, iov, iov_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfx_test_contexts() -> (SshKeyCtx, SshKeyCtx) {
        let session_key = [0x5a; SANON_SESSION_KEY_LEN];
        let mut initiator = SshKeyCtx::new(true);
        let mut acceptor = SshKeyCtx::new(false);

        initiator.complete = true;
        initiator.session_key = Some(session_key);
        acceptor.complete = true;
        acceptor.session_key = Some(session_key);

        (initiator, acceptor)
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
            assert_eq!(key, expected);
        }
    }

    #[test]
    fn initial_token_carries_public_key() {
        let public_key = [7u8; X25519_PUBLIC_LEN];
        let nonce = vec![9u8; HANDSHAKE_NONCE_LEN];
        let output = initial_context_token(&public_key, &nonce).unwrap();
        let inner = decapsulate_initial_token(&output).unwrap();
        let token = rasn::der::decode::<SshKeyToken>(inner).unwrap();

        assert!(token_has_status(&token, SSH_KEY_CONTINUE_NEEDED));
        let kex = token.kex.as_ref().unwrap();
        assert_eq!(kex_public_key(kex), Some(public_key));
        assert_eq!(kex_nonce(kex), Some(nonce));
        assert!(kex_octets_match(&kex.kextype, KEX_ALG));
        assert!(kex_octets_match(&kex.enctype, ENC_ALG));
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
    fn known_hosts_text_trusts_and_revokes_keys() {
        let private_key = ed25519_private_key();
        let public_key = private_key.public_key();
        let key = public_key.to_bytes().unwrap();
        let trusted = format!("example.com {}", public_key.to_string());
        let revoked =
            format!("@revoked example.com {}", public_key.to_string());

        assert_eq!(
            known_hosts_trust_text("example.com", &key, &trusted),
            HostTrust::Trusted
        );
        assert_eq!(
            known_hosts_trust_text("example.com", &key, &revoked),
            HostTrust::Revoked
        );
        assert_eq!(
            known_hosts_trust_text("other.example", &key, &trusted),
            HostTrust::NotFound
        );
    }

    #[test]
    fn hashed_known_host_patterns_match_hmac_sha1() {
        type HmacSha1 = Hmac<Sha1>;

        let salt = b"salt";
        let mut mac = HmacSha1::new_from_slice(salt).unwrap();
        mac.update(b"example.com");
        let hash: [u8; 20] = mac.finalize().into_bytes().into();
        let patterns = HostPatterns::HashedName {
            salt: salt.to_vec(),
            hash,
        };

        assert!(known_host_patterns_match(&patterns, "example.com"));
        assert!(!known_host_patterns_match(&patterns, "other.example"));
    }

    fn sshfp_packet(host: &str, algorithm: u8, digest: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x8020u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&(DNS_TYPE_SSHFP as u16).to_be_bytes());
        packet.extend_from_slice(&(DNS_CLASS_IN as u16).to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&(DNS_TYPE_SSHFP as u16).to_be_bytes());
        packet.extend_from_slice(&(DNS_CLASS_IN as u16).to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&((digest.len() + 2) as u16).to_be_bytes());
        packet.push(algorithm);
        packet.push(SSHFP_HASH_SHA256);
        packet.extend_from_slice(digest);
        packet
    }

    #[test]
    fn sshfp_parser_requires_ad_and_matches_digest() {
        let private_key = ed25519_private_key();
        let key = private_key.public_key().to_bytes().unwrap();
        let digest = Sha256::digest(&key);
        let packet = sshfp_packet("example.com", SSHFP_KEY_ED25519, &digest);
        let records = parse_sshfp_response(&packet).unwrap();

        assert_eq!(records.len(), 1);
        assert!(sshfp_record_matches(&records[0], SSHFP_KEY_ED25519, &key));

        let mut insecure = packet;
        insecure[3] &= !DNS_FLAG_AD as u8;
        assert!(parse_sshfp_response(&insecure).is_none());
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

    #[test]
    fn cfx_sealed_wrap_round_trips_and_rejects_replay() {
        unsafe {
            let (mut initiator, mut acceptor) = cfx_test_contexts();
            let (token, sealed) =
                cfx_wrap_message(&mut initiator, true, b"sealed").unwrap();

            assert!(sealed);
            assert_eq!(&token[..2], &rfc4121::MESSAGE_TOKEN_ID);
            assert_eq!(token[2] & rfc4121::FLAG_SEALED, rfc4121::FLAG_SEALED);
            assert_eq!(initiator.send_seq, 1);

            let (message, sealed) =
                cfx_unwrap_message(&mut acceptor, &token).unwrap();
            assert!(sealed);
            assert_eq!(message, b"sealed");
            assert_eq!(acceptor.recv_seq, 1);

            assert_eq!(
                cfx_unwrap_message(&mut acceptor, &token).unwrap_err(),
                GSS_S_UNSEQ_TOKEN
            );
        }
    }

    #[test]
    fn cfx_signed_wrap_rejects_tampering() {
        unsafe {
            let (mut initiator, mut acceptor) = cfx_test_contexts();
            let (mut token, sealed) =
                cfx_wrap_message(&mut initiator, false, b"signed").unwrap();

            assert!(!sealed);
            assert_eq!(token[4..6], (CFX_HMAC_LEN as u16).to_be_bytes());
            *token.last_mut().unwrap() ^= 0x01;

            assert_eq!(
                cfx_unwrap_message(&mut acceptor, &token).unwrap_err(),
                GSS_S_BAD_SIG
            );
        }
    }

    #[test]
    fn cfx_iov_split_wrap_round_trips() {
        unsafe {
            let (mut initiator, mut acceptor) = cfx_test_contexts();
            let original = b"iov sealed message";
            let mut data = original.to_vec();
            let mut header = [0u8; CFX_HEADER_LEN];
            let mut trailer = [0u8; CFX_HEADER_LEN + CFX_GCM_TAG_LEN];
            let mut iovs = [
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_HEADER,
                    buffer: gss_buffer_desc {
                        length: header.len(),
                        value: header.as_mut_ptr().cast(),
                    },
                },
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_DATA,
                    buffer: gss_buffer_desc {
                        length: data.len(),
                        value: data.as_mut_ptr().cast(),
                    },
                },
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_TRAILER,
                    buffer: gss_buffer_desc {
                        length: trailer.len(),
                        value: trailer.as_mut_ptr().cast(),
                    },
                },
            ];
            let mut minor = 0;
            let mut conf_state = 0;

            assert_eq!(
                gss_wrap_iov(
                    &mut minor,
                    (&mut initiator as *mut SshKeyCtx).cast(),
                    1,
                    0,
                    &mut conf_state,
                    iovs.as_mut_ptr(),
                    iovs.len() as c_int,
                ),
                GSS_S_COMPLETE
            );
            assert_eq!(conf_state, 1);
            assert_eq!(iovs[0].buffer.length, CFX_HEADER_LEN);
            assert_eq!(iovs[2].buffer.length, CFX_HEADER_LEN + CFX_GCM_TAG_LEN);

            assert_eq!(
                gss_unwrap_iov(
                    &mut minor,
                    (&mut acceptor as *mut SshKeyCtx).cast(),
                    &mut conf_state,
                    ptr::null_mut(),
                    iovs.as_mut_ptr(),
                    iovs.len() as c_int,
                ),
                GSS_S_COMPLETE
            );
            assert_eq!(conf_state, 1);
            assert_eq!(data, original);
        }
    }

    #[test]
    fn cfx_iov_sign_only_is_authenticated() {
        unsafe {
            let (mut initiator, mut acceptor) = cfx_test_contexts();
            let original = b"iov sealed message";
            let mut aad = b"metadata".to_vec();
            let mut data = original.to_vec();
            let mut header = [0u8; CFX_HEADER_LEN];
            let mut trailer = [0u8; CFX_HEADER_LEN + CFX_GCM_TAG_LEN];
            let mut iovs = [
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_HEADER,
                    buffer: gss_buffer_desc {
                        length: header.len(),
                        value: header.as_mut_ptr().cast(),
                    },
                },
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_SIGN_ONLY,
                    buffer: gss_buffer_desc {
                        length: aad.len(),
                        value: aad.as_mut_ptr().cast(),
                    },
                },
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_DATA,
                    buffer: gss_buffer_desc {
                        length: data.len(),
                        value: data.as_mut_ptr().cast(),
                    },
                },
                gss_iov_buffer_desc {
                    type_: GSS_IOV_BUFFER_TYPE_TRAILER,
                    buffer: gss_buffer_desc {
                        length: trailer.len(),
                        value: trailer.as_mut_ptr().cast(),
                    },
                },
            ];
            let mut minor = 0;
            let mut conf_state = 0;

            assert_eq!(
                gss_wrap_iov(
                    &mut minor,
                    (&mut initiator as *mut SshKeyCtx).cast(),
                    1,
                    0,
                    &mut conf_state,
                    iovs.as_mut_ptr(),
                    iovs.len() as c_int,
                ),
                GSS_S_COMPLETE
            );

            aad[0] ^= 0x01;
            assert_eq!(
                gss_unwrap_iov(
                    &mut minor,
                    (&mut acceptor as *mut SshKeyCtx).cast(),
                    &mut conf_state,
                    ptr::null_mut(),
                    iovs.as_mut_ptr(),
                    iovs.len() as c_int,
                ),
                GSS_S_BAD_SIG
            );

            aad[0] ^= 0x01;
            assert_eq!(
                gss_unwrap_iov(
                    &mut minor,
                    (&mut acceptor as *mut SshKeyCtx).cast(),
                    &mut conf_state,
                    ptr::null_mut(),
                    iovs.as_mut_ptr(),
                    iovs.len() as c_int,
                ),
                GSS_S_COMPLETE
            );
            assert_eq!(data, original);
        }
    }
}
