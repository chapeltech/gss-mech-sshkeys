#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;
use std::env;
use std::fs;
use std::io::Read;
use std::sync::OnceLock;

use asn1::sshkey::{
    EncCtx, EncSshKeyUserAuth, SshKeyHostAuth, SshKeyKEX,
    SshKeyServerContext, SshKeyStatus, SshKeyToken, SshKeyUserAuth,
};
use rasn::types::{Integer, OctetString};
use signature::{Signer, Verifier};
use ssh_key::{
    Algorithm, PrivateKey, PublicKey, Signature as SshSignature,
};

mod asn1 {
    #![allow(dead_code)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!(concat!(env!("OUT_DIR"), "/sshkey_asn1.rs"));
}

type OM_uint32 = u32;
type gss_cred_usage_t = i32;
type gss_qop_t = u32;
type gss_OID = *mut gss_OID_desc;
type gss_const_OID = *const gss_OID_desc;
type gss_OID_set = *mut gss_OID_set_desc;
type gss_const_OID_set = *const gss_OID_set_desc;
type gss_name_t = *mut gss_name_t_desc;
type gss_const_name_t = *const gss_name_t_desc;
type gss_buffer_t = *mut gss_buffer_desc;
type gss_iov_buffer_t = *mut gss_iov_buffer_desc;
type gss_const_ctx_id_t = *const c_void;
type gss_ctx_id_t = *mut c_void;
type gss_const_cred_id_t = *const c_void;
type gss_cred_id_t = *mut c_void;
type gss_channel_bindings_t = *const gss_channel_bindings_struct;
type c_int = i32;
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

const GSS_S_COMPLETE: OM_uint32 = 0;
const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
const GSS_S_BAD_MECH: OM_uint32 = 1 << 16;
const GSS_S_BAD_NAME: OM_uint32 = 2 << 16;
const GSS_S_BAD_SIG: OM_uint32 = 6 << 16;
const GSS_S_NO_CONTEXT: OM_uint32 = 8 << 16;
const GSS_S_DEFECTIVE_TOKEN: OM_uint32 = 9 << 16;
const GSS_S_FAILURE: OM_uint32 = 13 << 16;
const GSS_S_UNAVAILABLE: OM_uint32 = 16 << 16;
const GSS_S_UNSEQ_TOKEN: OM_uint32 = 1 << 3;
const GSS_C_BOTH: gss_cred_usage_t = 0;
const GSS_C_INDEFINITE: OM_uint32 = 0xffff_ffff;
const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
const GSS_C_CONF_FLAG: OM_uint32 = 16;
const GSS_C_INTEG_FLAG: OM_uint32 = 32;
const GSS_C_ANON_FLAG: OM_uint32 = 64;
const GSS_C_TRANS_FLAG: OM_uint32 = 256;
const GSS_C_CHANNEL_BOUND_FLAG: OM_uint32 = 2048;

const GSS_IOV_BUFFER_TYPE_EMPTY: OM_uint32 = 0;
const GSS_IOV_BUFFER_TYPE_DATA: OM_uint32 = 1;
const GSS_IOV_BUFFER_TYPE_HEADER: OM_uint32 = 2;
const GSS_IOV_BUFFER_TYPE_TRAILER: OM_uint32 = 7;
const GSS_IOV_BUFFER_TYPE_PADDING: OM_uint32 = 9;
const GSS_IOV_BUFFER_TYPE_STREAM: OM_uint32 = 10;
const GSS_IOV_BUFFER_TYPE_SIGN_ONLY: OM_uint32 = 11;
const GSS_IOV_BUFFER_TYPE_FLAG_MASK: OM_uint32 = 0xffff_0000;
const GSS_IOV_BUFFER_FLAG_ALLOCATE: OM_uint32 = 0x0001_0000;
const GSS_IOV_BUFFER_FLAG_ALLOCATED: OM_uint32 = 0x0002_0000;

const SSH_KEY_COMPLETE: u8 = 1;
const SSH_KEY_CONTINUE_NEEDED: u8 = 2;

const ENOMEM: OM_uint32 = 12;
const ENOTSUP: OM_uint32 = 95;
const EINVAL: OM_uint32 = 22;

static SSHKEY_OID_ELEMENTS: [u8; 9] =
    [0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f, 0x01];

const KEX_ALG: &[u8] = b"curve25519-sha256";
const ENC_ALG: &[u8] = b"aes256-gcm-sha256";
const SIG_ALGS: &[u8] =
    b"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss";
const SANON_KDF_LABEL: &[u8] = b"sanon-x25519";
const SANON_SESSION_KEY_LEN: usize = 16;
const X25519_PUBLIC_LEN: usize = 32;
const X25519_SHARED_LEN: usize = 32;
const CONTEXT_KEY_LEN: usize = 32;
const CFX_HEADER_LEN: usize = 16;
const CFX_WRAP_TOK_ID: [u8; 2] = [0x05, 0x04];
const CFX_FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const CFX_FLAG_SEALED: u8 = 0x02;
const CFX_FILLER: u8 = 0xff;
const CFX_HMAC_LEN: usize = 32;
const CFX_GCM_TAG_LEN: usize = 16;
const CFX_GCM_NONCE_LEN: usize = 12;
const SERVER_CONTEXT_LABEL: &[u8] = b"SSHKEY server context v1";
const USERAUTH_LABEL: &[u8] = b"SSHKEY userauth v1";
const HOSTAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey hostauth v1";
const HOSTCHALLENGE_TRANSCRIPT_LABEL: &[u8] =
    b"gss-sshkey hostchallenge v1";
const USERAUTH_TRANSCRIPT_LABEL: &[u8] = b"gss-sshkey userauth v1";
const SSHKEY_CTX_KEY_ENV: &str = "SSHKEY_CTX_KEY";
const SSHKEY_HOST_KEY_ENV: &str = "SSHKEY_HOST_KEY";
const SSHKEY_USER_KEY_ENV: &str = "SSHKEY_USER_KEY";
const SSHKEY_USER_ENV: &str = "SSHKEY_USER";

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

#[repr(C)]
pub struct gss_OID_desc {
    length: OM_uint32,
    elements: *mut c_void,
}

#[repr(C)]
pub struct gss_OID_set_desc {
    count: usize,
    elements: *mut gss_OID_desc,
}

#[repr(C)]
pub struct gss_buffer_desc {
    length: usize,
    value: *mut c_void,
}

#[repr(C)]
pub struct gss_channel_bindings_struct {
    initiator_addrtype: OM_uint32,
    initiator_address: gss_buffer_desc,
    acceptor_addrtype: OM_uint32,
    acceptor_address: gss_buffer_desc,
    application_data: gss_buffer_desc,
}

#[repr(C)]
pub struct gss_iov_buffer_desc {
    type_: OM_uint32,
    buffer: gss_buffer_desc,
}

#[repr(C)]
pub struct gss_name_t_desc {
    value: *mut c_void,
    length: u32,
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

unsafe fn set_minor(minor: *mut OM_uint32, value: OM_uint32) {
    if !minor.is_null() {
        *minor = value;
    }
}

unsafe fn clear_buffer(buf: gss_buffer_t) {
    if !buf.is_null() {
        (*buf).length = 0;
        (*buf).value = ptr::null_mut();
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

unsafe fn set_buffer_bytes(
    minor: *mut OM_uint32,
    buf: gss_buffer_t,
    bytes: &[u8],
) -> u32 {
    if buf.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let out = malloc_copy(bytes);
    if out.is_null() && !bytes.is_empty() {
        clear_buffer(buf);
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }

    (*buf).length = bytes.len();
    (*buf).value = out;
    set_minor(minor, 0);
    GSS_S_COMPLETE
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

fn iov_buffer_type(type_: OM_uint32) -> OM_uint32 {
    type_ & !GSS_IOV_BUFFER_TYPE_FLAG_MASK
}

fn iov_buffer_flags(type_: OM_uint32) -> OM_uint32 {
    type_ & GSS_IOV_BUFFER_TYPE_FLAG_MASK
}

unsafe fn iov_slice<'a>(
    iov: &'a gss_iov_buffer_desc,
) -> Result<&'a [u8], OM_uint32> {
    if iov.buffer.length == 0 {
        return Ok(&[]);
    }
    if iov.buffer.value.is_null() {
        return Err(GSS_S_FAILURE);
    }

    Ok(core::slice::from_raw_parts(
        iov.buffer.value.cast::<u8>(),
        iov.buffer.length,
    ))
}

unsafe fn iov_slice_mut<'a>(
    iov: &'a mut gss_iov_buffer_desc,
) -> Result<&'a mut [u8], OM_uint32> {
    if iov.buffer.length == 0 {
        return Ok(&mut []);
    }
    if iov.buffer.value.is_null() {
        return Err(GSS_S_FAILURE);
    }

    Ok(core::slice::from_raw_parts_mut(
        iov.buffer.value.cast::<u8>(),
        iov.buffer.length,
    ))
}

unsafe fn allocate_iov_buffer(
    iov: &mut gss_iov_buffer_desc,
    len: usize,
) -> Result<(), OM_uint32> {
    let flags = iov_buffer_flags(iov.type_);
    if (flags & GSS_IOV_BUFFER_FLAG_ALLOCATE) != 0 {
        let value = if len == 0 {
            ptr::null_mut()
        } else {
            libc::malloc(len)
        };
        if value.is_null() && len != 0 {
            return Err(GSS_S_FAILURE);
        }

        iov.buffer.length = len;
        iov.buffer.value = value;
        iov.type_ = iov_buffer_type(iov.type_)
            | ((flags & !GSS_IOV_BUFFER_FLAG_ALLOCATE)
                | GSS_IOV_BUFFER_FLAG_ALLOCATED);
        return Ok(());
    }

    if len != 0 && iov.buffer.value.is_null() {
        return Err(GSS_S_FAILURE);
    }
    if iov.buffer.length < len {
        return Err(GSS_S_FAILURE);
    }
    iov.buffer.length = len;
    Ok(())
}

unsafe fn set_iov_length(
    iov: &mut gss_iov_buffer_desc,
    len: usize,
) -> Result<(), OM_uint32> {
    if (iov.type_ & GSS_IOV_BUFFER_FLAG_ALLOCATE) != 0 {
        return allocate_iov_buffer(iov, len);
    }

    iov.buffer.length = len;
    Ok(())
}

unsafe fn release_iov_allocations(iov: gss_iov_buffer_t, iov_count: c_int) {
    if iov.is_null() || iov_count <= 0 {
        return;
    }

    let buffers = core::slice::from_raw_parts_mut(iov, iov_count as usize);
    for buffer in buffers {
        if (buffer.type_ & GSS_IOV_BUFFER_FLAG_ALLOCATED) != 0 {
            if !buffer.buffer.value.is_null() {
                libc::free(buffer.buffer.value);
            }
            buffer.buffer.length = 0;
            buffer.buffer.value = ptr::null_mut();
            buffer.type_ &= !GSS_IOV_BUFFER_FLAG_ALLOCATED;
        }
    }
}

fn cfx_trailer_len(sealed: bool) -> usize {
    if sealed {
        CFX_HEADER_LEN + CFX_GCM_TAG_LEN
    } else {
        CFX_HMAC_LEN
    }
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

fn initial_context_token(
    public_key: &[u8; X25519_PUBLIC_LEN],
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from_static(SIG_ALGS),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(public_key.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
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
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let kex = SshKeyKEX::new(
        OctetString::from_static(KEX_ALG),
        OctetString::from_static(ENC_ALG),
        OctetString::from(acceptor_sigtypes),
        Some(OctetString::from_static(KEX_ALG)),
        Some(OctetString::from(public_key.as_slice())),
        Some(OctetString::from_static(ENC_ALG)),
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
        hostauth,
        None,
        None,
        Some(sctx),
    );

    rasn::der::encode(&token)
}

fn initiator_final_token(
    kex: Option<SshKeyKEX>,
    encuserauth: Option<EncSshKeyUserAuth>,
    sctx: EncCtx,
) -> Result<Vec<u8>, rasn::error::EncodeError> {
    let token = SshKeyToken::new(
        token_status(SSH_KEY_COMPLETE),
        kex,
        None,
        encuserauth,
        None,
        Some(sctx),
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
    );
    let token = SshKeyToken::new(
        token_status(SSH_KEY_CONTINUE_NEEDED),
        Some(kex),
        None,
        None,
        None,
        Some(sctx),
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

fn alg_list_contains(list: &[u8], alg: &[u8]) -> bool {
    list.split(|byte| *byte == b',')
        .any(|item| item == alg)
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
    let private_key = read_private_key_from_env(SSHKEY_USER_KEY_ENV)?;
    let username = env::var(SSHKEY_USER_ENV)
        .or_else(|_| env::var("USER"))
        .unwrap_or_else(|_| "sshkey".to_string())
        .into_bytes();
    let public_key = private_key.public_key();
    let keytype = public_key.algorithm().as_str().as_bytes().to_vec();
    let key = public_key.to_bytes().ok()?;
    let sigtype = signature_algorithms(&private_key.algorithm())
        .into_iter()
        .find(|alg| alg_list_contains(acceptor_sigtypes, alg))
        .unwrap_or_else(|| keytype.clone());
    let input = user_signature_input(
        initiator_sigtypes,
        acceptor_sigtypes,
        initiator_public,
        acceptor_public,
        &username,
        &keytype,
        &key,
        &sigtype,
    )?;
    let (_, _, actual_sigtype, _) = sign_ssh_data(&private_key, &input)?;
    let input = user_signature_input(
        initiator_sigtypes,
        acceptor_sigtypes,
        initiator_public,
        acceptor_public,
        &username,
        &keytype,
        &key,
        &actual_sigtype,
    )?;
    let (_, _, sigtype, sig) = sign_ssh_data(&private_key, &input)?;
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

fn cfx_header(
    sender_acceptor: bool,
    sealed: bool,
    ec: u16,
    rrc: u16,
    seq: u64,
) -> [u8; CFX_HEADER_LEN] {
    // RFC 4121 section 4.2.6.2: Wrap tokens use TOK_ID 05 04,
    // one flags octet, FF filler, EC, RRC, and big-endian SND_SEQ.
    let mut header = [0u8; CFX_HEADER_LEN];
    header[..2].copy_from_slice(&CFX_WRAP_TOK_ID);
    header[2] = if sender_acceptor {
        CFX_FLAG_SENT_BY_ACCEPTOR
    } else {
        0
    };
    if sealed {
        header[2] |= CFX_FLAG_SEALED;
    }
    header[3] = CFX_FILLER;
    header[4..6].copy_from_slice(&ec.to_be_bytes());
    header[6..8].copy_from_slice(&rrc.to_be_bytes());
    header[8..16].copy_from_slice(&seq.to_be_bytes());
    header
}

fn cfx_header_with_zero_ec_rrc(header: &[u8; CFX_HEADER_LEN]) -> [u8; 16] {
    let mut out = *header;
    out[4..8].fill(0);
    out
}

fn cfx_header_with_zero_rrc(header: &[u8; CFX_HEADER_LEN]) -> [u8; 16] {
    let mut out = *header;
    out[6..8].fill(0);
    out
}

fn cfx_unrotate_body(body: &[u8], rrc: u16) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }

    let shift = usize::from(rrc) % body.len();
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[shift..]);
    out.extend_from_slice(&body[..shift]);
    out
}

fn cfx_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
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

unsafe fn cfx_wrap_message_with_aad(
    ctx: &mut SshKeyCtx,
    conf_req: bool,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    if !ctx.complete {
        return Err(GSS_S_NO_CONTEXT);
    }
    let Some(session_key) = ctx.session_key.as_ref() else {
        return Err(GSS_S_NO_CONTEXT);
    };

    let sender_acceptor = !ctx.is_initiator;
    let seq = ctx.send_seq;

    if conf_req {
        // RFC 4121 section 4.2.4: confidential Wrap encrypts
        // plaintext-data | filler | header.  We use zero filler.
        let header = cfx_header(sender_acceptor, true, 0, 0, seq);
        let key = derive_cfx_key(session_key, sender_acceptor, true)
            .ok_or(GSS_S_FAILURE)?;
        let nonce = derive_cfx_nonce(&key, sender_acceptor, seq)
            .ok_or(GSS_S_FAILURE)?;
        let mut sealed = Vec::with_capacity(plaintext.len() + CFX_HEADER_LEN);
        sealed.extend_from_slice(plaintext);
        sealed.extend_from_slice(&header);

        let body = aes_256_gcm_encrypt(&key, &nonce, aad, &sealed)
            .ok_or(GSS_S_FAILURE)?;
        let mut token = Vec::with_capacity(CFX_HEADER_LEN + body.len());
        token.extend_from_slice(&header);
        token.extend_from_slice(&body);
        ctx.send_seq = ctx.send_seq.wrapping_add(1);
        return Ok((token, true));
    }

    // RFC 4121 section 4.2.4: non-confidential Wrap signs the plaintext
    // followed by the header with EC and RRC zeroed for checksum input.
    let checksum_header = cfx_header(sender_acceptor, false, 0, 0, seq);
    let key = derive_cfx_key(session_key, sender_acceptor, false)
        .ok_or(GSS_S_FAILURE)?;
    let mut signed =
        Vec::with_capacity(aad.len() + plaintext.len() + CFX_HEADER_LEN);
    signed.extend_from_slice(aad);
    signed.extend_from_slice(plaintext);
    signed.extend_from_slice(&checksum_header);
    let checksum = hmac_sha256(&key, &signed).ok_or(GSS_S_FAILURE)?;
    let header =
        cfx_header(sender_acceptor, false, CFX_HMAC_LEN as u16, 0, seq);

    let mut token =
        Vec::with_capacity(CFX_HEADER_LEN + plaintext.len() + checksum.len());
    token.extend_from_slice(&header);
    token.extend_from_slice(plaintext);
    token.extend_from_slice(&checksum);
    ctx.send_seq = ctx.send_seq.wrapping_add(1);
    Ok((token, false))
}

#[cfg(test)]
unsafe fn cfx_unwrap_message(
    ctx: &mut SshKeyCtx,
    token: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    cfx_unwrap_message_with_aad(ctx, token, &[])
}

unsafe fn cfx_unwrap_message_with_aad(
    ctx: &mut SshKeyCtx,
    token: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), OM_uint32> {
    if !ctx.complete {
        return Err(GSS_S_NO_CONTEXT);
    }
    let Some(session_key) = ctx.session_key.as_ref() else {
        return Err(GSS_S_NO_CONTEXT);
    };
    if token.len() < CFX_HEADER_LEN {
        return Err(GSS_S_DEFECTIVE_TOKEN);
    }

    let mut header = [0u8; CFX_HEADER_LEN];
    header.copy_from_slice(&token[..CFX_HEADER_LEN]);
    if header[..2] != CFX_WRAP_TOK_ID || header[3] != CFX_FILLER {
        return Err(GSS_S_DEFECTIVE_TOKEN);
    }

    let sender_acceptor = (header[2] & CFX_FLAG_SENT_BY_ACCEPTOR) != 0;
    if sender_acceptor != ctx.is_initiator {
        return Err(GSS_S_BAD_SIG);
    }
    let sealed = (header[2] & CFX_FLAG_SEALED) != 0;
    let ec = u16::from_be_bytes([header[4], header[5]]) as usize;
    let rrc = u16::from_be_bytes([header[6], header[7]]);
    let seq = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if seq != ctx.recv_seq {
        return Err(GSS_S_UNSEQ_TOKEN);
    }

    let body = cfx_unrotate_body(&token[CFX_HEADER_LEN..], rrc);
    let plaintext = if sealed {
        let key = derive_cfx_key(session_key, sender_acceptor, true)
            .ok_or(GSS_S_FAILURE)?;
        let nonce = derive_cfx_nonce(&key, sender_acceptor, seq)
            .ok_or(GSS_S_FAILURE)?;
        let sealed = aes_256_gcm_decrypt(&key, &nonce, aad, &body)
            .ok_or(GSS_S_BAD_SIG)?;
        if sealed.len() < CFX_HEADER_LEN {
            return Err(GSS_S_DEFECTIVE_TOKEN);
        }
        let split = sealed.len() - CFX_HEADER_LEN;
        let (message, encrypted_header) = sealed.split_at(split);
        // RFC 4121 section 4.2.4 requires the encrypted header copy to
        // have RRC zero, even when the clear header uses rotation.
        let expected_header = cfx_header_with_zero_rrc(&header);
        if !cfx_constant_time_eq(encrypted_header, &expected_header) {
            return Err(GSS_S_BAD_SIG);
        }
        message.to_vec()
    } else {
        if ec != CFX_HMAC_LEN || body.len() < ec {
            return Err(GSS_S_DEFECTIVE_TOKEN);
        }
        let split = body.len() - ec;
        let (message, checksum) = body.split_at(split);
        let key = derive_cfx_key(session_key, sender_acceptor, false)
            .ok_or(GSS_S_FAILURE)?;
        let checksum_header = cfx_header_with_zero_ec_rrc(&header);
        let mut signed =
            Vec::with_capacity(aad.len() + message.len() + CFX_HEADER_LEN);
        signed.extend_from_slice(aad);
        signed.extend_from_slice(message);
        signed.extend_from_slice(&checksum_header);
        let expected = hmac_sha256(&key, &signed).ok_or(GSS_S_FAILURE)?;
        if !cfx_constant_time_eq(checksum, &expected) {
            return Err(GSS_S_BAD_SIG);
        }
        message.to_vec()
    };

    ctx.recv_seq = ctx.recv_seq.wrapping_add(1);
    Ok((plaintext, sealed))
}

unsafe fn iov_buffers<'a>(
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> Result<&'a mut [gss_iov_buffer_desc], OM_uint32> {
    if iov_count < 0 {
        return Err(GSS_S_FAILURE);
    }
    if iov_count == 0 {
        return Ok(&mut []);
    }
    if iov.is_null() {
        return Err(GSS_S_FAILURE);
    }

    Ok(core::slice::from_raw_parts_mut(iov, iov_count as usize))
}

fn find_iov(iovs: &[gss_iov_buffer_desc], type_: OM_uint32) -> Option<usize> {
    iovs.iter()
        .position(|iov| iov_buffer_type(iov.type_) == type_)
}

fn iov_contains(iovs: &[gss_iov_buffer_desc], type_: OM_uint32) -> bool {
    find_iov(iovs, type_).is_some()
}

fn validate_iov_types(iovs: &[gss_iov_buffer_desc]) -> Result<(), OM_uint32> {
    for iov in iovs {
        match iov_buffer_type(iov.type_) {
            GSS_IOV_BUFFER_TYPE_EMPTY
            | GSS_IOV_BUFFER_TYPE_DATA
            | GSS_IOV_BUFFER_TYPE_HEADER
            | GSS_IOV_BUFFER_TYPE_TRAILER
            | GSS_IOV_BUFFER_TYPE_PADDING
            | GSS_IOV_BUFFER_TYPE_STREAM
            | GSS_IOV_BUFFER_TYPE_SIGN_ONLY => {}
            _ => return Err(GSS_S_UNAVAILABLE),
        }
    }
    Ok(())
}

unsafe fn collect_data_iovs(
    iovs: &[gss_iov_buffer_desc],
) -> Result<Vec<u8>, OM_uint32> {
    collect_iovs_by_type(iovs, GSS_IOV_BUFFER_TYPE_DATA)
}

unsafe fn collect_sign_only_iovs(
    iovs: &[gss_iov_buffer_desc],
) -> Result<Vec<u8>, OM_uint32> {
    collect_iovs_by_type(iovs, GSS_IOV_BUFFER_TYPE_SIGN_ONLY)
}

unsafe fn collect_iovs_by_type(
    iovs: &[gss_iov_buffer_desc],
    type_: OM_uint32,
) -> Result<Vec<u8>, OM_uint32> {
    let len = iov_type_len(iovs, type_)?;
    let mut out = Vec::with_capacity(len);
    for iov in iovs {
        if iov_buffer_type(iov.type_) == type_ {
            out.extend_from_slice(iov_slice(iov)?);
        }
    }
    Ok(out)
}

fn iov_data_len(iovs: &[gss_iov_buffer_desc]) -> Result<usize, OM_uint32> {
    iov_type_len(iovs, GSS_IOV_BUFFER_TYPE_DATA)
}

fn iov_type_len(
    iovs: &[gss_iov_buffer_desc],
    type_: OM_uint32,
) -> Result<usize, OM_uint32> {
    let mut len = 0usize;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == type_ {
            len = len.checked_add(iov.buffer.length).ok_or(GSS_S_FAILURE)?;
        }
    }
    Ok(len)
}

unsafe fn copy_data_to_iovs(
    iovs: &mut [gss_iov_buffer_desc],
    data: &[u8],
) -> Result<(), OM_uint32> {
    let mut offset = 0usize;
    for iov in iovs {
        if iov_buffer_type(iov.type_) != GSS_IOV_BUFFER_TYPE_DATA {
            continue;
        }

        let len = iov.buffer.length;
        if data.len().checked_sub(offset).ok_or(GSS_S_FAILURE)? < len {
            return Err(GSS_S_DEFECTIVE_TOKEN);
        }
        let dst = iov_slice_mut(iov)?;
        if len != 0 {
            dst.copy_from_slice(&data[offset..offset + len]);
        }
        offset += len;
    }

    if offset != data.len() {
        return Err(GSS_S_DEFECTIVE_TOKEN);
    }
    Ok(())
}

unsafe fn set_iov_bytes(
    iov: &mut gss_iov_buffer_desc,
    bytes: &[u8],
) -> Result<(), OM_uint32> {
    allocate_iov_buffer(iov, bytes.len())?;
    let dst = iov_slice_mut(iov)?;
    if !bytes.is_empty() {
        dst.copy_from_slice(bytes);
    }
    Ok(())
}

unsafe fn set_iov_lengths(
    iovs: &mut [gss_iov_buffer_desc],
    conf_req: bool,
) -> Result<(), OM_uint32> {
    let data_len = iov_data_len(iovs)?;
    let trailer_len = cfx_trailer_len(conf_req);

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        let len = CFX_HEADER_LEN
            .checked_add(data_len)
            .and_then(|len| len.checked_add(trailer_len))
            .ok_or(GSS_S_FAILURE)?;
        set_iov_length(&mut iovs[stream], len)?;
        return Ok(());
    }

    let header =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER).ok_or(GSS_S_FAILURE)?;
    let trailer =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER).ok_or(GSS_S_FAILURE)?;

    set_iov_length(&mut iovs[header], CFX_HEADER_LEN)?;
    set_iov_length(&mut iovs[trailer], trailer_len)?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            set_iov_length(iov, 0)?;
        }
    }
    Ok(())
}

unsafe fn cfx_wrap_iov_message(
    ctx: &mut SshKeyCtx,
    conf_req: bool,
    iovs: &mut [gss_iov_buffer_desc],
) -> Result<bool, OM_uint32> {
    validate_iov_types(iovs)?;
    let plaintext = collect_data_iovs(iovs)?;
    let aad = collect_sign_only_iovs(iovs)?;
    let (token, sealed) =
        cfx_wrap_message_with_aad(ctx, conf_req, &plaintext, &aad)?;
    let trailer_len = cfx_trailer_len(sealed);
    if token.len() != CFX_HEADER_LEN + plaintext.len() + trailer_len {
        return Err(GSS_S_FAILURE);
    }

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        if iov_contains(iovs, GSS_IOV_BUFFER_TYPE_HEADER)
            || iov_contains(iovs, GSS_IOV_BUFFER_TYPE_TRAILER)
        {
            return Err(GSS_S_FAILURE);
        }
        set_iov_bytes(&mut iovs[stream], &token)?;
        return Ok(sealed);
    }

    let header =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER).ok_or(GSS_S_FAILURE)?;
    let trailer =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER).ok_or(GSS_S_FAILURE)?;
    let body_end = CFX_HEADER_LEN + plaintext.len();

    set_iov_bytes(&mut iovs[header], &token[..CFX_HEADER_LEN])?;
    copy_data_to_iovs(iovs, &token[CFX_HEADER_LEN..body_end])?;
    set_iov_bytes(&mut iovs[trailer], &token[body_end..])?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            allocate_iov_buffer(iov, 0)?;
        }
    }

    Ok(sealed)
}

unsafe fn cfx_unwrap_iov_message(
    ctx: &mut SshKeyCtx,
    iovs: &mut [gss_iov_buffer_desc],
) -> Result<bool, OM_uint32> {
    validate_iov_types(iovs)?;
    let aad = collect_sign_only_iovs(iovs)?;

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        let token = iov_slice(&iovs[stream])?.to_vec();
        let (message, sealed) = cfx_unwrap_message_with_aad(ctx, &token, &aad)?;
        let data =
            find_iov(iovs, GSS_IOV_BUFFER_TYPE_DATA).ok_or(GSS_S_FAILURE)?;
        set_iov_bytes(&mut iovs[data], &message)?;
        return Ok(sealed);
    }

    let header =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER).ok_or(GSS_S_FAILURE)?;
    let trailer =
        find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER).ok_or(GSS_S_FAILURE)?;

    let mut token = Vec::new();
    token.extend_from_slice(iov_slice(&iovs[header])?);
    for iov in iovs.iter() {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_DATA {
            token.extend_from_slice(iov_slice(iov)?);
        }
    }
    token.extend_from_slice(iov_slice(&iovs[trailer])?);

    let (message, sealed) = cfx_unwrap_message_with_aad(ctx, &token, &aad)?;
    copy_data_to_iovs(iovs, &message)?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            allocate_iov_buffer(iov, 0)?;
        }
    }

    Ok(sealed)
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
        let ctx = Box::new(SshKeyCtx::new(true));
        *context = Box::into_raw(ctx).cast();
    }
    let ctx = &mut *((*context).cast::<SshKeyCtx>());

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
        let server_first = ctx.public_key.is_none() || ctx.ecdh_key.is_none();
        if server_first {
            let Some((private_key, public_key)) = generate_x25519_keypair()
            else {
                set_minor(minor, EINVAL);
                return GSS_S_FAILURE;
            };
            ctx.ecdh_key = Some(private_key);
            ctx.public_key = Some(public_key);
            ctx.initiator_sigtypes = SIG_ALGS.to_vec();
        }
        let initiator_public = ctx.public_key.unwrap();
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
            ))
        } else {
            None
        };
        let ret = encode_output_token(
            minor,
            output_token,
            initiator_final_token(
                response_kex,
                encuserauth,
                EncCtx::new(OctetString::from(server_context)),
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
    ctx.ecdh_key = Some(private_key);
    ctx.public_key = Some(public_key);
    ctx.peer_public_key = None;
    ctx.session_key = None;
    ctx.initiator_sigtypes = SIG_ALGS.to_vec();
    ctx.acceptor_sigtypes = SIG_ALGS.to_vec();
    ctx.server_context = None;
    ctx.authenticated = false;
    ctx.send_seq = 0;
    ctx.recv_seq = 0;
    ctx.complete = false;

    let ret = encode_output_token(
        minor,
        output_token,
        initial_context_token(&public_key),
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
        let Some((private_key, acceptor_public)) = generate_x25519_keypair()
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
        let server_context = SshKeyServerContext::new(
            Some(OctetString::from(initiator_public.as_slice())),
            OctetString::from(acceptor_public.as_slice()),
            Some(OctetString::from(session_key.as_slice())),
            Some(OctetString::from(initiator_sigtypes.as_slice())),
            OctetString::from(acceptor_sigtypes.as_slice()),
            None,
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
    let Some(acceptor_public) = server_context.acceptor_pk.as_ref()
        .try_into()
        .ok()
    else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let token_initiator_public = token
        .kex
        .as_ref()
        .and_then(validate_initiator_kex);
    let initiator_public = if let Some(value) =
        server_context.initiator_pk.as_ref()
    {
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
    let session_key = if let Some(value) = server_context.session_key.as_ref()
    {
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
        session_key
    };
    let initiator_sigtypes = if let Some(value) =
        server_context.initiator_sigtypes.as_ref()
    {
        value.as_ref().to_vec()
    } else if let Some(kex) = token.kex.as_ref() {
        kex.sigtypes.as_ref().to_vec()
    } else {
        set_minor(minor, EINVAL);
        return GSS_S_DEFECTIVE_TOKEN;
    };
    let acceptor_sigtypes = server_context.acceptor_sigtypes.as_ref().to_vec();
    let mut display_name = b"sshkey".to_vec();
    let mut authenticated = false;

    if let Some(encuserauth) = token.encuserauth.as_ref() {
        let Some(userauth) = decrypt_userauth(&session_key, encuserauth)
        else {
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
    _ctx: gss_const_ctx_id_t,
    _conf_req_flag: i32,
    _qop_req: gss_qop_t,
    req_output_size: OM_uint32,
    max_input_size: *mut OM_uint32,
) -> OM_uint32 {
    if !max_input_size.is_null() {
        let overhead = CFX_HEADER_LEN + CFX_HEADER_LEN + CFX_GCM_TAG_LEN;
        *max_input_size = req_output_size.saturating_sub(overhead as u32);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
    clear_buffer(output);
    if !conf_state.is_null() {
        *conf_state = 0;
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }
    if input.is_null() || output.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    if (*input).length != 0 && (*input).value.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let mut data = core::slice::from_raw_parts(
        (*input).value.cast::<u8>(),
        (*input).length,
    )
    .to_vec();
    let mut iovs = [
        gss_iov_buffer_desc {
            type_: GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE,
            buffer: gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
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
            type_: GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE,
            buffer: gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            },
        },
    ];

    let major = gss_wrap_iov_inner(
        minor,
        ctx.cast_mut(),
        conf_req_flag,
        qop_req,
        conf_state,
        iovs.as_mut_ptr(),
        iovs.len() as c_int,
    );
    if major != GSS_S_COMPLETE {
        release_iov_allocations(iovs.as_mut_ptr(), iovs.len() as c_int);
        return major;
    }

    let header = iov_slice(&iovs[0]).unwrap_or(&[]);
    let wrapped_data = iov_slice(&iovs[1]).unwrap_or(&[]);
    let trailer = iov_slice(&iovs[2]).unwrap_or(&[]);
    let mut token =
        Vec::with_capacity(header.len() + wrapped_data.len() + trailer.len());
    token.extend_from_slice(header);
    token.extend_from_slice(wrapped_data);
    token.extend_from_slice(trailer);

    let ret = set_buffer_bytes(minor, output, &token);
    release_iov_allocations(iovs.as_mut_ptr(), iovs.len() as c_int);
    if ret != GSS_S_COMPLETE {
        return ret;
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
    clear_buffer(output);
    if !conf_state.is_null() {
        *conf_state = 0;
    }
    if !qop_state.is_null() {
        *qop_state = 0;
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }
    if input.is_null() || output.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }
    if (*input).length != 0 && (*input).value.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let mut iovs = [
        gss_iov_buffer_desc {
            type_: GSS_IOV_BUFFER_TYPE_STREAM,
            buffer: gss_buffer_desc {
                length: (*input).length,
                value: (*input).value,
            },
        },
        gss_iov_buffer_desc {
            type_: GSS_IOV_BUFFER_TYPE_DATA | GSS_IOV_BUFFER_FLAG_ALLOCATE,
            buffer: gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            },
        },
    ];

    let major = gss_unwrap_iov_inner(
        minor,
        ctx.cast_mut(),
        conf_state,
        qop_state,
        iovs.as_mut_ptr(),
        iovs.len() as c_int,
    );
    if major != GSS_S_COMPLETE {
        release_iov_allocations(iovs.as_mut_ptr(), iovs.len() as c_int);
        return major;
    }

    (*output).length = iovs[1].buffer.length;
    (*output).value = iovs[1].buffer.value;
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
    if !conf_state.is_null() {
        *conf_state = i32::from(conf_req_flag != 0);
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }

    let iovs = match iov_buffers(iov, iov_count) {
        Ok(iovs) => iovs,
        Err(major) => {
            set_minor(minor, EINVAL);
            return major;
        }
    };
    if let Err(major) = validate_iov_types(iovs)
        .and_then(|_| set_iov_lengths(iovs, conf_req_flag != 0))
    {
        set_minor(
            minor,
            if major == GSS_S_UNAVAILABLE {
                ENOTSUP
            } else {
                EINVAL
            },
        );
        return major;
    }

    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn gss_wrap_iov_inner(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_req_flag: i32,
    _qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    if !conf_state.is_null() {
        *conf_state = 0;
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }

    let iovs = match iov_buffers(iov, iov_count) {
        Ok(iovs) => iovs,
        Err(major) => {
            set_minor(minor, EINVAL);
            return major;
        }
    };
    let ctx = &mut *(ctx.cast::<SshKeyCtx>());
    let sealed = match cfx_wrap_iov_message(ctx, conf_req_flag != 0, iovs) {
        Ok(sealed) => sealed,
        Err(major) => {
            set_minor(
                minor,
                if major == GSS_S_UNAVAILABLE {
                    ENOTSUP
                } else {
                    EINVAL
                },
            );
            return major;
        }
    };

    if !conf_state.is_null() {
        *conf_state = i32::from(sealed);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
    gss_wrap_iov_inner(
        minor,
        ctx,
        conf_req_flag,
        qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

unsafe fn gss_unwrap_iov_inner(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    if !conf_state.is_null() {
        *conf_state = 0;
    }
    if !qop_state.is_null() {
        *qop_state = 0;
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }

    let iovs = match iov_buffers(iov, iov_count) {
        Ok(iovs) => iovs,
        Err(major) => {
            set_minor(minor, EINVAL);
            return major;
        }
    };
    let ctx = &mut *(ctx.cast::<SshKeyCtx>());
    let sealed = match cfx_unwrap_iov_message(ctx, iovs) {
        Ok(sealed) => sealed,
        Err(major) => {
            set_minor(
                minor,
                if major == GSS_S_UNAVAILABLE {
                    ENOTSUP
                } else {
                    EINVAL
                },
            );
            return major;
        }
    };

    if !conf_state.is_null() {
        *conf_state = i32::from(sealed);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
    gss_unwrap_iov_inner(minor, ctx, conf_state, qop_state, iov, iov_count)
}

#[no_mangle]
pub unsafe extern "C" fn gss_release_iov_buffer(
    minor: *mut OM_uint32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    release_iov_allocations(iov, iov_count);
    set_minor(minor, 0);
    GSS_S_COMPLETE
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
        let output = initial_context_token(&public_key).unwrap();
        let inner = decapsulate_initial_token(&output).unwrap();
        let token = rasn::der::decode::<SshKeyToken>(inner).unwrap();

        assert!(token_has_status(&token, SSH_KEY_CONTINUE_NEEDED));
        let kex = token.kex.as_ref().unwrap();
        assert_eq!(kex_public_key(kex), Some(public_key));
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
    fn cfx_sealed_wrap_round_trips_and_rejects_replay() {
        unsafe {
            let (mut initiator, mut acceptor) = cfx_test_contexts();
            let (token, sealed) =
                cfx_wrap_message(&mut initiator, true, b"sealed").unwrap();

            assert!(sealed);
            assert_eq!(&token[..2], &CFX_WRAP_TOK_ID);
            assert_eq!(token[2] & CFX_FLAG_SEALED, CFX_FLAG_SEALED);
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
