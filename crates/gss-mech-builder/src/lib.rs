#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use core::ffi::c_void;
use core::ptr;

pub mod sys {
    use super::c_void;

    pub type OM_uint32 = u32;
    pub type gss_cred_usage_t = i32;
    pub type gss_qop_t = u32;
    pub type gss_OID = *mut gss_OID_desc;
    pub type gss_const_OID = *const gss_OID_desc;
    pub type gss_OID_set = *mut gss_OID_set_desc;
    pub type gss_const_OID_set = *const gss_OID_set_desc;
    pub type gss_name_t = *mut gss_name_t_desc;
    pub type gss_const_name_t = *const gss_name_t_desc;
    pub type gss_ctx_id_t = *mut c_void;
    pub type gss_const_ctx_id_t = *const c_void;
    pub type gss_const_cred_id_t = *const c_void;
    pub type gss_cred_id_t = *mut c_void;
    pub type gss_buffer_t = *mut gss_buffer_desc;
    pub type gss_iov_buffer_t = *mut gss_iov_buffer_desc;
    pub type gss_channel_bindings_t = *const gss_channel_bindings_struct;
    pub type c_int = i32;

    pub const GSS_S_COMPLETE: OM_uint32 = 0;
    pub const GSS_S_CONTINUE_NEEDED: OM_uint32 = 1;
    pub const GSS_S_BAD_MECH: OM_uint32 = 1 << 16;
    pub const GSS_S_BAD_NAME: OM_uint32 = 2 << 16;
    pub const GSS_S_BAD_SIG: OM_uint32 = 6 << 16;
    pub const GSS_S_NO_CONTEXT: OM_uint32 = 8 << 16;
    pub const GSS_S_DEFECTIVE_TOKEN: OM_uint32 = 9 << 16;
    pub const GSS_S_FAILURE: OM_uint32 = 13 << 16;
    pub const GSS_S_UNAVAILABLE: OM_uint32 = 16 << 16;
    pub const GSS_S_UNSEQ_TOKEN: OM_uint32 = 1 << 3;
    pub const GSS_C_BOTH: gss_cred_usage_t = 0;
    pub const GSS_C_INDEFINITE: OM_uint32 = 0xffff_ffff;
    pub const GSS_C_REPLAY_FLAG: OM_uint32 = 4;
    pub const GSS_C_SEQUENCE_FLAG: OM_uint32 = 8;
    pub const GSS_C_CONF_FLAG: OM_uint32 = 16;
    pub const GSS_C_INTEG_FLAG: OM_uint32 = 32;
    pub const GSS_C_ANON_FLAG: OM_uint32 = 64;
    pub const GSS_C_TRANS_FLAG: OM_uint32 = 256;
    pub const GSS_C_CHANNEL_BOUND_FLAG: OM_uint32 = 2048;

    pub const GSS_IOV_BUFFER_TYPE_EMPTY: OM_uint32 = 0;
    pub const GSS_IOV_BUFFER_TYPE_DATA: OM_uint32 = 1;
    pub const GSS_IOV_BUFFER_TYPE_HEADER: OM_uint32 = 2;
    pub const GSS_IOV_BUFFER_TYPE_TRAILER: OM_uint32 = 7;
    pub const GSS_IOV_BUFFER_TYPE_PADDING: OM_uint32 = 9;
    pub const GSS_IOV_BUFFER_TYPE_STREAM: OM_uint32 = 10;
    pub const GSS_IOV_BUFFER_TYPE_SIGN_ONLY: OM_uint32 = 11;
    pub const GSS_IOV_BUFFER_TYPE_FLAG_MASK: OM_uint32 = 0xffff_0000;
    pub const GSS_IOV_BUFFER_FLAG_ALLOCATE: OM_uint32 = 0x0001_0000;
    pub const GSS_IOV_BUFFER_FLAG_ALLOCATED: OM_uint32 = 0x0002_0000;

    pub const EINVAL: OM_uint32 = 22;
    pub const ENOMEM: OM_uint32 = 12;
    pub const ENOTSUP: OM_uint32 = 95;

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_OID_desc {
        pub length: OM_uint32,
        pub elements: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_OID_set_desc {
        pub count: usize,
        pub elements: *mut gss_OID_desc,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_buffer_desc {
        pub length: usize,
        pub value: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_channel_bindings_struct {
        pub initiator_addrtype: OM_uint32,
        pub initiator_address: gss_buffer_desc,
        pub acceptor_addrtype: OM_uint32,
        pub acceptor_address: gss_buffer_desc,
        pub application_data: gss_buffer_desc,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_iov_buffer_desc {
        pub type_: OM_uint32,
        pub buffer: gss_buffer_desc,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct gss_name_t_desc {
        pub value: *mut c_void,
        pub length: u32,
    }
}

use sys::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub major: OM_uint32,
    pub minor: OM_uint32,
}

impl Status {
    pub const fn new(major: OM_uint32, minor: OM_uint32) -> Self {
        Self { major, minor }
    }
}

pub trait Rfc4121Context {
    type Profile: rfc4121::CryptoProfile;

    fn role(&self) -> rfc4121::Role;
    fn send_seq(&self) -> u64;
    fn recv_seq(&self) -> u64;
    fn set_send_seq(&mut self, seq: u64);
    fn set_recv_seq(&mut self, seq: u64);
    fn profile(&self) -> Result<Self::Profile, Status>;
}

pub fn rfc4121_status(error: rfc4121::Error) -> Status {
    match error {
        rfc4121::Error::BadSignature => Status::new(GSS_S_BAD_SIG, EINVAL),
        rfc4121::Error::DefectiveToken => {
            Status::new(GSS_S_DEFECTIVE_TOKEN, EINVAL)
        }
        rfc4121::Error::Failure => Status::new(GSS_S_FAILURE, EINVAL),
        rfc4121::Error::Sequence => Status::new(GSS_S_UNSEQ_TOKEN, EINVAL),
    }
}

pub fn trailer_len<C: Rfc4121Context>(sealed: bool) -> usize {
    rfc4121::trailer_len::<C::Profile>(sealed)
}

pub fn protect_message<C: Rfc4121Context>(
    ctx: &mut C,
    seal: bool,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), Status> {
    let profile = ctx.profile()?;
    let mut state =
        rfc4121::TokenState::new(ctx.role(), ctx.send_seq(), ctx.recv_seq());
    let result = state
        .protect(&profile, seal, plaintext, aad)
        .map_err(rfc4121_status)?;
    ctx.set_send_seq(state.send_seq());
    Ok((result.token, result.sealed))
}

pub fn unprotect_message<C: Rfc4121Context>(
    ctx: &mut C,
    token: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, bool), Status> {
    let profile = ctx.profile()?;
    let mut state =
        rfc4121::TokenState::new(ctx.role(), ctx.send_seq(), ctx.recv_seq());
    let result = state
        .unprotect(&profile, token, aad)
        .map_err(rfc4121_status)?;
    ctx.set_recv_seq(state.recv_seq());
    Ok((result.plaintext, result.sealed))
}

pub fn get_mic_message<C: Rfc4121Context>(
    ctx: &mut C,
    message: &[u8],
) -> Result<Vec<u8>, Status> {
    let profile = ctx.profile()?;
    let mut state =
        rfc4121::TokenState::new(ctx.role(), ctx.send_seq(), ctx.recv_seq());
    let result = state.checksum(&profile, message).map_err(rfc4121_status)?;
    ctx.set_send_seq(state.send_seq());
    Ok(result.token)
}

pub fn verify_mic_message<C: Rfc4121Context>(
    ctx: &mut C,
    message: &[u8],
    token: &[u8],
) -> Result<(), Status> {
    let profile = ctx.profile()?;
    let mut state =
        rfc4121::TokenState::new(ctx.role(), ctx.send_seq(), ctx.recv_seq());
    state
        .verify_checksum(&profile, message, token)
        .map_err(rfc4121_status)?;
    ctx.set_recv_seq(state.recv_seq());
    Ok(())
}

pub unsafe fn set_minor(minor: *mut OM_uint32, value: OM_uint32) {
    if !minor.is_null() {
        *minor = value;
    }
}

pub unsafe fn clear_buffer(buf: gss_buffer_t) {
    if !buf.is_null() {
        (*buf).length = 0;
        (*buf).value = ptr::null_mut();
    }
}

pub unsafe fn set_buffer_bytes(
    minor: *mut OM_uint32,
    buf: gss_buffer_t,
    bytes: &[u8],
) -> OM_uint32 {
    if buf.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    clear_buffer(buf);
    if bytes.is_empty() {
        set_minor(minor, 0);
        return GSS_S_COMPLETE;
    }

    let value = libc::malloc(bytes.len());
    if value.is_null() {
        set_minor(minor, ENOMEM);
        return GSS_S_FAILURE;
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), value.cast::<u8>(), bytes.len());
    (*buf).length = bytes.len();
    (*buf).value = value;
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

unsafe fn buffer_slice<'a>(buf: gss_buffer_t) -> Result<&'a [u8], Status> {
    if buf.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }
    if (*buf).length != 0 && (*buf).value.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }

    Ok(core::slice::from_raw_parts(
        (*buf).value.cast::<u8>(),
        (*buf).length,
    ))
}

pub unsafe fn release_buffer(buf: gss_buffer_t) {
    if buf.is_null() {
        return;
    }
    if !(*buf).value.is_null() {
        libc::free((*buf).value);
    }
    (*buf).value = ptr::null_mut();
    (*buf).length = 0;
}

pub fn iov_buffer_type(type_: OM_uint32) -> OM_uint32 {
    type_ & !GSS_IOV_BUFFER_TYPE_FLAG_MASK
}

pub unsafe fn release_iov_allocations(iov: gss_iov_buffer_t, iov_count: c_int) {
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

unsafe fn allocate_iov_buffer(
    iov: &mut gss_iov_buffer_desc,
    len: usize,
) -> Result<(), Status> {
    if (iov.type_ & GSS_IOV_BUFFER_FLAG_ALLOCATE) == 0 {
        if len != 0 && iov.buffer.value.is_null() {
            return Err(Status::new(GSS_S_FAILURE, EINVAL));
        }
        if iov.buffer.length < len {
            return Err(Status::new(GSS_S_FAILURE, EINVAL));
        }
        iov.buffer.length = len;
        return Ok(());
    }

    if (iov.type_ & GSS_IOV_BUFFER_FLAG_ALLOCATED) != 0
        && !iov.buffer.value.is_null()
    {
        libc::free(iov.buffer.value);
    }

    let value = if len == 0 {
        ptr::null_mut()
    } else {
        libc::malloc(len)
    };
    if value.is_null() && len != 0 {
        return Err(Status::new(GSS_S_FAILURE, ENOMEM));
    }
    iov.buffer.length = len;
    iov.buffer.value = value;
    iov.type_ = iov_buffer_type(iov.type_)
        | ((iov.type_ & GSS_IOV_BUFFER_TYPE_FLAG_MASK)
            & !GSS_IOV_BUFFER_FLAG_ALLOCATE)
        | GSS_IOV_BUFFER_FLAG_ALLOCATED;
    Ok(())
}

unsafe fn set_iov_length(
    iov: &mut gss_iov_buffer_desc,
    len: usize,
) -> Result<(), Status> {
    if (iov.type_ & GSS_IOV_BUFFER_FLAG_ALLOCATE) != 0 {
        return allocate_iov_buffer(iov, len);
    }

    iov.buffer.length = len;
    Ok(())
}

unsafe fn iov_buffers<'a>(
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> Result<&'a mut [gss_iov_buffer_desc], Status> {
    if iov_count < 0 {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }
    if iov_count == 0 {
        return Ok(&mut []);
    }
    if iov.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
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

fn validate_iov_types(iovs: &[gss_iov_buffer_desc]) -> Result<(), Status> {
    for iov in iovs {
        match iov_buffer_type(iov.type_) {
            GSS_IOV_BUFFER_TYPE_EMPTY
            | GSS_IOV_BUFFER_TYPE_DATA
            | GSS_IOV_BUFFER_TYPE_HEADER
            | GSS_IOV_BUFFER_TYPE_TRAILER
            | GSS_IOV_BUFFER_TYPE_PADDING
            | GSS_IOV_BUFFER_TYPE_STREAM
            | GSS_IOV_BUFFER_TYPE_SIGN_ONLY => {}
            _ => return Err(Status::new(GSS_S_UNAVAILABLE, ENOTSUP)),
        }
    }
    Ok(())
}

unsafe fn iov_slice(iov: &gss_iov_buffer_desc) -> Result<&[u8], Status> {
    if iov.buffer.length == 0 {
        return Ok(&[]);
    }
    if iov.buffer.value.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }

    Ok(core::slice::from_raw_parts(
        iov.buffer.value.cast::<u8>(),
        iov.buffer.length,
    ))
}

unsafe fn iov_slice_mut(
    iov: &mut gss_iov_buffer_desc,
) -> Result<&mut [u8], Status> {
    if iov.buffer.length == 0 {
        return Ok(&mut []);
    }
    if iov.buffer.value.is_null() {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }

    Ok(core::slice::from_raw_parts_mut(
        iov.buffer.value.cast::<u8>(),
        iov.buffer.length,
    ))
}

unsafe fn collect_iovs_by_type(
    iovs: &[gss_iov_buffer_desc],
    type_: OM_uint32,
) -> Result<Vec<u8>, Status> {
    let len = iov_type_len(iovs, type_)?;
    let mut out = Vec::with_capacity(len);
    for iov in iovs {
        if iov_buffer_type(iov.type_) == type_ {
            out.extend_from_slice(iov_slice(iov)?);
        }
    }
    Ok(out)
}

fn iov_type_len(
    iovs: &[gss_iov_buffer_desc],
    type_: OM_uint32,
) -> Result<usize, Status> {
    let mut len = 0usize;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == type_ {
            len = len
                .checked_add(iov.buffer.length)
                .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
        }
    }
    Ok(len)
}

unsafe fn copy_data_to_iovs(
    iovs: &mut [gss_iov_buffer_desc],
    data: &[u8],
) -> Result<(), Status> {
    let mut offset = 0usize;
    for iov in iovs {
        if iov_buffer_type(iov.type_) != GSS_IOV_BUFFER_TYPE_DATA {
            continue;
        }

        let len = iov.buffer.length;
        if data.len().checked_sub(offset).unwrap_or(0) < len {
            return Err(Status::new(GSS_S_DEFECTIVE_TOKEN, EINVAL));
        }
        let dst = iov_slice_mut(iov)?;
        if len != 0 {
            dst.copy_from_slice(&data[offset..offset + len]);
        }
        offset += len;
    }

    if offset != data.len() {
        return Err(Status::new(GSS_S_DEFECTIVE_TOKEN, EINVAL));
    }
    Ok(())
}

unsafe fn set_iov_bytes(
    iov: &mut gss_iov_buffer_desc,
    bytes: &[u8],
) -> Result<(), Status> {
    allocate_iov_buffer(iov, bytes.len())?;
    let dst = iov_slice_mut(iov)?;
    if !bytes.is_empty() {
        dst.copy_from_slice(bytes);
    }
    Ok(())
}

pub unsafe fn set_iov_lengths<C: Rfc4121Context>(
    iovs: &mut [gss_iov_buffer_desc],
    seal: bool,
) -> Result<(), Status> {
    let data_len = iov_type_len(iovs, GSS_IOV_BUFFER_TYPE_DATA)?;
    let plan = rfc4121::buffer_plan::<C::Profile>(data_len, seal)
        .map_err(rfc4121_status)?;

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        set_iov_length(&mut iovs[stream], plan.stream_len)?;
        return Ok(());
    }

    let header = find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
    let trailer = find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;

    set_iov_length(&mut iovs[header], plan.header_len)?;
    set_iov_length(&mut iovs[trailer], plan.trailer_len)?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            set_iov_length(iov, 0)?;
        }
    }
    Ok(())
}

pub unsafe fn protect_iov_message<C: Rfc4121Context>(
    ctx: &mut C,
    seal: bool,
    iovs: &mut [gss_iov_buffer_desc],
) -> Result<bool, Status> {
    validate_iov_types(iovs)?;
    let plaintext = collect_iovs_by_type(iovs, GSS_IOV_BUFFER_TYPE_DATA)?;
    let aad = collect_iovs_by_type(iovs, GSS_IOV_BUFFER_TYPE_SIGN_ONLY)?;
    let (token, sealed) = protect_message(ctx, seal, &plaintext, &aad)?;
    let plan = rfc4121::buffer_plan::<C::Profile>(plaintext.len(), sealed)
        .map_err(rfc4121_status)?;
    if token.len() != plan.stream_len {
        return Err(Status::new(GSS_S_FAILURE, EINVAL));
    }

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        if iov_contains(iovs, GSS_IOV_BUFFER_TYPE_HEADER)
            || iov_contains(iovs, GSS_IOV_BUFFER_TYPE_TRAILER)
        {
            return Err(Status::new(GSS_S_FAILURE, EINVAL));
        }
        set_iov_bytes(&mut iovs[stream], &token)?;
        return Ok(sealed);
    }

    let header = find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
    let trailer = find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
    let body_end = plan.header_len + plaintext.len();

    set_iov_bytes(&mut iovs[header], &token[..plan.header_len])?;
    copy_data_to_iovs(iovs, &token[plan.header_len..body_end])?;
    set_iov_bytes(&mut iovs[trailer], &token[body_end..])?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            allocate_iov_buffer(iov, 0)?;
        }
    }

    Ok(sealed)
}

pub unsafe fn unprotect_iov_message<C: Rfc4121Context>(
    ctx: &mut C,
    iovs: &mut [gss_iov_buffer_desc],
) -> Result<bool, Status> {
    validate_iov_types(iovs)?;
    let aad = collect_iovs_by_type(iovs, GSS_IOV_BUFFER_TYPE_SIGN_ONLY)?;

    if let Some(stream) = find_iov(iovs, GSS_IOV_BUFFER_TYPE_STREAM) {
        let token = iov_slice(&iovs[stream])?.to_vec();
        let (message, sealed) = unprotect_message(ctx, &token, &aad)?;
        let data = find_iov(iovs, GSS_IOV_BUFFER_TYPE_DATA)
            .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
        set_iov_bytes(&mut iovs[data], &message)?;
        return Ok(sealed);
    }

    let header = find_iov(iovs, GSS_IOV_BUFFER_TYPE_HEADER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;
    let trailer = find_iov(iovs, GSS_IOV_BUFFER_TYPE_TRAILER)
        .ok_or(Status::new(GSS_S_FAILURE, EINVAL))?;

    let mut token = Vec::new();
    token.extend_from_slice(iov_slice(&iovs[header])?);
    for iov in iovs.iter() {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_DATA {
            token.extend_from_slice(iov_slice(iov)?);
        }
    }
    token.extend_from_slice(iov_slice(&iovs[trailer])?);

    let (message, sealed) = unprotect_message(ctx, &token, &aad)?;
    copy_data_to_iovs(iovs, &message)?;
    for iov in iovs {
        if iov_buffer_type(iov.type_) == GSS_IOV_BUFFER_TYPE_PADDING {
            allocate_iov_buffer(iov, 0)?;
        }
    }

    Ok(sealed)
}

pub unsafe fn wrap_size_limit<C: Rfc4121Context>(
    minor: *mut OM_uint32,
    _ctx: gss_const_ctx_id_t,
    conf_req_flag: i32,
    _qop_req: gss_qop_t,
    req_output_size: OM_uint32,
    max_input_size: *mut OM_uint32,
) -> OM_uint32 {
    if !max_input_size.is_null() {
        let overhead =
            rfc4121::HEADER_LEN + trailer_len::<C>(conf_req_flag != 0);
        *max_input_size = req_output_size.saturating_sub(overhead as u32);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

pub unsafe fn get_mic<C: Rfc4121Context>(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    _qop_req: gss_qop_t,
    message: gss_buffer_t,
    token: gss_buffer_t,
) -> OM_uint32 {
    clear_buffer(token);
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }
    if token.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_FAILURE;
    }

    let message = match buffer_slice(message) {
        Ok(message) => message,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    let ctx = &mut *(ctx.cast_mut().cast::<C>());
    let mic = match get_mic_message(ctx, message) {
        Ok(mic) => mic,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };

    set_buffer_bytes(minor, token, &mic)
}

pub unsafe fn verify_mic<C: Rfc4121Context>(
    minor: *mut OM_uint32,
    ctx: gss_const_ctx_id_t,
    message: gss_buffer_t,
    token: gss_buffer_t,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    if !qop_state.is_null() {
        *qop_state = 0;
    }
    if ctx.is_null() {
        set_minor(minor, EINVAL);
        return GSS_S_NO_CONTEXT;
    }

    let message = match buffer_slice(message) {
        Ok(message) => message,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    let token = match buffer_slice(token) {
        Ok(token) => token,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    let ctx = &mut *(ctx.cast_mut().cast::<C>());
    if let Err(status) = verify_mic_message(ctx, message, token) {
        set_minor(minor, status.minor);
        return status.major;
    }

    set_minor(minor, 0);
    GSS_S_COMPLETE
}

pub unsafe fn wrap<C: Rfc4121Context>(
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

    let mut data = match buffer_slice(input) {
        Ok(input) => input.to_vec(),
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
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

    let major = wrap_iov_inner::<C>(
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

pub unsafe fn unwrap<C: Rfc4121Context>(
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
    if let Err(status) = buffer_slice(input) {
        set_minor(minor, status.minor);
        return status.major;
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

    let major = unwrap_iov_inner::<C>(
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

pub unsafe fn wrap_iov_length<C: Rfc4121Context>(
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
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    if let Err(status) = validate_iov_types(iovs)
        .and_then(|_| set_iov_lengths::<C>(iovs, conf_req_flag != 0))
    {
        set_minor(minor, status.minor);
        return status.major;
    }

    set_minor(minor, 0);
    GSS_S_COMPLETE
}

pub unsafe fn wrap_iov_inner<C: Rfc4121Context>(
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
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    let ctx = &mut *(ctx.cast::<C>());
    let sealed = match protect_iov_message(ctx, conf_req_flag != 0, iovs) {
        Ok(sealed) => sealed,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };

    if !conf_state.is_null() {
        *conf_state = i32::from(sealed);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

pub unsafe fn wrap_iov<C: Rfc4121Context>(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    wrap_iov_inner::<C>(
        minor,
        ctx,
        conf_req_flag,
        qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

pub unsafe fn unwrap_iov_inner<C: Rfc4121Context>(
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
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };
    let ctx = &mut *(ctx.cast::<C>());
    let sealed = match unprotect_iov_message(ctx, iovs) {
        Ok(sealed) => sealed,
        Err(status) => {
            set_minor(minor, status.minor);
            return status.major;
        }
    };

    if !conf_state.is_null() {
        *conf_state = i32::from(sealed);
    }
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

pub unsafe fn unwrap_iov<C: Rfc4121Context>(
    minor: *mut OM_uint32,
    ctx: gss_ctx_id_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    unwrap_iov_inner::<C>(minor, ctx, conf_state, qop_state, iov, iov_count)
}

pub unsafe fn release_iov_buffer(
    minor: *mut OM_uint32,
    iov: gss_iov_buffer_t,
    iov_count: c_int,
) -> OM_uint32 {
    release_iov_allocations(iov, iov_count);
    set_minor(minor, 0);
    GSS_S_COMPLETE
}

#[macro_export]
macro_rules! export_rfc4121_per_message {
    ($ctx:ty) => {
        #[no_mangle]
        pub unsafe extern "C" fn gss_wrap_size_limit(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_const_ctx_id_t,
            conf_req_flag: i32,
            qop_req: $crate::sys::gss_qop_t,
            req_output_size: $crate::sys::OM_uint32,
            max_input_size: *mut $crate::sys::OM_uint32,
        ) -> $crate::sys::OM_uint32 {
            $crate::wrap_size_limit::<$ctx>(
                minor,
                ctx,
                conf_req_flag,
                qop_req,
                req_output_size,
                max_input_size,
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn gss_get_mic(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_const_ctx_id_t,
            qop_req: $crate::sys::gss_qop_t,
            message: $crate::sys::gss_buffer_t,
            token: $crate::sys::gss_buffer_t,
        ) -> $crate::sys::OM_uint32 {
            $crate::get_mic::<$ctx>(minor, ctx, qop_req, message, token)
        }

        #[no_mangle]
        pub unsafe extern "C" fn gss_verify_mic(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_const_ctx_id_t,
            message: $crate::sys::gss_buffer_t,
            token: $crate::sys::gss_buffer_t,
            qop_state: *mut $crate::sys::gss_qop_t,
        ) -> $crate::sys::OM_uint32 {
            $crate::verify_mic::<$ctx>(minor, ctx, message, token, qop_state)
        }

        #[no_mangle]
        pub unsafe extern "C" fn gss_wrap(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_const_ctx_id_t,
            conf_req_flag: i32,
            qop_req: $crate::sys::gss_qop_t,
            input: $crate::sys::gss_buffer_t,
            conf_state: *mut i32,
            output: $crate::sys::gss_buffer_t,
        ) -> $crate::sys::OM_uint32 {
            $crate::wrap::<$ctx>(
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
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_const_ctx_id_t,
            input: $crate::sys::gss_buffer_t,
            output: $crate::sys::gss_buffer_t,
            conf_state: *mut i32,
            qop_state: *mut $crate::sys::gss_qop_t,
        ) -> $crate::sys::OM_uint32 {
            $crate::unwrap::<$ctx>(
                minor, ctx, input, output, conf_state, qop_state,
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn gss_wrap_iov_length(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_ctx_id_t,
            conf_req_flag: i32,
            qop_req: $crate::sys::gss_qop_t,
            conf_state: *mut i32,
            iov: $crate::sys::gss_iov_buffer_t,
            iov_count: $crate::sys::c_int,
        ) -> $crate::sys::OM_uint32 {
            $crate::wrap_iov_length::<$ctx>(
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
        pub unsafe extern "C" fn gss_wrap_iov(
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_ctx_id_t,
            conf_req_flag: i32,
            qop_req: $crate::sys::gss_qop_t,
            conf_state: *mut i32,
            iov: $crate::sys::gss_iov_buffer_t,
            iov_count: $crate::sys::c_int,
        ) -> $crate::sys::OM_uint32 {
            $crate::wrap_iov::<$ctx>(
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
            minor: *mut $crate::sys::OM_uint32,
            ctx: $crate::sys::gss_ctx_id_t,
            conf_state: *mut i32,
            qop_state: *mut $crate::sys::gss_qop_t,
            iov: $crate::sys::gss_iov_buffer_t,
            iov_count: $crate::sys::c_int,
        ) -> $crate::sys::OM_uint32 {
            $crate::unwrap_iov::<$ctx>(
                minor, ctx, conf_state, qop_state, iov, iov_count,
            )
        }

        #[no_mangle]
        pub unsafe extern "C" fn gss_release_iov_buffer(
            minor: *mut $crate::sys::OM_uint32,
            iov: $crate::sys::gss_iov_buffer_t,
            iov_count: $crate::sys::c_int,
        ) -> $crate::sys::OM_uint32 {
            $crate::release_iov_buffer(minor, iov, iov_count)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct ToyProfile;

    impl ToyProfile {
        fn mac(
            sender: rfc4121::Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            suffix: &[u8],
        ) -> [u8; 4] {
            let mut acc = 0x4753_5300u32 ^ seq as u32;
            acc ^= if sender.is_acceptor() { 0xa5 } else { 0x5a };
            for byte in aad.iter().chain(plaintext).chain(suffix) {
                acc = acc.rotate_left(5).wrapping_add(u32::from(*byte));
            }
            acc.to_be_bytes()
        }
    }

    impl rfc4121::CryptoProfile for ToyProfile {
        const CHECKSUM_LEN: usize = 4;
        const SEALED_OVERHEAD: usize = 4;

        fn seal(
            &self,
            sender: rfc4121::Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, rfc4121::Error> {
            let tag = Self::mac(sender, seq, aad, plaintext, b"seal");
            let mut out = plaintext.to_vec();
            out.extend_from_slice(&tag);
            Ok(out)
        }

        fn open(
            &self,
            sender: rfc4121::Role,
            seq: u64,
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, rfc4121::Error> {
            if ciphertext.len() < Self::SEALED_OVERHEAD {
                return Err(rfc4121::Error::DefectiveToken);
            }
            let split = ciphertext.len() - Self::SEALED_OVERHEAD;
            let (plaintext, tag) = ciphertext.split_at(split);
            let expected = Self::mac(sender, seq, aad, plaintext, b"seal");
            if !rfc4121::constant_time_eq(tag, &expected) {
                return Err(rfc4121::Error::BadSignature);
            }
            Ok(plaintext.to_vec())
        }

        fn sign(
            &self,
            sender: rfc4121::Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            checksum_header: &[u8; rfc4121::HEADER_LEN],
        ) -> Result<Vec<u8>, rfc4121::Error> {
            Ok(
                Self::mac(sender, seq, aad, plaintext, checksum_header)
                    .to_vec(),
            )
        }

        fn verify(
            &self,
            sender: rfc4121::Role,
            seq: u64,
            aad: &[u8],
            plaintext: &[u8],
            checksum_header: &[u8; rfc4121::HEADER_LEN],
            checksum: &[u8],
        ) -> Result<(), rfc4121::Error> {
            let expected =
                Self::mac(sender, seq, aad, plaintext, checksum_header);
            if rfc4121::constant_time_eq(checksum, &expected) {
                Ok(())
            } else {
                Err(rfc4121::Error::BadSignature)
            }
        }
    }

    struct TestContext {
        role: rfc4121::Role,
        send_seq: u64,
        recv_seq: u64,
    }

    impl TestContext {
        fn new(role: rfc4121::Role) -> Self {
            Self {
                role,
                send_seq: 0,
                recv_seq: 0,
            }
        }
    }

    impl Rfc4121Context for TestContext {
        type Profile = ToyProfile;

        fn role(&self) -> rfc4121::Role {
            self.role
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
            Ok(ToyProfile)
        }
    }

    #[test]
    fn context_helpers_update_sequences() {
        let mut initiator = TestContext::new(rfc4121::Role::Initiator);
        let mut acceptor = TestContext::new(rfc4121::Role::Acceptor);

        let (token, sealed) =
            protect_message(&mut initiator, true, b"hello", b"aad").unwrap();
        assert!(sealed);
        assert_eq!(initiator.send_seq, 1);

        let (message, sealed) =
            unprotect_message(&mut acceptor, &token, b"aad").unwrap();
        assert!(sealed);
        assert_eq!(message, b"hello");
        assert_eq!(acceptor.recv_seq, 1);
    }

    #[test]
    fn mic_helpers_update_sequences() {
        let mut initiator = TestContext::new(rfc4121::Role::Initiator);
        let mut acceptor = TestContext::new(rfc4121::Role::Acceptor);

        let token = get_mic_message(&mut initiator, b"hello").unwrap();
        assert_eq!(initiator.send_seq, 1);
        verify_mic_message(&mut acceptor, b"hello", &token).unwrap();
        assert_eq!(acceptor.recv_seq, 1);
        assert_eq!(
            verify_mic_message(&mut acceptor, b"hello", &token).unwrap_err(),
            rfc4121_status(rfc4121::Error::Sequence),
        );
    }

    #[test]
    fn gss_wrap_and_unwrap_use_rfc4121() {
        unsafe {
            let mut initiator = TestContext::new(rfc4121::Role::Initiator);
            let mut acceptor = TestContext::new(rfc4121::Role::Acceptor);
            let input_bytes = b"payload";
            let mut minor = 0;
            let mut input = gss_buffer_desc {
                length: input_bytes.len(),
                value: input_bytes.as_ptr() as *mut c_void,
            };
            let mut wrapped = gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            };
            let mut conf_state = 0;

            assert_eq!(
                wrap::<TestContext>(
                    &mut minor,
                    (&mut initiator as *mut TestContext).cast(),
                    1,
                    0,
                    &mut input,
                    &mut conf_state,
                    &mut wrapped,
                ),
                GSS_S_COMPLETE,
            );
            assert_eq!(conf_state, 1);
            assert_eq!(initiator.send_seq, 1);

            let mut output = gss_buffer_desc {
                length: 0,
                value: ptr::null_mut(),
            };
            let mut qop_state = 99;
            assert_eq!(
                unwrap::<TestContext>(
                    &mut minor,
                    (&mut acceptor as *mut TestContext).cast(),
                    &mut wrapped,
                    &mut output,
                    &mut conf_state,
                    &mut qop_state,
                ),
                GSS_S_COMPLETE,
            );
            assert_eq!(conf_state, 1);
            assert_eq!(qop_state, 0);
            assert_eq!(acceptor.recv_seq, 1);
            assert_eq!(
                core::slice::from_raw_parts(
                    output.value.cast::<u8>(),
                    output.length,
                ),
                input_bytes,
            );

            release_buffer(&mut wrapped);
            release_buffer(&mut output);
        }
    }
}
