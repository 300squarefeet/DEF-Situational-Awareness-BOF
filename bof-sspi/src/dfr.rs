// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
// secur32.dll symbols resolved via djb2 (matches existing repo pattern).
use common::dfr_fn;

#[repr(C)]
pub struct SecHandle {
    pub low: usize,
    pub high: usize,
}

#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: u32,
    pub buffer_type: u32,
    pub pv_buffer: *mut u8,
}

#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,
    pub c_buffers: u32,
    pub p_buffers: *mut SecBuffer,
}

#[repr(C)]
pub struct TimeStamp {
    pub low: u32,
    pub high: u32,
}

dfr_fn!(
    AcquireCredentialsHandleA(
        principal: *const i8,
        package: *const i8,
        cred_use: u32,
        logon_id: *mut u8,
        auth_data: *mut u8,
        get_key_fn: *mut u8,
        get_key_arg: *mut u8,
        cred_handle: *mut SecHandle,
        expiry: *mut TimeStamp,
    ) -> u32,
    module = "secur32.dll",
    api    = "AcquireCredentialsHandleA"
);

dfr_fn!(
    InitializeSecurityContextA(
        cred_handle: *mut SecHandle,
        ctx_handle: *mut SecHandle,
        target_name: *const i8,
        ctx_req: u32,
        reserved1: u32,
        target_data_rep: u32,
        input: *mut SecBufferDesc,
        reserved2: u32,
        new_ctx: *mut SecHandle,
        output: *mut SecBufferDesc,
        ctx_attr: *mut u32,
        expiry: *mut TimeStamp,
    ) -> u32,
    module = "secur32.dll",
    api    = "InitializeSecurityContextA"
);

dfr_fn!(
    DeleteSecurityContext(ctx_handle: *mut SecHandle) -> u32,
    module = "secur32.dll",
    api    = "DeleteSecurityContext"
);

dfr_fn!(
    FreeCredentialsHandle(cred_handle: *mut SecHandle) -> u32,
    module = "secur32.dll",
    api    = "FreeCredentialsHandle"
);

dfr_fn!(
    FreeContextBuffer(buf: *mut u8) -> u32,
    module = "secur32.dll",
    api    = "FreeContextBuffer"
);
