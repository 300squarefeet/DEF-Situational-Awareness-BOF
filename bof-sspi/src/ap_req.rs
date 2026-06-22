// SPDX-FileCopyrightText: 2026 Dani <daniagungg@gmail.com>
// SPDX-License-Identifier: MIT
//
//! Acquire a Kerberos service ticket (AP-REQ blob) for the given SPN via
//! `AcquireCredentialsHandleA` + `InitializeSecurityContextA`.
//!
//! A single `InitSecCtx` call is sufficient for Kerberos AP-REQ when the
//! KDC is reachable — the ticket is returned in the output buffer directly.
//! If the server requires a multi-round exchange and the output buffer is
//! empty after one call, `SspiErr::NoOutputToken` is returned.

extern crate alloc;
use alloc::vec::Vec;
use crate::{SspiErr, dfr::*};
use common::obf_cstr;

const SECPKG_CRED_OUTBOUND:    u32 = 0x00000002;
const SECURITY_NETWORK_DREP:   u32 = 0x00000000;
const SEC_E_OK:                u32 = 0;
const SEC_I_CONTINUE_NEEDED:   u32 = 0x00090312;
const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x00000100;
const ISC_REQ_CONNECTION:      u32 = 0x00000800;
const SECBUFFER_TOKEN:         u32 = 2;

/// Request a Kerberos service ticket for `spn_cstr` and return the raw AP-REQ
/// blob bytes.
///
/// # Safety
/// `spn_cstr` must be a valid pointer to a null-terminated C string for the
/// duration of this call.
pub fn request_service_ticket(spn_cstr: *const i8) -> Result<Vec<u8>, SspiErr> {
    obf_cstr! { let pkg = c"Kerberos"; }
    let mut creds  = SecHandle  { low: 0, high: 0 };
    let mut expiry = TimeStamp  { low: 0, high: 0 };

    // -- AcquireCredentialsHandle ----------------------------------------
    let rc = match unsafe {
        AcquireCredentialsHandleA(
            core::ptr::null(),          // pszPrincipal  (current logon)
            pkg.as_ptr() as *const i8,  // pszPackage    = "Kerberos"
            SECPKG_CRED_OUTBOUND,
            core::ptr::null_mut(),      // pvLogonID
            core::ptr::null_mut(),      // pAuthData
            core::ptr::null_mut(),      // pGetKeyFn
            core::ptr::null_mut(),      // pvGetKeyArgument
            &mut creds,
            &mut expiry,
        )
    } {
        Ok(c)  => c,
        Err(_) => return Err(SspiErr::AcquireCreds),
    };
    if rc != SEC_E_OK {
        return Err(SspiErr::AcquireCreds);
    }

    // -- InitializeSecurityContext ----------------------------------------
    let mut ctx = SecHandle { low: 0, high: 0 };
    let mut out_buf = SecBuffer {
        cb_buffer:   0,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer:   core::ptr::null_mut(),
    };
    let mut out_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers:  1,
        p_buffers:  &mut out_buf,
    };
    let mut attr: u32 = 0;

    let rc = match unsafe {
        InitializeSecurityContextA(
            &mut creds,
            core::ptr::null_mut(),               // phContext (NULL = first call)
            spn_cstr,
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
            0,                                   // Reserved1
            SECURITY_NETWORK_DREP,
            core::ptr::null_mut(),               // pInput (NULL = first call)
            0,                                   // Reserved2
            &mut ctx,
            &mut out_desc,
            &mut attr,
            &mut expiry,
        )
    } {
        Ok(c)  => c,
        Err(_) => {
            let _ = unsafe { FreeCredentialsHandle(&mut creds) };
            return Err(SspiErr::InitCtx);
        }
    };

    if rc != SEC_E_OK && rc != SEC_I_CONTINUE_NEEDED {
        let _ = unsafe { FreeCredentialsHandle(&mut creds) };
        return Err(SspiErr::InitCtx);
    }

    // -- Check output token -----------------------------------------------
    if out_buf.pv_buffer.is_null() || out_buf.cb_buffer == 0 {
        let _ = unsafe { DeleteSecurityContext(&mut ctx) };
        let _ = unsafe { FreeCredentialsHandle(&mut creds) };
        return Err(SspiErr::NoOutputToken);
    }

    // -- Copy blob then clean up (FreeContextBuffer → DeleteCtx → FreeCreds)
    let mut blob = Vec::with_capacity(out_buf.cb_buffer as usize);
    unsafe {
        for i in 0..out_buf.cb_buffer as isize {
            blob.push(*out_buf.pv_buffer.offset(i));
        }
        let _ = FreeContextBuffer(out_buf.pv_buffer);
        let _ = DeleteSecurityContext(&mut ctx);
        let _ = FreeCredentialsHandle(&mut creds);
    }

    Ok(blob)
}
