#![cfg(target_arch = "x86")]

pub fn secure_zero<T: ?Sized>(value: &mut T) {
    let p = value as *mut T as *mut u8;
    let len = core::mem::size_of_val(value);
    unsafe { core::ptr::write_bytes(p, 0, len); }
}

pub unsafe fn secure_zero_typed<T>(value: *mut T) {
    if !value.is_null() { core::ptr::write_bytes(value as *mut u8, 0, core::mem::size_of::<T>()); }
}

pub unsafe fn has_hardware_breakpoints() -> bool { false }
