use std::alloc::System;

#[global_allocator]
static A: System = System;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// # Safety
/// - This function is unsafe because it dereferences and a returns raw pointer.
/// - ENSURE that result is passed into cstring_free(ptr: *mut c_char) after use.
#[no_mangle]
pub unsafe extern "C" fn example(
    input: *const c_char,
) -> *mut c_char {
    let input_cstr = CStr::from_ptr(input);
    let input: &str = match input_cstr.to_str() {
        Ok(string) => string,
        Err(_) => "test",
    };
    let output = CString::new(input).unwrap().into_raw();
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
