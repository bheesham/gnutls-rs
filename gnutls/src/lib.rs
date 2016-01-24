extern crate libc;
extern crate gnutls_sys as gt;

use std::ffi::CString;
use std::ffi::CStr;

pub use gt::consts::*;
use gt::gen::{
    gnutls_check_version
};

pub mod gnutls;


/// Check that the minimum libgnutls version is `req_version`. Returns the installed
/// version on success.
///
/// See: http://gnutls.org/manual/gnutls.html#gnutls_005fcheck_005fversion
///
pub fn check_version(req_version: Option<&'static str>) -> Result<&str, &str> {
    let version = match req_version {
        Some(x) => x,
        None => GNUTLS_VERSION
    };

    unsafe {
        let result = gnutls_check_version(CString::new(version)
                                          .unwrap()
                                          .as_ptr());

        if result.is_null() {
            return Err("required version not found")
        }

        let something = CStr::from_ptr(result);
        Ok(something.to_str().unwrap())
    }
}

#[test]
fn test_version() {
    assert_eq!(check_version(Some("3.4.8")).unwrap(), "3.4.8");
    assert_eq!(check_version(None).unwrap(), "3.4.8");
    assert_eq!(check_version(Some("4")).unwrap_or(""), "");
}
