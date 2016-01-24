use std::ffi::CStr;
pub use gt::consts::*;
use gt::gen::{
    gnutls_sec_param_t,
    gnutls_sec_param_get_name,
};

pub enum SecParam {}

impl SecParam {
    #[allow(dead_code)]
    fn get_name(param: gnutls_sec_param_t) -> Result<&'static str, &'static str> {
        unsafe {
            let name = gnutls_sec_param_get_name(param);
            if name.is_null() {
                Err("no name for that security parameter")
            } else {
                Ok(CStr::from_ptr(name).to_str().unwrap())
            }
        }
    }
}

#[test]
fn test_sec_param_get_name() {
    assert_eq!(SecParam::get_name(gnutls_sec_param_t::GNUTLS_SEC_PARAM_UNKNOWN).ok(),
               Some("Unknown"));
    assert_eq!(SecParam::get_name(gnutls_sec_param_t::GNUTLS_SEC_PARAM_FUTURE).ok(),
               Some("Future"));
}
