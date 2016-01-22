#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case, unused_imports)]
extern crate libc;
pub mod gen;
use gen::{gnutls_global_init,
          gnutls_global_deinit};

#[test]
fn test_gnutls_global() {
    unsafe {
        let status: libc::c_int = gnutls_global_init();
        assert_eq!(status, 0);
        gnutls_global_deinit();
    }
}
