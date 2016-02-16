#![allow(non_camel_case_types, non_upper_case_globals,
         non_snake_case, dead_code, unused_imports)]
extern crate libc;

pub mod gen;
pub mod consts;

use std::mem;
use libc::{c_int, c_uchar};

pub use consts::*;
pub use gen::{gnutls_global_init,
              gnutls_global_deinit,

              gnutls_anon_server_credentials_t,
              gnutls_anon_allocate_server_credentials,
              gnutls_anon_free_server_credentials,

              gnutls_certificate_credentials_t,
              gnutls_certificate_allocate_credentials,
              gnutls_certificate_free_credentials
};


#[cfg(test)]
mod tests {
    use super::*;
    use libc::{c_int, c_uchar};

    #[test]
    fn test_gnutls_global() {
        unsafe {
            let status: c_int = gnutls_global_init();
            assert_eq!(status, GNUTLS_E_SUCCESS);
            gnutls_global_deinit();
        }
    }

    #[test]
    fn test_gnutls_alloc() {
        unsafe {
            gnutls_global_init();
            let mut sc: gnutls_anon_server_credentials_t = mem::zeroed();
            assert_eq!(gnutls_anon_allocate_server_credentials(&mut sc),
                       GNUTLS_E_SUCCESS);

            gnutls_anon_free_server_credentials(sc);

            let mut cert_creds: gnutls_certificate_credentials_t = mem::zeroed();
            assert_eq!(gnutls_certificate_allocate_credentials(&mut cert_creds),
                       GNUTLS_E_SUCCESS);

            gnutls_certificate_free_credentials(cert_creds);

            let mut client_cert: gnutls_certificate_credentials_t = mem::zeroed();
            assert_eq!(gnutls_certificate_allocate_credentials(&mut client_cert),
                       GNUTLS_E_SUCCESS);

            gnutls_certificate_free_credentials(client_cert);
            gnutls_global_deinit();
        }
    }
}
