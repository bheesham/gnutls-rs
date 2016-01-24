#![allow(dead_code)]
/// TODO: Remove the suppressed warnings.
use std::mem;
use std::ops::Drop;

use gt::consts::*;
use gt::gen::{
    gnutls_certificate_credentials_t,
    gnutls_certificate_allocate_credentials,
    gnutls_certificate_free_credentials
};

pub struct Certificate {
   credentials: gnutls_certificate_credentials_t
}

impl Certificate {
    #[allow(unused_must_use)]
    fn new() -> Result<Certificate, i32> {
        unsafe {
            ::init();

            let mut credentials: gnutls_certificate_credentials_t = mem::zeroed();
            let val = gnutls_certificate_allocate_credentials(&mut credentials);

            if val == GNUTLS_E_SUCCESS {
                return Ok(Certificate {
                    credentials: credentials
                });
            }

            Err(val)
        }
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe {
            // Also free keys, and CRLs?
            gnutls_certificate_free_credentials(self.credentials);
        }
    }
}
