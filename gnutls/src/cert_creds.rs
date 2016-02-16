#![allow(dead_code)]
/// TODO: Remove the suppressed warnings.
use std::ffi::CString;

use std::mem;
use std::ops::Drop;

use gt::consts::*;
use error::{
    Error,
    AsGnutlsError
};

use gt::gen::{gnutls_x509_crt_fmt_t,
              gnutls_certificate_credentials_t,
              gnutls_certificate_allocate_credentials,
              gnutls_certificate_free_credentials,
              gnutls_certificate_set_x509_trust_file,
              gnutls_certificate_set_x509_trust_dir,
              gnutls_certificate_set_x509_key_file
};

pub struct CertCreds {
   credentials: gnutls_certificate_credentials_t
}

impl CertCreds {
    #[allow(unused_must_use)]
    fn new() -> Result<CertCreds, Error> {
        unsafe {
            ::init();

            let mut credentials: gnutls_certificate_credentials_t = mem::zeroed();
            let val = gnutls_certificate_allocate_credentials(&mut credentials);

            if val != GNUTLS_E_SUCCESS {
                return Err(val.as_gnutls_error());
            }

            Ok(CertCreds {
                credentials: credentials
            })
        }
    }

    fn x509_set_trust_file(&mut self, file: &'static str,
                           fmt: Option<gnutls_x509_crt_fmt_t>) -> Result<i32, Error> {
        let format: gnutls_x509_crt_fmt_t = match fmt {
            None => gnutls_x509_crt_fmt_t::GNUTLS_X509_FMT_PEM,
            Some(x) => x
        };

        unsafe {
            let processed: i32 = gnutls_certificate_set_x509_trust_file(
                self.credentials,
                CString::new(file).unwrap().as_ptr(),
                format);

            if processed < 1 {
                Err(processed.as_gnutls_error())
            } else {
                Ok(processed)
            }
        }
    }

    fn x509_set_trust_dir(&mut self, directory: &'static str,
                          fmt: Option<gnutls_x509_crt_fmt_t>)
                          -> Result<i32, Error> {
        let format: gnutls_x509_crt_fmt_t = match fmt {
            None => gnutls_x509_crt_fmt_t::GNUTLS_X509_FMT_PEM,
            Some(x) => x
        };

        unsafe {
            let processed: i32 = gnutls_certificate_set_x509_trust_dir(
                self.credentials,
                CString::new(directory).unwrap().as_ptr(),
                format);

            if processed < 1 {
                Err(processed.as_gnutls_error())
            } else {
                Ok(processed)
            }
        }
    }


    fn x509_set_key_file(&mut self, cert: &'static str, key: &'static str,
                         fmt: Option<gnutls_x509_crt_fmt_t>)
                         -> Result<Error, Error> {
        let format: gnutls_x509_crt_fmt_t = match fmt {
            None => gnutls_x509_crt_fmt_t::GNUTLS_X509_FMT_PEM,
            Some(x) => x
        };

        unsafe {
            let res: i32 = gnutls_certificate_set_x509_key_file(
                self.credentials,
                CString::new(cert).unwrap().as_ptr(),
                CString::new(key).unwrap().as_ptr(),
                format
            );

            is_succ!(res)
        }
    }
}

impl Drop for CertCreds {
    fn drop(&mut self) {
        unsafe {
            // Also free keys, and CRLs?
            gnutls_certificate_free_credentials(self.credentials);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use error::Error;

    #[test]
    fn comp() {
        let mut cert: CertCreds = match CertCreds::new() {
            Ok(x) => x,
            Err(_) => {
                panic!("Could not initialize the certificate.")
            }
        };

        assert_eq!(Error::FileError,
                   cert.x509_set_trust_file("tests/does_not_exist.pem", None)
                   .err().unwrap());

        assert_eq!(1, cert.x509_set_trust_file("tests/ca.cert.pem", None)
                   .ok().unwrap());

        match cert.x509_set_trust_dir("does_not_exist/does_not_exist",
                                      None).err().unwrap() {
            Error::None => {},
            _ => {
                panic!("An error occurred when trying to load files.");
            }
        }

        assert_eq!(1, cert.x509_set_trust_dir("tests/", None) .ok().unwrap());

        assert_eq!(Error::DecryptionFailed,
                   cert.x509_set_key_file("tests/ca.cert.pem",
                                          "tests/ca.key.pem",
                                          None)
                   .err().unwrap());

        assert_eq!(Error::None,
                   cert.x509_set_key_file("tests/ca.cert.pem",
                                          "tests/ca.noenckey.pem",
                                          None)
                   .ok().unwrap());
    }
}
