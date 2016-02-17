#![allow(dead_code)]
/// TODO: Remove the suppressed warnings.
use std::mem;
use std::ops::Drop;

use gt::gen::{
    gnutls_dh_params_t,
    gnutls_dh_params_init,
    gnutls_dh_params_cpy,
    gnutls_dh_params_deinit,
    gnutls_x509_crt_fmt_t,
    gnutls_datum_t,
    gnutls_dh_params_export2_pkcs3,
    gnutls_dh_params_export_raw,
    gnutls_dh_params_generate2,
    gnutls_dh_params_import_pkcs3,
    gnutls_dh_params_import_raw2,
};

use error::{
    Error,
    AsGnutlsError
};

pub struct DHParams {
    params: gnutls_dh_params_t
}

impl DHParams {
    #[allow(unused_must_use)]
    fn new() -> Result<DHParams, Error> {
        unsafe {
            ::init();

            let mut dh_params: gnutls_dh_params_t = mem::zeroed();
            let val = gnutls_dh_params_init(&mut dh_params);

            if val == Error::None as i32 {
                return Ok(DHParams {
                    params: dh_params
                });
            }

            Err(val.as_gnutls_error())
        }
    }

    #[allow(unused_mut)]
    fn try_clone(&self) -> Result<DHParams, Error> {
        unsafe {
            let mut new_params: gnutls_dh_params_t = mem::zeroed();
            let val = gnutls_dh_params_cpy(new_params, self.params);

            if val == Error::None as i32 {
                Ok(DHParams {
                    params: new_params
                })
            } else {
                Err(val.as_gnutls_error())
            }
        }
    }

    /// TODO: Refactor to edit a gnutls_datum_t structure.
    fn export_pkcs3(&self, format: gnutls_x509_crt_fmt_t,
                    datum: *mut gnutls_datum_t) -> Result<Error, Error> {

        unsafe {
            let val = gnutls_dh_params_export2_pkcs3(self.params, format, datum);
            is_succ!(val)
        }
    }

    /// TODO: Same as above.
    fn export_raw(&self, prime: *mut gnutls_datum_t,
                  generator: *mut gnutls_datum_t,
                  bits: *mut u32) -> Result<Error, Error> {

        unsafe {
            let val = gnutls_dh_params_export_raw(self.params, prime,
                                                  generator, bits);
            is_succ!(val)
        }
    }

    fn generate(&self, bits: u32) -> Result<Error, Error> {
        unsafe {
            let val = gnutls_dh_params_generate2(self.params, bits);
            is_succ!(val)
        }
    }

    fn import_pkcs3(&mut self, pkcs3_params: *const gnutls_datum_t,
                    format: gnutls_x509_crt_fmt_t) -> Result<Error, Error> {

        unsafe {
            let val = gnutls_dh_params_import_pkcs3(self.params, pkcs3_params,
                                                    format);
            is_succ!(val)
        }
    }

    fn import_raw(&mut self, prime: *const gnutls_datum_t,
                  generator: *const gnutls_datum_t,
                  key_bits: Option<u32>) -> Result<Error, Error> {

        let bits: u32 = match key_bits {
            Some(x) => x,
            None => 0
        };

        unsafe {
            let val = gnutls_dh_params_import_raw2(self.params, prime, generator, bits);
            is_succ!(val)
        }
    }

    fn as_raw(&self) -> gnutls_dh_params_t {
        self.params
    }
}

impl Drop for DHParams {
    fn drop(&mut self) {
        unsafe {
            gnutls_dh_params_deinit(self.params)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn comp() {

    }
}
