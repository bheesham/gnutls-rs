#[macro_use]
extern crate bitflags;
extern crate libc;
extern crate gnutls_sys as gt;

use libc::{c_char};

use std::ffi::{CStr, CString};
use std::mem;
use std::ops::Drop;
use std::sync::{Once, ONCE_INIT};

use gt::consts::*;
use gt::gen::{gnutls_global_init,
              gnutls_global_deinit,
              gnutls_check_version,
              gnutls_session_t,
              gnutls_init,
              gnutls_deinit,
              gnutls_credentials_set,
              gnutls_session_set_verify_cert,
              gnutls_priority_set_direct
};

pub use gt::gen::gnutls_certificate_verify_flags as CertVerifyFlags;

macro_rules! is_succ {
    ($e:ident) => (
        if $e.as_gnutls_error() == Error::None {
            Ok($e.as_gnutls_error())
        } else {
            Err($e.as_gnutls_error())
        }
    );
}

pub mod error;
use error::{
    Error,
    AsGnutlsError
};

pub mod creds;
use creds::{Cert, CredType};

/// Globally initialize the library. This should be called if you want to use
/// GnuTLS. Calling `init()` more than once is safe.
pub fn init() -> Result<Error, Error> {
    static mut INIT: Once = ONCE_INIT;
    let mut val: Option<i32> = None;

    unsafe{
        INIT.call_once(|| {
            val = Some(gnutls_global_init());
        });
    }

    match val {
        Some(val) => {
            if val == 0 {
                Ok(Error::None)
            } else {
               Err(val.as_gnutls_error())
            }
        },
        None => {
            // Already initialized.
            Ok(Error::None)
        }
    }
}


/// Globally deinitialize the library.
pub fn deinit() {
    unsafe {
        gnutls_global_deinit()
    }
}

/// Check that the minimum libgnutls version is `req_version`. Returns the installed
/// version on success.
///
/// See: http://gnutls.org/manual/gnutls.html#gnutls_005fcheck_005fversion
pub fn check_version(req_version: Option<&'static str>) -> Result<&'static  str, &'static str> {
    let version = match req_version {
        Some(x) => x,
        None => GNUTLS_VERSION
    };

    unsafe {
        let result = gnutls_check_version(CString::new(version)
                                          .unwrap()
                                          .as_ptr());

        if result.is_null() {
            return Err("required version not found");
        }

        let something = CStr::from_ptr(result);
        Ok(something.to_str().unwrap())
    }
}

/// Kinds of Sessions we can use.
bitflags! {
    flags Flags: u32 {
        const GNUTLS_SERVER = 1,
        const GNUTLS_CLIENT = 1 << 1,
        const GNUTLS_DATAGRAM = 1 << 2,
        const GNUTLS_NONBLOCK = 1 << 3,
        const GNUTLS_NO_EXTENSIONS = 1 <<  4,
        const GNUTLS_NO_REPLAY_PROTECTION = 1 << 5,
        const GNUTLS_NO_SIGNAL = 1 << 6
    }
}

pub struct Session {
    session: gnutls_session_t,
    creds: bool,
    priority: bool,
    verify_cert: bool

}

impl Session {
    #[allow(unused_must_use)]
    pub fn new(flags: Flags) -> Result<Session, Error> {
        unsafe {
            ::init();

            let mut session: gnutls_session_t = mem::zeroed();
            let val = gnutls_init(&mut session, flags.bits);

            if val != 0 {
                return Err(val.as_gnutls_error());
            }

            Ok(Session{
                session: session,
                creds: false,
                priority: false,
                verify_cert: false
            })
        }
    }

    pub fn set_creds(&mut self, cred_type: CredType,
                 creds: &mut Cert) -> Result<Error, Error> {
        unsafe {
            let res: i32 = gnutls_credentials_set(self.session,
                                                  cred_type,
                                                  mem::transmute(&creds.credentials));

            self.creds = true;
            is_succ!(res)
        }
    }

    pub fn set_verify_cert(&mut self, host: &'static str,
                           verify_flags: Option<CertVerifyFlags>) {
        let flags = match verify_flags {
            None => 0,
            Some(x) => x as u32
        };

        unsafe {
            gnutls_session_set_verify_cert(self.session,
                                           CString::new(host).unwrap().as_ptr(),
                                           flags);

            self.verify_cert = true;
        }
    }

    /// The default priority is "NORMAL".
    pub fn set_priority(&mut self, pri: Option<&'static str>) -> Result<Error, String> {
        let priority = match pri {
            None => "NORMAL",
            Some(x) => x
        };

        unsafe {
            let mut err_location: *const c_char = mem::zeroed();
            let priority_string = CString::new(priority).unwrap();
            let res = gnutls_priority_set_direct(self.session,
                                                 priority_string.as_ptr(),
                                                 &mut err_location);

            if res == 0 {
                self.priority = true;
                return Ok(Error::None);
            }

            match CStr::from_ptr(err_location).to_str() {
                Ok(x) => Err(format!("could not parse the priority string, specifically: {}", x)),
                Err(e) => Err(format!("{}", e))
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            gnutls_deinit(self.session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use error::Error;

    #[test]
    fn test_init() {
        assert_eq!(Error::None, init().ok().unwrap());

        // Calling init twice should be successful, but return an error code.
        assert_eq!(Error::None, init().ok().unwrap());
    }

    #[test]
    fn test_check_version() {
        assert_eq!(check_version(Some("3.4.8")).unwrap(), "3.4.8");
        assert_eq!(check_version(None).unwrap(), "3.4.8");
        assert_eq!(check_version(Some("4")).unwrap_or(""), "");
    }
}
