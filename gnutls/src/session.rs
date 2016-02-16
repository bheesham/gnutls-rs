#![allow(dead_code)]
/// TODO: Remove the suppressed warnings.
use std::ffi::CString;

use std::mem;
use std::ops::Drop;

use gt::consts::*;
use cert_creds::CertCreds;
use error::{
    Error,
    AsGnutlsError
};

use gt::gen::{gnutls_session_t,
              gnutls_init,
              gnutls_deinit,
              gnutls_credentials_type_t,
              gnutls_credentials_set
};

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
   session: gnutls_session_t
}

impl Session {
    #[allow(unused_must_use)]
    fn new(flags: Flags) -> Result<Session, Error> {
        unsafe {
            ::init();

            let mut session: gnutls_session_t = mem::zeroed();
            let val = gnutls_init(&mut session, flags.bits);

            if val != 0 {
                return Err(val.as_gnutls_error());
            }

            Ok(Session{
                session: session
            })
        }
    }

    fn set_creds(&mut self, cred_type: gnutls_credentials_type_t,
                 creds: CertCreds) -> Result<Error, Error> {
        unsafe {
            let res: i32 = gnutls_credentials_set(self.session,
                                                  cred_type,
                                                  creds.credentials);

            is_succ!(res)
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
    fn comp() {
        let mut session: Session = match Session::new(GNUTLS_CLIENT) {
            Ok(x) => x,
            Err(_) => panic!("Could not create the session.")
        };

    }
}
