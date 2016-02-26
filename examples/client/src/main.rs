extern crate bitflags;
extern crate gnutls;

use gnutls::creds::{Cert, CredType};
use gnutls::{
    init,
    deinit,
    CertVerifyFlags,
    Session
};

fn main() {
    match init() {
        Ok(_) => {},
        Err(_) => panic!("could not initialize.")
    };

    let hostname: &'static str = "localhost";
    let mut creds: Cert = Cert::new().unwrap();
    let mut session: Session = Session::new(gnutls::GNUTLS_CLIENT).unwrap();

    if creds.x509_set_trust_file("../../gnutls/tests/ca.cert.pem", None).err() != None {
        panic!("Error: couldn't set the trust file.");
    }

    if creds.x509_set_key_file("../../gnutls/tests/ca.cert.pem",
                               "../../gnutls/tests/ca.noenckey.pem", None).err() != None {
        panic!("Error: couldn't set the keyfile.");
    }

    if session.set_creds(CredType::GNUTLS_CRD_CERTIFICATE, &mut creds).err() != None {
        panic!("Error: could not set the session credentials.");
    }

    session.set_verify_cert(hostname,
                            Some(CertVerifyFlags::GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT));

    match session.set_priority(None) {
        Err(e) => panic!("{}", e),
        Ok(_) => {}
    };

    deinit();
}
