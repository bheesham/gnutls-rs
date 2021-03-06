extern crate gnutls;

use gnutls::creds::{Cert, CredType};
use gnutls::{init, deinit, Session};

use std::io::prelude::*;
use std::os::unix::io::AsRawFd;
use std::net::TcpStream;

fn main() {
    match init() {
        Ok(_) => {},
        Err(_) => panic!("could not initialize.")
    };

    let host = ("bheesham.com", 443);
    let mut creds = Cert::new().unwrap();
    let mut session = Session::new(gnutls::GNUTLS_CLIENT).unwrap();

    if creds.x509_set_system_trust().err() != None {
        panic!("Error: couldn't set system trust.");
    }

    if creds.x509_set_key_file("../../gnutls/tests/ca.cert.pem",
                               "../../gnutls/tests/ca.noenckey.pem", None).err() != None {
        panic!("Error: couldn't set the keyfile.");
    }

    match session.set_priority(None) {
        Err(e) => panic!("{}", e),
        Ok(_) => {}
    };

    if session.set_creds(CredType::GNUTLS_CRD_CERTIFICATE, &mut creds).err() != None {
        panic!("Error: could not set the session credentials.");
    }

    session.set_verify_cert(Some(host.0), None);

    let mut stream = match TcpStream::connect(host) {
        Err(e) => panic!("{}", e),
        Ok(s) => s
    };

    session.set_fd(stream.as_raw_fd());
    session.handshake_timeout(None);

    match session.handshake() {
        Ok(_) => println!("Established a connection!"),
        Err(e) => panic!("Error: {}", e)
    };

    let _ = stream.write("GET / HTTP/1.0\n\n".as_bytes()).unwrap();

    let mut res = String::new();
    let _ = stream.read_to_string(&mut res).unwrap();
    println!("{}", res);

    deinit();
}
