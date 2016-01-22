extern crate gcc;
extern crate pkg_config;

fn main() {
    match pkg_config::find_library("gnutls") {
        Ok(..) => return,
        Err(e) => panic!("GnuTLS not found: {}", e),
    }

    println!("cargo:rustc-link-lib=gnutls");
}
