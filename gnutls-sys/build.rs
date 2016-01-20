extern crate gcc;

fn main() {
    gcc::Config::new().target("gnutls");
}
