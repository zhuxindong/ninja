use rcgen::Certificate;

use crate::{error, serve::preauth::proxy::CertificateAuthority};

use std::fs;

pub fn gen_ca() -> Certificate {
    let cert = CertificateAuthority::gen_ca().expect("preauth generate cert");
    let cert_crt = cert.serialize_pem().unwrap();

    fs::create_dir("ca").unwrap();

    println!("{}", cert_crt);
    if let Err(err) = fs::write("ca/cert.crt", cert_crt) {
        error!("cert file write failed: {}", err);
    }

    let private_key = cert.serialize_private_key_pem();
    println!("{}", private_key);
    if let Err(err) = fs::write("ca/key.pem", private_key) {
        error!("private key file write failed: {}", err);
    }

    cert
}
