use ring::rand::SecureRandom;
use ring::signature::KeyPair;

fn main() {
    let rng = ring::rand::SystemRandom::new();
    let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keys = ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let pub_key = keys.public_key();
    std::fs::write("rad_keys.pkcs8", &doc).unwrap();
    std::fs::write("rad_pub_key", &pub_key).unwrap();

    let mut auth_key = vec![0u8; ring::aead::CHACHA20_POLY1305.key_len()];
    rng.fill(&mut auth_key).unwrap();
    std::fs::write("rad_auth_key", &auth_key).unwrap();
}
