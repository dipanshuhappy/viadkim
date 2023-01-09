use crate::crypto::{SigningError, VerificationError};
use ed25519::pkcs8::{DecodePublicKey as _, KeypairBytes, PublicKeyBytes};
use ed25519_dalek::{
    Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey,
    Signature as Ed25519Signature, Signer as _, Verifier as _,
};

/*
pub fn read_ed25519_private_key_file(path: impl AsRef<Path>) -> io::Result<Ed25519Keypair> {
    let s = fs::read_to_string(path)?;

    read_ed25519_private_key(&s)
}

pub fn read_ed25519_private_key(s: &str) -> io::Result<Ed25519Keypair> {
    let keypair =
        KeypairBytes::from_pkcs8_pem(s).map_err(|_| io::Error::from(ErrorKind::Other))?;

    let keypair = keypair_bytes_to_keypair(keypair);

    Ok(keypair)
}
*/

pub fn keypair_bytes_to_keypair(kpb: KeypairBytes) -> Ed25519Keypair {
    let secret = SecretKey::from_bytes(&kpb.secret_key[..]).unwrap();
    let public = Ed25519PublicKey::from(&secret);

    Ed25519Keypair { secret, public }
}

pub fn verify_signature_ed25519(
    key_data: &[u8],
    msg: &[u8],
    signature_data: &[u8],
) -> Result<(), VerificationError> {
    let public_key = match Ed25519PublicKey::from_bytes(key_data) {
        Ok(pk) => pk,
        Err(_) => {
            let pkb = PublicKeyBytes::from_public_key_der(key_data)
                .map_err(|_| VerificationError::InvalidKey)?;
            Ed25519PublicKey::from_bytes(&pkb.0[..]).map_err(|_| VerificationError::InvalidKey)?
        }
    };

    let signature = Ed25519Signature::try_from(signature_data)
        .map_err(|_| VerificationError::InvalidSignature)?;

    public_key
        .verify(msg, &signature)
        .map_err(|_| VerificationError::VerificationFailure)
}

pub fn sign_ed25519(keypair: &Ed25519Keypair, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
    let signature = keypair.sign(msg);
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};

    /*
    #[test]
    fn make_ed25519_key() {
        use rand::rngs::OsRng;
        let mut csprng = OsRng{};
        let keypair: Keypair = ed25519_dalek::Keypair::generate(&mut csprng);

        let kb: [u8; 64] = keypair.to_bytes();

        let pubkey: ed25519_dalek::PublicKey = keypair.public;
        let pb: [u8; 32] = pubkey.to_bytes();
        let seckey: ed25519_dalek::SecretKey = keypair.secret;
        let sb: [u8; 32] = seckey.to_bytes();

        let pkb = ed25519::pkcs8::PublicKeyBytes(pb);
        let s = pkb.to_public_key_pem(Default::default()).unwrap();
        eprintln!("pub: {}", s);

        let kpb = ed25519::pkcs8::KeypairBytes {
            secret_key: sb,
            public_key: Some(pb),
        };
        let s = kpb.to_pkcs8_pem(Default::default()).unwrap();
        let s: &str = s.as_ref();
        eprintln!("sec: {}", s);
    }
    */

    #[test]
    fn read_ed25519_key() {
        // TODO These two pkcs8 encoded keys generated with disabled test above:

        let public_key_pem = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9VXMCgG0fXGIzwV7eOxKhz+Pe6DRmOBYjyvVoVrc/Dw=
-----END PUBLIC KEY-----
";
        let pkb = PublicKeyBytes::from_public_key_pem(public_key_pem).unwrap();

        let keypair_pem = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIJdevcQP5V+0H3FgPiT9874RoyKNRxhWceWcZWhgMSTB
gSEA9VXMCgG0fXGIzwV7eOxKhz+Pe6DRmOBYjyvVoVrc/Dw=
-----END PRIVATE KEY-----
";
        let mut kpb = KeypairBytes::from_pkcs8_pem(keypair_pem).unwrap();

        assert_eq!(pkb.0, kpb.public_key.unwrap());

        // bonus, PKCS#8 of private key only:

        kpb.public_key = None;

        let s = kpb.to_pkcs8_pem(Default::default()).unwrap();
        let s: &str = &s;
        let secret_key_pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJdevcQP5V+0H3FgPiT9874RoyKNRxhWceWcZWhgMSTB
-----END PRIVATE KEY-----
";

        assert_eq!(s, secret_key_pem);

        // alternative keys from openssl:

        // note output from `openssl genpkey -algorithm Ed25519 -out tested25519key.pem`
        // (only private key bytes w/o public key part)
        // -----BEGIN PRIVATE KEY-----
        // MC4CAQAwBQYDK2VwBCIEIHvzPSvRhWPU1VgJnRXFB8PkLebN9Bt8ZByayeWQ76iQ
        // -----END PRIVATE KEY-----
        //
        // and output from `openssl pkey -in tested25519key.pem -pubout`
        // (public key derived from private key above)
        // -----BEGIN PUBLIC KEY-----
        // MCowBQYDK2VwAyEAQJ+uTVeKqqdr+tbplMgr0ic7x7rhL0F6UlI4vbvurgI=
        // -----END PUBLIC KEY-----
    }
}
