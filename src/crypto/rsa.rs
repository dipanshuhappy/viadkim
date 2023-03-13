use crate::crypto::{HashAlgorithm, SigningError, VerificationError};
use rsa::{
    pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Sign, PublicKey, PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
#[cfg(feature = "sha1")]
use sha1::Sha1;

pub fn get_public_key_size(k: &RsaPublicKey) -> usize {
    k.size() * 8
}

pub fn read_rsa_public_key(key_data: &[u8]) -> Result<RsaPublicKey, VerificationError> {
    // first try reading data as SubjectPublicKeyInfo
    // (*de facto* procedure, as shown in examples in appendix of RFC)
    // then try reading data as RSAPublicKey
    // (what was actually specified in RFC, but not what is in appendix)
    let public_key = RsaPublicKey::from_public_key_der(key_data)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(key_data))
        .map_err(|_| VerificationError::InvalidKey)?;

    if get_public_key_size(&public_key) < 1024 {
        return Err(VerificationError::InsufficientKeySize);
    }

    Ok(public_key)
}

pub fn verify_rsa(
    hash_alg: HashAlgorithm,
    public_key: &RsaPublicKey,
    msg: &[u8],
    signature_data: &[u8],
) -> Result<(), VerificationError> {
    let result = match hash_alg {
        HashAlgorithm::Sha256 => {
            public_key.verify(Pkcs1v15Sign::new::<Sha256>(), msg, signature_data)
        }
        #[cfg(feature = "sha1")]
        HashAlgorithm::Sha1 => {
            public_key.verify(Pkcs1v15Sign::new::<Sha1>(), msg, signature_data)
        }
    };

    // TODO consider recording rsa crypto error somewhere
    result.map_err(|_e| VerificationError::VerificationFailure)
}

pub fn sign_rsa(
    hash_alg: HashAlgorithm,
    private_key: &RsaPrivateKey,
    msg: &[u8],
) -> Result<Vec<u8>, SigningError> {
    let result = match hash_alg {
        HashAlgorithm::Sha256 => private_key.sign(Pkcs1v15Sign::new::<Sha256>(), msg),
        #[cfg(feature = "sha1")]
        HashAlgorithm::Sha1 => private_key.sign(Pkcs1v15Sign::new::<Sha1>(), msg),
    };

    result.map_err(|_| SigningError::SigningFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    /*
    #[test]
    fn make_rsa2048_key() {
        use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
        use tracing::debug;

        let mut rng = rand::thread_rng();

        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let s = public_key.to_public_key_pem(Default::default()).unwrap();
        debug!("pub: {s}");

        let s = private_key.to_pkcs8_pem(Default::default()).unwrap();
        let s: &str = s.as_ref();
        debug!("sec: {s}");
    }
    */

    #[test]
    fn read_rsa2048_key() {
        let pubkey_s = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvXEn6j24wx68Zs5djoKQ
LFXcGUUPzvAAfrc9RKzBQG+dglfdCqZy2ZFai4SlLivvkkCU+0wXl+ExSSY5xEiQ
k7m3YQZbeIAeSWUTLe7asTri73c7nX5D7+1KKWUarMHKLeWN5F9Re8uOfWrgZdYC
20bfoptbMQLLPcbfchP9Z7epZRwdi6xeZySFO2JnwyK2kEay7VpF7YivwQzMohF2
hlQ9OshDIa2w7uudKp5jAcOVymPTi3iu6tEI/3NNkcezukVawN6bLkZf6IEE3Gap
2oD3pidf51iAfb7BBbeE36Hl3dPxAgfsSrc/v2HTRMYeeBb7fjFC50ImvxjtmFUI
xQIDAQAB
-----END PUBLIC KEY-----";
        let privkey_s = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9cSfqPbjDHrxm
zl2OgpAsVdwZRQ/O8AB+tz1ErMFAb52CV90KpnLZkVqLhKUuK++SQJT7TBeX4TFJ
JjnESJCTubdhBlt4gB5JZRMt7tqxOuLvdzudfkPv7UopZRqswcot5Y3kX1F7y459
auBl1gLbRt+im1sxAss9xt9yE/1nt6llHB2LrF5nJIU7YmfDIraQRrLtWkXtiK/B
DMyiEXaGVD06yEMhrbDu650qnmMBw5XKY9OLeK7q0Qj/c02Rx7O6RVrA3psuRl/o
gQTcZqnagPemJ1/nWIB9vsEFt4TfoeXd0/ECB+xKtz+/YdNExh54Fvt+MULnQia/
GO2YVQjFAgMBAAECggEAYoVNr9lnlDoQ2xppt2qZViVU8ONkxEc2yq+7MlLxsfQa
IyZUs2w7AIFCaJqUWP3KevIRSNuazYb03cj+c+EVJ26HOvNWcMWYeq0RG2tD2rX4
PXdxzodTB50NW5fUFpI19kaS03jq5InJUdpaVzvEgotKVMOc2lFMp5UcsbRJrj0E
Z5aluqzPe92B6uCBdL6wMehW+Bpd5Bb6Fh/ZKYGmEqmfba4NM7JHdhKlfFOLQqtm
1PEjJG9nomR27JK4cIMXpa1IHnaqWWnyTI5A/vDu/QlmqxwYBQXw5/BU8h55dibc
DHhLCRXvpQ2SJZVFDQEKUSKAWkZaJOtMqBQW4KAIZQKBgQDFEUx8l5KlKE9QFwvO
2PVmQIndEBQg0z6ygRmORoxIsn2eDxByjgHtBIixoacF0K5ChhefjQSQrjS16B24
xddK7qGA1SB50Uuxnn05zzsgYI2oiShGWiAANCozAGx/Ni2+8FileonFIHOqMONf
vrGlVvdEBV17ijDIwsG/SFCu7wKBgQD2GBM38FF/6nQXTCyAtGWI2bJy0eor/pL7
BpiZB062O9qhyjSkZ/XcYk60HGp9SPLSuDs6OU5ni9/RFOdEFqAP6ywNFpZl7Hf1
0DYH1k1cI8XehqJQhE4rzcInxspM6jB0BsD6n+dsONV4Z6xv04S7NeS0vVhzhdtu
65uXlRrDiwKBgDQk0KVDAgV7dgkOIAy6cax9tTzuLTVGUBexe06fMi1mNUDmYYa+
Npo9keHWkThDsGhfzM5l5OhXgBEF+x9SEhZ8r/VD75TsIWg9NItgXxfBFJqcuDBt
VnxXUTcvjIXYkyArvnkCxIOJg7FrwC4sahsCuOihtsuilCf7CIMRom+3AoGAALPC
4kb6RI4rtKFQAzIAlCpi2vcEXwnD65lyOAWQUO7MyedkzQ9K4U0agmMOXrsljjpe
WOUu9xasFdGkc0pJPKJkJslotnO9R+NHNDCFWfz0JJVnwykNfAyDQE/N5fhJGRun
008/fsyOt2A8WrlUyJ/3vhhIN1Qrcx6S/BS91c8CgYBdF8EGdKh+OtlISio3y7u5
YpIFoCGGPqWdiHEie7j/J2kQMZ4DLzQTl/VwzTokiMDJS2VFp8Ul8vdakWmFCpyI
bjrBykE/N9Fi2FVYbKF2pevzTeMj4J6YirkG998T0IcuNfJdH7o57z+AJC7zIuzj
CQ8od0/ltBQAeX9B2QXumw==
-----END PRIVATE KEY-----";

        let privkey = RsaPrivateKey::from_pkcs8_pem(privkey_s).unwrap();
        let pubkey = RsaPublicKey::from_public_key_pem(pubkey_s).unwrap();

        assert_eq!(get_public_key_size(&pubkey), 2048);

        let privkey2 = crate::crypto::SigningKey::from_pkcs8_pem(privkey_s).unwrap();

        match privkey2 {
            crate::crypto::SigningKey::Rsa(privkey2) => {
                assert_eq!(privkey, privkey2);
            }
            _ => panic!(),
        }
    }
}
