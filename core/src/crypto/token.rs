use crate::crypto::hash;
use crate::util;
use crabgraph::asym::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};

// Import RSA types from crabgraph for legacy client support
#[cfg(feature = "crypto")]
use crabgraph::asym::{RsaPublicKey, RsaSignature};

pub struct SigningTokenKey {
    inner: Ed25519KeyPair,
}

impl SigningTokenKey {
    pub fn to_verifying_key(&self) -> Box<dyn VerifyingTokenKey> {
        Box::new(Ed25519VerifyingKey {
            inner: self.inner.public_key(),
        })
    }
}

pub trait VerifyingTokenKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> anyhow::Result<()>;

    fn to_der(&self) -> anyhow::Result<Vec<u8>>;

    fn signature_method(&self) -> &'static str;
}

struct Ed25519VerifyingKey {
    inner: Ed25519PublicKey,
}

#[cfg(feature = "crypto")]
struct RsaPssVerifyingKey {
    inner: RsaPublicKey,
}

impl VerifyingTokenKey for Ed25519VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let sig = Ed25519Signature::from_bytes(signature)?;
        let valid = self.inner.verify(msg, &sig)?;
        
        if !valid {
            anyhow::bail!("Invalid signature");
        }
        Ok(())
    }

    fn to_der(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.inner.to_public_key_der()?)
    }

    fn signature_method(&self) -> &'static str {
        "ed25519"
    }
}

#[cfg(feature = "crypto")]
impl VerifyingTokenKey for RsaPssVerifyingKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let sig = RsaSignature::from_bytes(signature.to_vec());
        let valid = self.inner.verify(msg, &sig)?;
        
        if !valid {
            anyhow::bail!("Invalid RSA-PSS signature");
        }
        Ok(())
    }

    fn to_der(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.inner.to_public_key_der()?)
    }

    fn signature_method(&self) -> &'static str {
        "rsa-pss"
    }
}

pub fn generate_key() -> SigningTokenKey {
    let keypair = Ed25519KeyPair::generate()
        .expect("Failed to generate Ed25519 keypair");
    
    SigningTokenKey { inner: keypair }
}

pub fn export_private_key(key: &SigningTokenKey) -> anyhow::Result<String> {
    let pem = key.inner.to_pkcs8_pem()?;
    Ok(pem)
}

pub fn parse_private_key(private_key: &str) -> anyhow::Result<SigningTokenKey> {
    let parsed = Ed25519KeyPair::from_pkcs8_pem(private_key)?;
    Ok(SigningTokenKey { inner: parsed })
}

pub fn export_public_key(key: &SigningTokenKey) -> anyhow::Result<String> {
    let pem = key.inner.public_key().to_public_key_pem()?;
    Ok(pem)
}

pub fn parse_public_key(
    public_key: &str,
    identifier: &str,
) -> anyhow::Result<Box<dyn VerifyingTokenKey + Send>> {
    Ok(match identifier {
        "ed25519" => Box::new(Ed25519VerifyingKey {
            inner: Ed25519PublicKey::from_public_key_pem(public_key)?,
        }),
        #[cfg(feature = "crypto")]
        "rsa-pss" => Box::new(RsaPssVerifyingKey {
            inner: RsaPublicKey::from_pem(public_key)?,
        }),
        #[cfg(not(feature = "crypto"))]
        "rsa-pss" => return Err(anyhow::anyhow!("RSA support requires 'crypto' feature")),
        _ => return Err(anyhow::anyhow!("Unsupported key type")),
    })
}

pub fn generate_token_timestamp(key: &SigningTokenKey) -> anyhow::Result<String> {
    let salt = util::time::unix_timestamp_u64()?.to_le_bytes();
    let result = generate_token_nonce(key, &salt)?;
    Ok(result)
}

pub fn generate_token_nonce(key: &SigningTokenKey, salt: &[u8]) -> anyhow::Result<String> {
    // Construct hash input from public key DER + salt
    let digest = {
        let pubkey_der = key.inner.public_key().to_public_key_der()?;
        let combined = [pubkey_der.as_slice(), salt].concat();
        hash::sha256(&combined)
    };
    
    let signature = key.inner.sign(&digest);

    // Build token string: hash_method.hash_b64.salt_b64.sign_method.signature_b64
    let hash_method = "sha256";
    let hash_base64 = util::base64::encode(&digest);
    let salt_base64 = util::base64::encode(salt);
    let sign_method = "ed25519";
    let signature_base64 = util::base64::encode(signature.as_bytes());

    Ok(format!(
        "{}.{}.{}.{}.{}",
        hash_method, hash_base64, salt_base64, sign_method, signature_base64
    ))
}

pub fn extract_signature_identifier(token: &str) -> Option<&str> {
    let parts: Vec<&str> = token.split('.').collect();
    parts.get(3).copied()
}

pub fn verify_token_timestamp(public_key: &dyn VerifyingTokenKey, token: &str) -> bool {
    verify_token_with_result(public_key, token, |salt| {
        let salt = {
            if salt.len() != 8 {
                return Err(anyhow::anyhow!("Invalid salt length"));
            }
            u64::from_le_bytes(
                salt.try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid salt"))?,
            )
        };

        let now_seconds = util::time::unix_timestamp_u64()?;
        if now_seconds - salt > 60 * 60 {
            // Fingerprint is older than 1h, reject
            return Err(anyhow::anyhow!("Fingerprint timestamp expired"));
        }

        Ok(())
    })
    .is_ok()
}

pub fn verify_token_nonce(public_key: &dyn VerifyingTokenKey, token: &str, nonce: &[u8]) -> bool {
    verify_token_with_result(public_key, token, |salt| {
        if salt != nonce {
            return Err(anyhow::anyhow!("Invalid nonce"));
        }

        Ok(())
    })
    .is_ok()
}

pub fn verify_token_with_result(
    public_key: &dyn VerifyingTokenKey,
    token: &str,
    verify_salt: impl Fn(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = token.split('.').collect();
    let [hash_method, hash_base64, salt_base64, sign_method, signature_base64] = parts[0..5] else {
        anyhow::bail!("Invalid token structure");
    };

    if hash_method != "sha256" {
        anyhow::bail!("Unsupported hash method: {}", hash_method);
    }

    if sign_method != public_key.signature_method() {
        anyhow::bail!("Signature method mismatch: expected {}, got {}", 
            public_key.signature_method(), sign_method);
    }

    // Decode and validate salt
    let salt = {
        let salt_bytes = util::base64::decode(salt_base64)?;
        verify_salt(&salt_bytes)?;
        salt_bytes
    };

    // Reconstruct digest from public key + salt
    let digest = {
        let pubkey_der = public_key.to_der()?;
        let combined = [pubkey_der.as_slice(), &salt].concat();
        hash::sha256(&combined)
    };

    // Verify hash matches
    if util::base64::encode(&digest) != hash_base64 {
        anyhow::bail!("Hash mismatch");
    }

    // Decode and verify signature
    let signature = util::base64::decode(signature_base64)
        .map_err(|_| anyhow::anyhow!("Invalid signature encoding"))?;

    public_key.verify(&digest, &signature)
        .map_err(|_| anyhow::anyhow!("Signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key = generate_key();
        let pem = export_private_key(&key).unwrap();

        let parsed = parse_private_key(&pem).unwrap();
        let original_bytes = key.inner.secret_bytes();
        let parsed_bytes = parsed.inner.secret_bytes();
        assert_eq!(parsed_bytes, original_bytes);
    }

    #[test]
    fn test_sign_verify() {
        let key = generate_key();
        let data = b"hello world";
        let signature = key.inner.sign(data);
        let verified = key
            .to_verifying_key()
            .verify(data, signature.as_bytes())
            .is_ok();
        assert!(verified);
    }

    #[test]
    fn test_fingerprint() {
        let key = generate_key();
        let fingerprint = generate_token_timestamp(&key).unwrap();
        let verified = verify_token_timestamp(&*key.to_verifying_key(), &fingerprint);
        assert!(verified);
    }
}
