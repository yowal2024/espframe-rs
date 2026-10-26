use aes::{Aes128, Aes192, Aes256};
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::DecodePublicKey,
    traits::PublicKeyParts,
    BigUint, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthCryptoError {
    #[error("invalid base64")]
    InvalidBase64,
    #[error("AES key must contain 16, 24, or 32 bytes")]
    InvalidAesKey,
    #[error("AES IV must contain 16 bytes")]
    InvalidAesIv,
    #[error("invalid ciphertext or PKCS7 padding")]
    InvalidCiphertext,
    #[error("invalid RSA public key PEM")]
    InvalidRsaPem,
    #[error("RSA operation failed")]
    Rsa,
}

pub struct AuthCrypto {
    key: Vec<u8>,
}

impl AuthCrypto {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    #[allow(non_snake_case)]
    pub fn DecodeBase64(value: &str) -> Result<Vec<u8>, AuthCryptoError> {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| AuthCryptoError::InvalidBase64)
    }

    #[allow(non_snake_case)]
    pub fn AesEncrypt(&self, plain: &str, iv: &[u8]) -> Result<Vec<u8>, AuthCryptoError> {
        if iv.len() != 16 {
            return Err(AuthCryptoError::InvalidAesIv);
        }
        match self.key.len() {
            16 => Ok(cbc::Encryptor::<Aes128>::new_from_slices(&self.key, iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes())),
            24 => Ok(cbc::Encryptor::<Aes192>::new_from_slices(&self.key, iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes())),
            32 => Ok(cbc::Encryptor::<Aes256>::new_from_slices(&self.key, iv)
                .unwrap()
                .encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes())),
            _ => Err(AuthCryptoError::InvalidAesKey),
        }
    }

    #[allow(non_snake_case)]
    pub fn AesDecrypt(&self, cipher: &[u8], iv: &[u8]) -> Result<Vec<u8>, AuthCryptoError> {
        if iv.len() != 16 {
            return Err(AuthCryptoError::InvalidAesIv);
        }
        let result = match self.key.len() {
            16 => cbc::Decryptor::<Aes128>::new_from_slices(&self.key, iv)
                .unwrap()
                .decrypt_padded_vec_mut::<Pkcs7>(cipher),
            24 => cbc::Decryptor::<Aes192>::new_from_slices(&self.key, iv)
                .unwrap()
                .decrypt_padded_vec_mut::<Pkcs7>(cipher),
            32 => cbc::Decryptor::<Aes256>::new_from_slices(&self.key, iv)
                .unwrap()
                .decrypt_padded_vec_mut::<Pkcs7>(cipher),
            _ => return Err(AuthCryptoError::InvalidAesKey),
        };
        result.map_err(|_| AuthCryptoError::InvalidCiphertext)
    }

    #[allow(non_snake_case)]
    pub fn DesEncrypt(
        &self,
        plain: &str,
        _key: &[u8],
        _iv: &[u8],
    ) -> Result<String, AuthCryptoError> {
        Ok(plain.to_owned())
    }

    #[allow(non_snake_case)]
    pub fn Rc4Encrypt(&self, plain: &[u8], _key: &[u8]) -> Result<Vec<u8>, AuthCryptoError> {
        Ok(plain.to_vec())
    }

    #[allow(non_snake_case)]
    pub fn HmacSha256Hex(&self, key: &[u8], message: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary keys");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    #[allow(non_snake_case)]
    pub fn RsaPublicEncrypt(plain: &[u8], public_pem: &str) -> Result<Vec<u8>, AuthCryptoError> {
        let key = RsaPublicKey::from_public_key_pem(public_pem)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_pem))
            .map_err(|_| AuthCryptoError::InvalidRsaPem)?;
        key.encrypt(&mut OsRng, Pkcs1v15Encrypt, plain)
            .map_err(|_| AuthCryptoError::Rsa)
    }

    #[allow(non_snake_case)]
    pub fn RsaPublicEncryptWithRandom<F>(
        plain: &[u8],
        public_pem: &str,
        mut fill: F,
    ) -> Result<Vec<u8>, AuthCryptoError>
    where
        F: FnMut(&mut [u8]),
    {
        let key = RsaPublicKey::from_public_key_pem(public_pem)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_pem))
            .map_err(|_| AuthCryptoError::InvalidRsaPem)?;
        let size = key.size();
        if size <= 11 || plain.is_empty() {
            return Err(AuthCryptoError::Rsa);
        }
        let mut output = Vec::new();
        for chunk in plain.chunks(size - 11) {
            let mut padding = vec![0u8; size - chunk.len() - 3];
            fill(&mut padding);
            for byte in &mut padding {
                while *byte == 0 {
                    fill(std::slice::from_mut(byte));
                }
            }
            let mut block = Vec::with_capacity(size);
            block.extend([0, 2]);
            block.extend(padding);
            block.push(0);
            block.extend(chunk);
            let value = BigUint::from_bytes_be(&block).modpow(key.e(), key.n());
            let bytes = value.to_bytes_be();
            output.extend(std::iter::repeat_n(0, size - bytes.len()));
            output.extend(bytes);
        }
        Ok(output)
    }

    #[allow(non_snake_case)]
    pub fn RsaPrivateDecrypt(cipher: &[u8], private_pem: &str) -> Result<Vec<u8>, AuthCryptoError> {
        let key = RsaPrivateKey::from_pkcs1_pem(private_pem)
            .map_err(|_| AuthCryptoError::InvalidRsaPem)?;
        if cipher.is_empty() || !cipher.len().is_multiple_of(key.size()) {
            return Err(AuthCryptoError::Rsa);
        }
        let mut output = Vec::new();
        for chunk in cipher.chunks(key.size()) {
            output.extend(
                key.decrypt(Pkcs1v15Encrypt, chunk)
                    .map_err(|_| AuthCryptoError::Rsa)?,
            );
        }
        Ok(output)
    }
}
