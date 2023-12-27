use crate::arkose::error::ArkoseError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::anyhow;
use base64::{engine::general_purpose, Engine};
use rand::random;
use serde::{Deserialize, Serialize};

/// AES-256-CBC with PKCS#7 padding Decryptor
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-256-CBC with PKCS#7 padding Encryptor
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

#[derive(Serialize, Deserialize, Debug)]
struct EncryptionData {
    ct: String,
    iv: String,
    s: String,
}

#[inline]
pub fn encrypt(data: &str, key: &str) -> anyhow::Result<String> {
    let enc_data = aes_encrypt(data, key)?;
    Ok(serde_json::to_string(&enc_data)?)
}

#[inline]
pub fn decrypt(data: Vec<u8>, key: &str) -> anyhow::Result<String> {
    let dec_data = ase_decrypt(data, key)?;
    let data = String::from_utf8(dec_data)?;
    Ok(data)
}

fn aes_encrypt(content: &str, password: &str) -> anyhow::Result<EncryptionData> {
    // bytes for salt
    let salt = random::<[u8; 8]>().to_vec();
    // bytes for key and iv
    let (key, iv) = default_evp_kdf(password.as_bytes(), &salt).map_err(|err| anyhow!(err))?;

    let mut buf = vec![0u8; content.len() + 32];

    // encrypt
    let cipher_bytes = Aes256CbcEnc::new_from_slices(&key, &iv)?
        .encrypt_padded_b2b_mut::<Pkcs7>(content.as_bytes(), &mut buf)
        .map_err(|err| anyhow::anyhow!(err))?;

    let mut md5_hash = md5::Context::new();
    let mut salted = String::new();
    let mut dx: Vec<u8> = vec![];

    for _ in 0..3 {
        md5_hash.consume(&dx);
        md5_hash.consume(password.as_bytes());
        md5_hash.consume(&salt);

        let digest = md5_hash.compute();
        dx = digest.as_ref().to_vec();
        md5_hash = md5::Context::new();

        salted += &dx.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    }

    let cipher_text = general_purpose::STANDARD.encode(&cipher_bytes);
    let enc_data = EncryptionData {
        ct: cipher_text,
        iv: salted[64..64 + 32].to_string(),
        s: salt
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>(),
    };
    Ok(enc_data)
}

fn ase_decrypt(content: Vec<u8>, password: &str) -> anyhow::Result<Vec<u8>> {
    let encode_data = serde_json::from_slice::<EncryptionData>(&content)?;

    // bytes for cipher text
    let ct = general_purpose::STANDARD.decode(&encode_data.ct)?;
    // bytes for salt
    let salt = hex_to_bytes(&encode_data.s).ok_or(ArkoseError::HexDecodeError)?;
    // bytes for iv
    let iv = hex_to_bytes(&encode_data.iv).ok_or(ArkoseError::HexDecodeError)?;
    // bytes for key
    let (key, _) = (default_evp_kdf(password.as_bytes(), &salt).map_err(|s| anyhow::anyhow!(s)))?;

    let mut out_buf = vec![0u8; ct.len()];

    // decrypt
    let decode_bytes = Aes256CbcDec::new_from_slices(&key, &iv)?
        .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut out_buf)
        .map_err(|err| anyhow::anyhow!(err))?;
    Ok(decode_bytes.to_vec())
}

fn evp_kdf(
    password: &[u8],
    salt: &[u8],
    key_size: usize,
    iterations: usize,
    hash_algorithm: &str,
) -> Result<Vec<u8>, ArkoseError> {
    let mut derived_key_bytes = Vec::new();
    match hash_algorithm {
        "md5" => {
            let mut block = Vec::new();
            let mut hasher = md5::Context::new();

            while derived_key_bytes.len() < key_size * 4 {
                if !block.is_empty() {
                    hasher.consume(&block);
                }
                hasher.consume(password);
                hasher.consume(salt);

                let digest = hasher.compute();
                block = digest.as_ref().to_vec();
                hasher = md5::Context::new();

                for _ in 1..iterations {
                    hasher.consume(&block);
                    let digest = hasher.compute();
                    block = digest.as_ref().to_vec();
                    hasher = md5::Context::new();
                }

                derived_key_bytes.extend_from_slice(&block);
            }
        }
        _ => return Err(ArkoseError::UnsupportedHashAlgorithm),
    }

    Ok(derived_key_bytes[..key_size * 4].to_vec())
}

fn default_evp_kdf(password: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ArkoseError> {
    let key_size = 256 / 32;
    let iv_size = 128 / 32;
    let derived_key_bytes = evp_kdf(password, salt, key_size + iv_size, 1, "md5")?;
    Ok((
        derived_key_bytes[..key_size * 4].to_vec(),
        derived_key_bytes[key_size * 4..].to_vec(),
    ))
}

fn hex_to_bytes(hex_string: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = 0;

    for (i, hex_char) in hex_string.chars().enumerate() {
        if let Some(digit) = hex_char.to_digit(16) {
            buffer = (buffer << 4) | digit;

            if i % 2 == 1 {
                bytes.push(buffer as u8);
                buffer = 0;
            }
        } else {
            return None;
        }
    }

    if hex_string.len() % 2 != 0 {
        return None;
    }

    Some(bytes)
}
