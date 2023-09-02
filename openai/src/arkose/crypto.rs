use nom::AsBytes;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct EncryptionData {
    ct: String,
    iv: String,
    s: String,
}

pub fn encrypt(data: &str, key: &str) -> anyhow::Result<String> {
    let enc_data = aes_encrypt(data, key)?;
    Ok(serde_json::to_string(&enc_data)?)
}

pub fn decrypt(data: Vec<u8>, key: &str) -> anyhow::Result<String> {
    let dec_data = ase_decrypt(data, key)?;
    Ok(String::from_utf8(dec_data)?)
}

fn aes_encrypt(content: &str, password: &str) -> anyhow::Result<EncryptionData> {
    let salt: Vec<u8> = rand::thread_rng().gen::<[u8; 8]>().to_vec();
    let (key, iv) = default_evp_kdf(password.as_bytes(), &salt).map_err(|s| anyhow::anyhow!(s))?;

    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut buf = [0u8; 8192];

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
    #[allow(deprecated)]
    let cipher_text = base64::encode(&cipher_bytes);
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

    #[allow(deprecated)]
    let decode_ct = base64::decode(&encode_data.ct)?;

    let salt: Result<Vec<u8>, _> = (0..encode_data.s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&encode_data.s[i..i + 2], 16))
        .collect();

    let (key, iv) =
        default_evp_kdf(password.as_bytes(), salt?.as_bytes()).map_err(|s| anyhow::anyhow!(s))?;

    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut buf = [0u8; 8192];

    let decode_bytes = Aes256CbcDec::new_from_slices(&key, &iv)?
        .decrypt_padded_b2b_mut::<Pkcs7>(&decode_ct, &mut buf)
        .map_err(|err| anyhow::anyhow!(err))?;

    Ok(decode_bytes.to_vec())
}

fn evp_kdf(
    password: &[u8],
    salt: &[u8],
    key_size: usize,
    iterations: usize,
    hash_algorithm: &str,
) -> Result<Vec<u8>, &'static str> {
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
        _ => return Err("unsupported hash algorithm"),
    }

    Ok(derived_key_bytes[..key_size * 4].to_vec())
}

fn default_evp_kdf(password: &[u8], salt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let key_size = 256 / 32;
    let iv_size = 128 / 32;
    let derived_key_bytes = evp_kdf(password, salt, key_size + iv_size, 1, "md5")?;
    Ok((
        derived_key_bytes[..key_size * 4].to_vec(),
        derived_key_bytes[key_size * 4..].to_vec(),
    ))
}
