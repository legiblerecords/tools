//! Encrypted bundles and feeds: [age](https://age-encryption.org).
//!
//! [`is_encrypted`] tells an age file by its first bytes, binary or
//! armored, and is always built. [`encrypt`] and [`decrypt`] need feature
//! `age`.

/// The first bytes of a binary age file.
const BINARY: &[u8] = b"age-encryption.org/";
/// The first bytes of an armored age file.
const ARMORED: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// Whether `bytes` start like an age file, binary or armored.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(BINARY) || bytes.starts_with(ARMORED)
}

/// Encrypts `bytes` to the age recipients given (`age1...`), as a binary
/// age file.
#[cfg(feature = "age")]
pub fn encrypt(bytes: &[u8], recipients: &[String]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    if recipients.is_empty() {
        return Err("no recipients".to_owned());
    }
    let parsed = recipients
        .iter()
        .map(|text| {
            text.parse::<age::x25519::Recipient>()
                .map_err(|e| format!("recipient {text:?}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let encryptor =
        age::Encryptor::with_recipients(parsed.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(|e| e.to_string())?;
    writer.write_all(bytes).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    Ok(out)
}

/// Decrypts a binary or armored age file with the identities in
/// `identities`, the text of an identity file, refusing one whose plaintext
/// is larger than `max_bytes` without holding more than that, so that a
/// small ciphertext can't fill memory. An error never repeats the identity
/// text.
#[cfg(feature = "age")]
pub fn decrypt(bytes: &[u8], identities: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = age::IdentityFile::from_buffer(std::io::BufReader::new(identities.as_bytes()))
        .map_err(|_| "the identity file couldn't be read".to_owned())?;
    let identities = file
        .into_identities()
        .map_err(|e| format!("the identity file has an identity this reader can't use: {e}"))?;
    if identities.is_empty() {
        return Err("the identity file has no identities".to_owned());
    }
    // ArmoredReader passes a binary file through unchanged.
    let reader = age::armor::ArmoredReader::new(bytes);
    let decryptor = age::Decryptor::new(reader).map_err(|e| e.to_string())?;
    let mut stream = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    (&mut stream)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > max_bytes {
        return Err(format!(
            "the decrypted file is larger than {max_bytes} bytes"
        ));
    }
    Ok(out)
}
