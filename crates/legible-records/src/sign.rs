//! Ed25519 signatures over Legible Records files: the three contexts, keys,
//! and the signature file (`manifest.sig`, `feed.sig`, `keys.sig`).

use crate::bundle::canonical_record;
use crate::code::Code;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

/// What a signature is over. Each context has its own prefix, so a signature
/// made for one kind of file can't be passed off as another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Manifest,
    Feed,
    Keys,
}

impl Context {
    /// The bytes that come before the file's bytes in what is signed.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Context::Manifest => b"legible-records/v1 manifest\n",
            Context::Feed => b"legible-records/v1 feed\n",
            Context::Keys => b"legible-records/v1 keys\n",
        }
    }
}

/// A public key and the publisher and id it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub publisher: String,
    pub id: String,
    pub key: [u8; 32],
}

/// A private key and the publisher and id it belongs to.
#[derive(Clone)]
pub struct SigningKey {
    pub publisher: String,
    pub id: String,
    inner: ed25519_dalek::SigningKey,
}

/// Whether `s` is a key id: `^[a-z0-9][a-z0-9.-]{0,63}$`.
pub fn is_key_id(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
}

fn check_names(publisher: &str, id: &str) -> Result<(), String> {
    if !is_publisher(publisher) {
        return Err(format!(
            "{publisher:?} is not a publisher: use a lowercase domain such as acme.example, with no scheme, port or path"
        ));
    }
    if !is_key_id(id) {
        return Err(format!(
            "{id:?} is not a key id: use lowercase letters, digits, dots and hyphens, up to 64, such as 2026-11"
        ));
    }
    Ok(())
}

impl SigningKey {
    /// A new key from the system's random source.
    pub fn generate(publisher: &str, id: &str) -> Result<SigningKey, String> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("no random source: {e}"))?;
        SigningKey::from_seed(publisher, id, seed)
    }

    /// A key from its 32-byte seed.
    pub fn from_seed(publisher: &str, id: &str, seed: [u8; 32]) -> Result<SigningKey, String> {
        check_names(publisher, id)?;
        Ok(SigningKey {
            publisher: publisher.to_owned(),
            id: id.to_owned(),
            inner: ed25519_dalek::SigningKey::from_bytes(&seed),
        })
    }

    /// Reads the tools' secret key file. It is not a spec type.
    pub fn from_json(bytes: &[u8]) -> Result<SigningKey, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("not a secret key file: {e}"))?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("not a secret key file: {name} is missing"))
        };
        if field("$type")? != "legible-secret-key" {
            return Err("not a secret key file: $type isn't legible-secret-key".to_owned());
        }
        if field("alg")? != "ed25519" {
            return Err("not a secret key file: alg isn't ed25519".to_owned());
        }
        let seed: [u8; 32] = Zeroizing::new(
            from_b64url(field("seed")?)
                .map_err(|_| "not a secret key file: seed is not base64url without padding")?,
        )
        .as_slice()
        .try_into()
        .map_err(|_| "not a secret key file: seed isn't 32 bytes".to_owned())?;
        SigningKey::from_seed(field("publisher")?, field("id")?, seed)
    }

    /// The secret key file: `{"$type": "legible-secret-key", ...}`.
    pub fn to_json(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(canonical_record(&json!({
            "$type": "legible-secret-key",
            "publisher": self.publisher,
            "id": self.id,
            "alg": "ed25519",
            "seed": b64url(&self.inner.to_bytes()),
        })))
    }

    /// The public half.
    pub fn public(&self) -> PublicKey {
        PublicKey {
            publisher: self.publisher.clone(),
            id: self.id.clone(),
            key: self.inner.verifying_key().to_bytes(),
        }
    }
}

/// The JSON of `manifest.sig`, `feed.sig` and `keys.sig`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFile {
    pub alg: String,
    pub publisher: String,
    pub key: String,
    pub signature: Vec<u8>,
}

impl SignatureFile {
    /// Reads a signature file. A file that isn't the JSON the spec defines is
    /// `bad_signature_file`; another algorithm is `unknown_alg`.
    pub fn parse(bytes: &[u8]) -> Result<SignatureFile, Code> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| Code::BadSignatureFile)?;
        let object = value.as_object().ok_or(Code::BadSignatureFile)?;
        const MEMBERS: [&str; 4] = ["alg", "publisher", "key", "signature"];
        if object.len() != MEMBERS.len() || MEMBERS.iter().any(|m| !object.contains_key(*m)) {
            return Err(Code::BadSignatureFile);
        }
        let text = |name: &str| {
            object[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(Code::BadSignatureFile)
        };
        let alg = text("alg")?;
        let publisher = text("publisher")?;
        let key = text("key")?;
        let signature = from_b64url(&text("signature")?).map_err(|_| Code::BadSignatureFile)?;
        if signature.len() != 64 {
            return Err(Code::BadSignatureFile);
        }
        if alg != "ed25519" {
            return Err(Code::UnknownAlg);
        }
        Ok(SignatureFile {
            alg,
            publisher,
            key,
            signature,
        })
    }

    /// The file's bytes as a signer writes them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut object = Map::new();
        object.insert("alg".to_owned(), json!(self.alg));
        object.insert("publisher".to_owned(), json!(self.publisher));
        object.insert("key".to_owned(), json!(self.key));
        object.insert("signature".to_owned(), json!(b64url(&self.signature)));
        canonical_record(&Value::Object(object))
    }
}

fn signed_bytes(context: Context, message: &[u8]) -> Vec<u8> {
    let mut bytes = context.prefix().to_vec();
    bytes.extend_from_slice(message);
    bytes
}

/// Signs the context prefix followed by `message`, the file's exact bytes.
pub fn sign(key: &SigningKey, context: Context, message: &[u8]) -> SignatureFile {
    let signature = key.inner.sign(&signed_bytes(context, message));
    SignatureFile {
        alg: "ed25519".to_owned(),
        publisher: key.publisher.clone(),
        key: key.id.clone(),
        signature: signature.to_bytes().to_vec(),
    }
}

/// Checks that `sig` names `key` and is a valid signature over the context
/// prefix and `message`.
pub fn verify(
    key: &PublicKey,
    context: Context,
    message: &[u8],
    sig: &SignatureFile,
) -> Result<(), Code> {
    if sig.alg != "ed25519" {
        return Err(Code::UnknownAlg);
    }
    if sig.publisher != key.publisher {
        return Err(Code::PublisherMismatch);
    }
    if sig.key != key.id {
        return Err(Code::UnknownKey);
    }
    let verifying = VerifyingKey::from_bytes(&key.key).map_err(|_| Code::BadSignature)?;
    let bytes: [u8; 64] = sig
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Code::BadSignatureFile)?;
    verifying
        .verify_strict(
            &signed_bytes(context, message),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| Code::BadSignature)
}

/// Whether `s` is a publisher: what `common.domain` accepts, which is
/// `^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`.
pub fn is_publisher(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let mut labels = 0;
    for label in s.split('.') {
        let b = label.as_bytes();
        let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let ok = !b.is_empty()
            && edge(b[0])
            && edge(b[b.len() - 1])
            && b.iter().all(|c| edge(*c) || *c == b'-');
        if !ok {
            return false;
        }
        labels += 1;
    }
    labels >= 2
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding.
pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Reads base64url without padding. Padding, other characters and a final
/// group with leftover bits are errors.
pub fn from_b64url(s: &str) -> Result<Vec<u8>, String> {
    // The input is never echoed: it may be a secret.
    let bad = || "not base64url without padding".to_owned();
    if s.len() % 4 == 1 {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B64.iter().position(|x| *x == c).ok_or_else(bad)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(bad());
    }
    Ok(out)
}
