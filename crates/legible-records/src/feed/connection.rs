//! Connection files (`spec/feeds.md` § Connection files): how a reader
//! reaches and trusts one feed. They name environment variables, never
//! secrets.

use serde_json::{Map, Value};

use super::index::{is_feed_id, string};
use crate::keys::Pin;
use crate::sign::{from_b64url, is_key_id, is_publisher};

/// A connection file's `$type`.
pub const CONNECTION_TYPE: &str = "org.legiblerecords.feed-connection";

/// Where a feed's files are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// The feed's base URL, `https://` (or `http://` for a loopback host),
    /// ending in a slash: a file's URL is this followed by its path.
    Https { url: String },
    /// A prefix in an S3-compatible bucket.
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        /// Address the bucket in the path rather than the host name.
        path_style: bool,
    },
}

/// How a reader authenticates. Every secret is the name of an environment
/// variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    None,
    Bearer {
        token_env: String,
    },
    OAuth {
        token_url: String,
        client_id: String,
        client_secret_env: String,
        resource: Option<String>,
        scope: Option<String>,
    },
    S3 {
        access_key_id_env: String,
        secret_access_key_env: String,
    },
}

/// A connection file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    /// The feed's id, `<publisher>/<slug>`.
    pub feed: String,
    pub location: Location,
    pub auth: Auth,
    /// Pinned keys (the file's `keys`).
    pub pins: Vec<Pin>,
    /// The variable holding the reader's age identity.
    pub age_identity_env: Option<String>,
}

impl Connection {
    /// The feed's publisher: the domain its id starts with.
    pub fn publisher(&self) -> &str {
        self.feed.split_once('/').map_or(&self.feed, |(p, _)| p)
    }
}

fn is_env_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// A required field of `object` (named `place.name` in errors).
fn required(
    object: &Map<String, Value>,
    place: &str,
    name: &str,
    why: &str,
) -> Result<String, String> {
    match object.get(name) {
        None | Some(Value::Null) => Err(format!("{place}.{name} is required {why}")),
        Some(_) => string(object, name)
            .map(str::to_owned)
            .map_err(|e| format!("{place}.{e}")),
    }
}

fn optional(
    object: &Map<String, Value>,
    place: &str,
    name: &str,
) -> Result<Option<String>, String> {
    match object.get(name) {
        None => Ok(None),
        Some(_) => string(object, name)
            .map(|s| Some(s.to_owned()))
            .map_err(|e| format!("{place}.{e}")),
    }
}

fn env(object: &Map<String, Value>, place: &str, name: &str, why: &str) -> Result<String, String> {
    let value = required(object, place, name, why)?;
    if !is_env_name(&value) {
        return Err(format!(
            "{place}.{name} must name an environment variable, such as ACME_FEED_TOKEN"
        ));
    }
    Ok(value)
}

/// Whether `host` (as written in a URL, without its port) is this machine.
fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "[::1]" | "localhost")
}

/// An `https` URL with a host and no userinfo. Plain `http` is allowed
/// only for a loopback host (127.0.0.1, [::1], localhost), for local tests.
fn url(object: &Map<String, Value>, place: &str, name: &str, why: &str) -> Result<String, String> {
    let value = required(object, place, name, why)?;
    let (rest, plain) = match value.strip_prefix("https://") {
        Some(rest) => (rest, false),
        None => match value.strip_prefix("http://") {
            Some(rest) => (rest, true),
            None => return Err(format!("{place}.{name} must be an https:// URL")),
        },
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        // The value isn't echoed: its userinfo is a credential.
        return Err(format!(
            "{place}.{name} carries userinfo (user:password@): a connection file holds no credential"
        ));
    }
    if authority.is_empty() {
        return Err(format!("{place}.{name} has no host"));
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6
            .split_once(']')
            .map_or(authority, |(h, _)| &authority[..h.len() + 2]),
        None => authority.split(':').next().unwrap_or_default(),
    };
    if plain && !is_loopback(host) {
        return Err(format!(
            "{place}.{name} must be an https:// URL (http:// is only for 127.0.0.1, [::1] or localhost)"
        ));
    }
    Ok(value)
}

/// Fields that can only be `null`, so that a literal secret doesn't validate.
fn no_secrets(object: &Map<String, Value>, place: &str, names: &[&str]) -> Result<(), String> {
    for name in names {
        if object.get(*name).is_some_and(|v| !v.is_null()) {
            return Err(format!(
                "{place}.{name} holds a value: a connection file holds no secret; use {name}_env to name the variable that does"
            ));
        }
    }
    Ok(())
}

fn location(value: Option<&Value>) -> Result<Location, String> {
    let object = value
        .and_then(Value::as_object)
        .ok_or("location is required, as an object")?;
    let kind = required(object, "location", "kind", "")?;
    match kind.as_str() {
        "https" => {
            // The base URL ends in a slash, so a reader joins paths onto it
            // by appending. One without is refused rather than guessed at.
            let url = url(object, "location", "url", "for kind https")?;
            if !url.ends_with('/') || url.contains(['?', '#']) {
                return Err(
                    "location.url must be the feed's base URL, ending in a slash, with no query or fragment"
                        .to_owned(),
                );
            }
            Ok(Location::Https { url })
        }
        "s3" => {
            let why = "for kind s3";
            let path_style = match object.get("path_style") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return Err("location.path_style must be true or false".to_owned()),
            };
            Ok(Location::S3 {
                endpoint: url(object, "location", "endpoint", why)?,
                region: required(object, "location", "region", why)?,
                bucket: required(object, "location", "bucket", why)?,
                prefix: required(object, "location", "prefix", why)?,
                path_style,
            })
        }
        other => Err(format!(
            "location.kind {other:?} is not one this reader knows (https, s3)"
        )),
    }
}

fn auth(value: Option<&Value>) -> Result<Auth, String> {
    let object = value
        .and_then(Value::as_object)
        .ok_or("auth is required, as an object")?;
    no_secrets(
        object,
        "auth",
        &[
            "token",
            "client_secret",
            "access_key_id",
            "secret_access_key",
        ],
    )?;
    let method = required(object, "auth", "method", "")?;
    match method.as_str() {
        "none" => Ok(Auth::None),
        "bearer" => Ok(Auth::Bearer {
            token_env: env(object, "auth", "token_env", "for method bearer")?,
        }),
        "oauth-client-credentials" => {
            let why = "for method oauth-client-credentials";
            Ok(Auth::OAuth {
                token_url: url(object, "auth", "token_url", why)?,
                client_id: required(object, "auth", "client_id", why)?,
                client_secret_env: env(object, "auth", "client_secret_env", why)?,
                resource: optional(object, "auth", "resource")?,
                scope: optional(object, "auth", "scope")?,
            })
        }
        "s3" => {
            let why = "for method s3";
            Ok(Auth::S3 {
                access_key_id_env: env(object, "auth", "access_key_id_env", why)?,
                secret_access_key_env: env(object, "auth", "secret_access_key_env", why)?,
            })
        }
        other => Err(format!(
            "auth.method {other:?} is not one this reader knows (none, bearer, oauth-client-credentials, s3)"
        )),
    }
}

fn pins(value: Option<&Value>) -> Result<Vec<Pin>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let listed = value.as_array().ok_or("keys must be a list")?;
    let mut pins = Vec::with_capacity(listed.len());
    for (index, key) in listed.iter().enumerate() {
        let place = format!("keys[{index}]");
        let object = key
            .as_object()
            .ok_or_else(|| format!("{place} must be an object"))?;
        let publisher = required(object, &place, "publisher", "")?;
        if !is_publisher(&publisher) {
            return Err(format!("{place}.publisher {publisher:?} is not a domain"));
        }
        let id = required(object, &place, "id", "")?;
        if !is_key_id(&id) {
            return Err(format!("{place}.id {id:?} is not a key id"));
        }
        let alg = required(object, &place, "alg", "")?;
        if alg != "ed25519" {
            return Err(format!("{place}.alg {alg:?} is not ed25519"));
        }
        let public_key = from_b64url(&required(object, &place, "public_key", "")?)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| {
                format!("{place}.public_key is not 32 bytes of base64url without padding")
            })?;
        pins.push(Pin {
            publisher,
            id,
            public_key,
        });
    }
    Ok(pins)
}

/// Reads a connection file, refusing one that lacks a field its location's
/// `kind` or auth `method` needs, names a kind or method this reader
/// doesn't know, carries userinfo in a URL, or holds a literal secret.
pub fn parse_connection(bytes: &[u8]) -> Result<Connection, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("connection file: not JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or("connection file: not a JSON object")?;
    let inner = || -> Result<Connection, String> {
        if string(object, "$type")? != CONNECTION_TYPE
            || object.get("version") != Some(&Value::from(1))
        {
            return Err(format!("not an {CONNECTION_TYPE} version 1"));
        }
        no_secrets(object, "connection", &["age_identity"])?;
        let feed = string(object, "feed")?;
        if !is_feed_id(feed) {
            return Err(format!("feed {feed:?} is not <publisher>/<slug>"));
        }
        let age_identity_env = match object.get("age_identity_env") {
            None => None,
            Some(_) => Some(env(object, "connection", "age_identity_env", "")?),
        };
        Ok(Connection {
            feed: feed.to_owned(),
            location: location(object.get("location"))?,
            auth: auth(object.get("auth"))?,
            pins: pins(object.get("keys"))?,
            age_identity_env,
        })
    };
    inner().map_err(|e| format!("connection file: {e}"))
}
