//! Reading feeds over the network (feature `net`): a [`Source`] for a
//! connection file's location and auth (`spec/feeds.md` § Access), and
//! [`HttpsKeySource`] for publishers' key sets (`records.md` § Key sets).
//!
//! - `https` locations, with `none`, `bearer` or `oauth-client-credentials`
//!   auth. An OAuth token is held in memory only, and fetched again when
//!   less than 60 seconds (or half its lifetime, if that is shorter) is
//!   left, or when the feed answers 401.
//! - `s3` locations, with `s3` auth (each GET presigned for 60 seconds) or
//!   `none` (a public bucket). The access key needs `s3:ListBucket` on the
//!   prefix as well as `s3:GetObject`: a reader asks for files that may not
//!   be there (`feed.json.age` beside `feed.json`, `feed.sig`), and S3
//!   answers 404 for a missing object only to a key that may list the
//!   bucket; to any other it answers 403, which is an error.
//!
//! Requests honour `HTTPS_PROXY` (and `ALL_PROXY`, `HTTP_PROXY`, `NO_PROXY`),
//! except to a loopback host, which is always reached directly. Server
//! certificates are checked with the platform's verifier. Redirects are
//! followed for https only, and never carry the `Authorization` header;
//! the OAuth token request follows none, so the client secret goes only to
//! `token_url`.
//!
//! Every body is read with a cap: [`MAX_INDEX_BYTES`] for the index, its
//! signature and key sets, and [`Limits::max_stored_bytes`] for bundles.
//! Secrets come from the environment variables the connection names, and
//! no error carries a secret, a token or a presigned URL's signature.

use std::time::{Duration, Instant};

use ureq::config::RedirectAuthHeaders;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::{Agent, Proxy};
use zeroize::Zeroizing;

use crate::bundle::{is_safe_path, Limits};
use crate::feed::connection::is_loopback;
use crate::feed::{Auth, Connection, Fetched, KeySetFiles, KeySource, Location, Source};
use crate::sign::is_publisher;

pub use crate::feed::MAX_INDEX_BYTES;

/// How long a presigned S3 GET is good for.
const PRESIGN_FOR: Duration = Duration::from_secs(60);
/// An OAuth token is fetched again when it has less than this left, or
/// less than half its lifetime if that is shorter.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);
/// The longest a request for a small file (an index, a signature, a key
/// set, a token) may take in all.
const SMALL_TIMEOUT: Duration = Duration::from_secs(120);

/// A [`Source`] for `conn`, with secrets read through `env` (normally
/// `|name| std::env::var(name).ok()`), and bundles capped at the default
/// [`Limits`]. Nothing is fetched yet.
pub fn source(
    conn: &Connection,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Box<dyn Source>, String> {
    source_with_limits(conn, env, &Limits::default())
}

/// [`source`], with bundles capped at `limits`' [`Limits::max_stored_bytes`]:
/// give it the limits `pull` opens bundles with.
pub fn source_with_limits(
    conn: &Connection,
    env: &dyn Fn(&str) -> Option<String>,
    limits: &Limits,
) -> Result<Box<dyn Source>, String> {
    let max_bundle = limits.max_stored_bytes();
    match (&conn.location, &conn.auth) {
        (Location::Https { url }, auth) => {
            let auth = match auth {
                Auth::None => HttpAuth::None,
                Auth::Bearer { token_env } => HttpAuth::Bearer(secret(env, token_env)?),
                Auth::OAuth {
                    token_url,
                    client_id,
                    client_secret_env,
                    resource,
                    scope,
                } => HttpAuth::OAuth(OAuth {
                    // No redirects: the form carries the client secret.
                    agent: agent_with(token_url, 0)?,
                    token_url: token_url.clone(),
                    client_id: client_id.clone(),
                    client_secret: secret(env, client_secret_env)?,
                    resource: resource.clone(),
                    scope: scope.clone(),
                    token: None,
                }),
                Auth::S3 { .. } => {
                    return Err("auth method s3 is for location kind s3, not https".to_owned())
                }
            };
            Ok(Box::new(HttpsSource {
                agent: agent(url)?,
                base: url.clone(),
                auth,
                max_bundle,
            }))
        }
        (
            Location::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                path_style,
            },
            auth,
        ) => {
            let credentials = match auth {
                Auth::None => None,
                Auth::S3 {
                    access_key_id_env,
                    secret_access_key_env,
                } => {
                    let key = secret(env, access_key_id_env)?;
                    let secret = secret(env, secret_access_key_env)?;
                    Some(rusty_s3::Credentials::new(key.as_str(), secret.as_str()))
                }
                Auth::Bearer { .. } | Auth::OAuth { .. } => {
                    return Err("location kind s3 takes auth method s3 or none".to_owned())
                }
            };
            let endpoint = url::Url::parse(endpoint)
                .map_err(|e| format!("location.endpoint isn't a URL: {e}"))?;
            let style = if *path_style {
                rusty_s3::UrlStyle::Path
            } else {
                rusty_s3::UrlStyle::VirtualHost
            };
            let bucket = rusty_s3::Bucket::new(endpoint, style, bucket.clone(), region.clone())
                .map_err(|e| format!("location: the bucket's URL can't be made: {e}"))?;
            Ok(Box::new(S3Source {
                agent: agent(bucket.base_url().as_str())?,
                bucket,
                credentials,
                prefix: normalize_prefix(prefix),
                max_bundle,
            }))
        }
    }
}

/// `prefix` with no leading `/` and ending in exactly one `/`; an empty
/// prefix stays empty.
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

/// The value of the variable `name`, which must be set and not empty. The
/// error names the variable, never a value.
fn secret(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<Zeroizing<String>, String> {
    match env(name) {
        Some(value) if !value.is_empty() => Ok(Zeroizing::new(value)),
        _ => Err(format!("the environment variable {name} is not set")),
    }
}

/// An agent for requests to `url`'s host: through the environment's proxy
/// unless the host is loopback, https only unless it is loopback (so no
/// redirect can downgrade an https feed), never treating a status as an
/// error, and with timeouts that stop a stalled server, not a slow download.
fn agent(url: &str) -> Result<Agent, String> {
    agent_with(url, 10)
}

/// [`agent`], following at most `max_redirects`.
fn agent_with(url: &str, max_redirects: u32) -> Result<Agent, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    let loopback = parsed.host_str().is_some_and(is_loopback);
    let proxy = if loopback {
        None
    } else {
        Proxy::try_from_env()
    };
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    Ok(Agent::config_builder()
        .proxy(proxy)
        .https_only(!loopback)
        .max_redirects(max_redirects)
        // Pinned rather than left to the default: a redirect never carries
        // a bearer token, wherever it points.
        .redirect_auth_headers(RedirectAuthHeaders::Never)
        .http_status_as_error(false)
        .tls_config(tls)
        .user_agent(concat!("legible-records/", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        .timeout_per_read(Some(Duration::from_secs(60)))
        .build()
        .into())
}

/// `text` with any URL's query cut off, so that a presigned URL's
/// signature doesn't reach an error message.
fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_url = false;
    let mut cut = false;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() || c == '"' || c == '\'' {
            in_url = false;
            cut = false;
        } else if !in_url && text[i..].starts_with("://") {
            in_url = true;
        } else if in_url && c == '?' {
            cut = true;
        }
        if !cut {
            out.push(c);
        }
    }
    out
}

/// A ureq error as a reason, without the URL it was for.
fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::BodyExceedsLimit(max) => format!("larger than {max} bytes"),
        ureq::Error::HostNotFound => "host not found".to_owned(),
        ureq::Error::ConnectionFailed => "couldn't connect".to_owned(),
        ureq::Error::TooManyRedirects => "too many redirects".to_owned(),
        ureq::Error::RequireHttpsOnly(_) => "redirected to a URL that isn't https".to_owned(),
        ureq::Error::BadUri(_) => "a bad URL".to_owned(),
        other => scrub(&other.to_string()),
    }
}

/// What a GET found: its status, and for a 200 its body and ETag.
struct Reply {
    status: u16,
    etag: Option<String>,
    retry_after: Option<String>,
    body: Vec<u8>,
}

/// GETs `url`, reading a 200's body up to `max` bytes. The error never
/// repeats the URL.
fn get(
    agent: &Agent,
    url: &str,
    bearer: Option<&str>,
    etag: Option<&str>,
    max: u64,
) -> Result<Reply, String> {
    let mut request = agent.get(url);
    if max <= MAX_INDEX_BYTES {
        request = request.config().timeout_global(Some(SMALL_TIMEOUT)).build();
    }
    if let Some(token) = bearer {
        request = request.header(
            "Authorization",
            Zeroizing::new(format!("Bearer {token}")).as_str(),
        );
    }
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().map_err(describe)?;
    let status = response.status().as_u16();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let etag = header("etag");
    let retry_after = header("retry-after");
    let mut body = Vec::new();
    if status == 200 {
        let length = header("content-length").and_then(|v| v.parse::<u64>().ok());
        if length.is_some_and(|length| length > max) {
            return Err(format!("larger than {max} bytes"));
        }
        body = response
            .body_mut()
            .with_config()
            .limit(max)
            .read_to_vec()
            .map_err(describe)?;
    }
    Ok(Reply {
        status,
        etag,
        retry_after,
        body,
    })
}

/// A status other than 200, 304 and 404 as an error.
fn status_error(reply: &Reply) -> String {
    let mut text = format!("HTTP {}", reply.status);
    match reply.status {
        401 | 403 => text.push_str(" (not authorized)"),
        429 => {
            text.push_str(" (too many requests");
            if let Some(after) = reply
                .retry_after
                .as_deref()
                .filter(|a| a.len() <= 64 && a.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
            {
                text.push_str(&format!("; retry after {after}"));
            }
            text.push(')');
        }
        _ => {}
    }
    text
}

fn fetched(reply: Reply) -> Result<Fetched, String> {
    match reply.status {
        200 => Ok(Fetched::Found {
            bytes: reply.body,
            etag: reply.etag,
        }),
        304 => Ok(Fetched::NotModified),
        404 => Ok(Fetched::NotFound),
        _ => Err(status_error(&reply)),
    }
}

/// A path `pull` asks for, checked, and the most its body may hold.
fn checked(path: &str, max_bundle: u64) -> Result<u64, String> {
    if !is_safe_path(path) {
        return Err(format!("{path:?} is not a path inside the feed"));
    }
    Ok(if path.starts_with("bundles/") {
        max_bundle
    } else {
        MAX_INDEX_BYTES
    })
}

enum HttpAuth {
    None,
    Bearer(Zeroizing<String>),
    OAuth(OAuth),
}

/// An OAuth client-credentials client, and the token it holds in memory.
struct OAuth {
    agent: Agent,
    token_url: String,
    client_id: String,
    client_secret: Zeroizing<String>,
    resource: Option<String>,
    scope: Option<String>,
    /// The token held, if any.
    token: Option<Token>,
}

/// An OAuth access token.
struct Token {
    value: Zeroizing<String>,
    /// When it expires and how long it was good for, if the server said
    /// and the instant can be represented; else it is held until a 401.
    expires: Option<(Instant, Duration)>,
}

impl Token {
    /// Whether it is good for this request: more than the margin left,
    /// the margin being 60 s or half its lifetime, whichever is shorter,
    /// so that a short-lived token isn't fetched again for every request.
    fn fresh(&self, now: Instant) -> bool {
        match self.expires {
            None => true,
            Some((at, lifetime)) => {
                let margin = TOKEN_MARGIN.min(lifetime / 2);
                now.checked_add(margin).is_some_and(|edge| edge < at)
            }
        }
    }
}

impl OAuth {
    /// The token to send: the one held, unless it expires within the
    /// margin, else a new one.
    fn token(&mut self) -> Result<Zeroizing<String>, String> {
        if let Some(token) = &self.token {
            if token.fresh(Instant::now()) {
                return Ok(token.value.clone());
            }
        }
        self.token = None;
        let token = self.fetch()?;
        let value = token.value.clone();
        self.token = Some(token);
        Ok(value)
    }

    fn forget(&mut self) {
        self.token = None;
    }

    fn fetch(&self) -> Result<Token, String> {
        let asked = Instant::now();
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if let Some(resource) = &self.resource {
            form.push(("resource", resource));
        }
        if let Some(scope) = &self.scope {
            form.push(("scope", scope));
        }
        let fail = |why: String| format!("token request: {why}");
        let mut response = self
            .agent
            .post(&self.token_url)
            .config()
            .timeout_global(Some(SMALL_TIMEOUT))
            .build()
            .header("Accept", "application/json")
            .send_form(form)
            .map_err(|e| fail(describe(e)))?;
        let status = response.status().as_u16();
        let body = Zeroizing::new(
            response
                .body_mut()
                .with_config()
                .limit(MAX_INDEX_BYTES)
                .read_to_vec()
                .map_err(|e| fail(describe(e)))?,
        );
        // The body holds the token, or perhaps an echo of the request: only
        // a short error code from it is ever repeated.
        let value: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
        let field = |name: &str| value.as_ref().and_then(|v| v.get(name));
        let code = field("error")
            .and_then(|v| v.as_str())
            .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
            .map(|c| format!(" ({c})"))
            .unwrap_or_default();
        if status != 200 {
            return Err(fail(format!("HTTP {status}{code}")));
        }
        let token = field("access_token")
            .and_then(|v| v.as_str())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| fail(format!("the answer has no access_token{code}")))?;
        if field("token_type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| !t.eq_ignore_ascii_case("bearer"))
        {
            return Err(fail("the token isn't a bearer token".to_owned()));
        }
        let expires_in = field("expires_in").and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        });
        // A lifetime too long to represent counts as none given.
        let expires = expires_in.and_then(|secs| {
            let lifetime = Duration::from_secs(secs);
            asked.checked_add(lifetime).map(|at| (at, lifetime))
        });
        Ok(Token {
            value: Zeroizing::new(token.to_owned()),
            expires,
        })
    }
}

/// A feed at an https base URL.
struct HttpsSource {
    agent: Agent,
    /// Ends in a slash (`parse_connection` checks), so a path is appended.
    base: String,
    auth: HttpAuth,
    max_bundle: u64,
}

impl Source for HttpsSource {
    fn get(&mut self, path: &str, etag: Option<&str>) -> Result<Fetched, String> {
        let max = checked(path, self.max_bundle)?;
        let url = format!("{}{path}", self.base);
        let mut retried = false;
        loop {
            let token = match &mut self.auth {
                HttpAuth::None => None,
                HttpAuth::Bearer(token) => Some(token.clone()),
                HttpAuth::OAuth(oauth) => Some(oauth.token()?),
            };
            let reply = get(
                &self.agent,
                &url,
                token.as_deref().map(|t| t.as_str()),
                etag,
                max,
            )?;
            // A token the server no longer takes is dropped, and the
            // request made once more with a new one.
            if let (401, HttpAuth::OAuth(oauth), false) = (reply.status, &mut self.auth, retried) {
                oauth.forget();
                retried = true;
                continue;
            }
            return fetched(reply);
        }
    }
}

/// S3's 403, which is also its answer for a missing object to a key that
/// can't list the bucket.
const S3_FORBIDDEN: &str = "HTTP 403 (not authorized; S3 also answers 403 for a missing object when the key can't list the bucket)";

/// A feed under a prefix in an S3-compatible bucket.
struct S3Source {
    agent: Agent,
    bucket: rusty_s3::Bucket,
    credentials: Option<rusty_s3::Credentials>,
    /// Empty, or ending in exactly one slash.
    prefix: String,
    max_bundle: u64,
}

impl Source for S3Source {
    fn get(&mut self, path: &str, etag: Option<&str>) -> Result<Fetched, String> {
        use rusty_s3::S3Action;
        let max = checked(path, self.max_bundle)?;
        let key = format!("{}{path}", self.prefix);
        let url = self
            .bucket
            .get_object(self.credentials.as_ref(), &key)
            .sign(PRESIGN_FOR);
        let reply = get(&self.agent, url.as_str(), None, etag, max)?;
        if reply.status == 403 {
            return Err(S3_FORBIDDEN.to_owned());
        }
        fetched(reply)
    }
}

/// Publishers' key sets, from
/// `https://<publisher>/.well-known/legible-records/keys.json` and
/// `keys.sig`. A publisher with no `keys.json` (404) has no key set, and one
/// with no `keys.sig` (404) has an unendorsed one; any other failure is an
/// error, so that `pull` keeps the key set it holds.
pub struct HttpsKeySource {
    agent: Agent,
    /// Replaces `https://<publisher>`.
    origin: Option<String>,
}

impl HttpsKeySource {
    pub fn new() -> HttpsKeySource {
        HttpsKeySource {
            agent: agent("https://example.com/").expect("a fixed URL parses"),
            origin: None,
        }
    }

    /// Reads every publisher's key set from `origin` instead of from the
    /// publisher's own domain: `<origin>/.well-known/legible-records/keys.json`
    /// and `keys.sig`.
    ///
    /// This is for a reader on the publisher's own machine, such as a
    /// collector on an outpost node that reads the key set from the node's own
    /// server on loopback (`http://127.0.0.1:8080`) while it pins the signer's
    /// key. `origin` must be a loopback host (`127.0.0.1`, `[::1]` or
    /// `localhost`), so that nothing but the machine itself can stand in for a
    /// publisher's domain; any other host is an `Err`. Loopback is reached
    /// directly, never through a proxy, and over plain `http`.
    pub fn loopback(origin: &str) -> Result<HttpsKeySource, String> {
        let parsed =
            url::Url::parse(origin).map_err(|e| format!("key source origin: not a URL: {e}"))?;
        if !parsed.host_str().is_some_and(is_loopback) {
            return Err(
                "key source origin: only a loopback host (127.0.0.1, [::1], localhost) may stand in for a publisher's domain"
                    .to_owned(),
            );
        }
        let origin = origin.trim_end_matches('/').to_owned();
        Ok(HttpsKeySource {
            agent: agent(&origin).map_err(|e| format!("key source origin: {e}"))?,
            origin: Some(origin),
        })
    }

    /// The former name of [`HttpsKeySource::loopback`].
    #[deprecated(note = "renamed to `HttpsKeySource::loopback`")]
    pub fn with_base(origin: &str) -> Result<HttpsKeySource, String> {
        HttpsKeySource::loopback(origin)
    }

    fn file(&self, base: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
        let url = format!("{base}/.well-known/legible-records/{name}");
        let reply = get(&self.agent, &url, None, None, MAX_INDEX_BYTES)
            .map_err(|e| format!("{name}: {e}"))?;
        match reply.status {
            200 => Ok(Some(reply.body)),
            404 => Ok(None),
            _ => Err(format!("{name}: {}", status_error(&reply))),
        }
    }
}

impl Default for HttpsKeySource {
    fn default() -> HttpsKeySource {
        HttpsKeySource::new()
    }
}

impl KeySource for HttpsKeySource {
    fn key_set(&mut self, publisher: &str) -> Result<Option<KeySetFiles>, String> {
        if !is_publisher(publisher) {
            return Err(format!("{publisher:?} is not a publisher's domain"));
        }
        let base = match &self.origin {
            Some(origin) => origin.clone(),
            None => format!("https://{publisher}"),
        };
        let Some(keys) = self.file(&base, "keys.json")? else {
            return Ok(None);
        };
        let sig = self.file(&base, "keys.sig")?;
        Ok(Some((keys, sig)))
    }
}
