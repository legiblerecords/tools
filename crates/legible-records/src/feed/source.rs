//! Where `pull` reads a feed's files and a publisher's key set from.

/// What a [`Source`] found at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    Found {
        bytes: Vec<u8>,
        /// The ETag to send back exactly as received, quotes included.
        etag: Option<String>,
    },
    /// The ETag sent still matches.
    NotModified,
    NotFound,
}

/// A feed's files, by path from the feed's base (`feed.json`, `feed.sig`,
/// `bundles/<sha256>.zip`).
pub trait Source {
    /// Fetches `path`, sending `etag` as `If-None-Match` when the source
    /// supports it. An error is a failure to fetch, such as a network error.
    fn get(&mut self, path: &str, etag: Option<&str>) -> Result<Fetched, String>;
}

/// The bytes of a publisher's `keys.json`, and of its `keys.sig` if it has one.
pub type KeySetFiles = (Vec<u8>, Option<Vec<u8>>);

/// A publisher's key set, `keys.json` and its `keys.sig`.
pub trait KeySource {
    /// The bytes of `publisher`'s `keys.json` and, if it has one, its
    /// `keys.sig`; `None` when the publisher serves no key set.
    fn key_set(&mut self, publisher: &str) -> Result<Option<KeySetFiles>, String>;
}

/// A key source for a reader that uses only its pins and the key sets it
/// already holds.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoKeySource;

impl KeySource for NoKeySource {
    fn key_set(&mut self, _publisher: &str) -> Result<Option<KeySetFiles>, String> {
        Ok(None)
    }
}

/// A feed in a local directory, laid out as at its base URL. It gives no
/// ETags, so never `NotModified`.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct DirSource {
    pub root: std::path::PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl Source for DirSource {
    fn get(&mut self, path: &str, _etag: Option<&str>) -> Result<Fetched, String> {
        if !crate::bundle::is_safe_path(path) {
            return Err(format!("{path}: not a path inside the feed"));
        }
        match std::fs::read(self.root.join(path)) {
            Ok(bytes) => Ok(Fetched::Found { bytes, etag: None }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Fetched::NotFound),
            Err(e) => Err(format!("{path}: {e}")),
        }
    }
}
