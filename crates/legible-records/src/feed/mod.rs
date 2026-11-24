//! Feeds (`spec/feeds.md`): the feed index, connection files, reader state,
//! and reading a feed with [`pull()`], which does no I/O of its own: it reads
//! through a [`Source`] and a [`KeySource`].
//!
//! - `feed.json`, in [`index`];
//! - connection files, in [`connection`];
//! - what a reader keeps between polls, in [`state`];
//! - where a feed's files and key sets come from, in [`source`];
//! - what a publisher works out before writing, in [`publish`];
//! - one poll, in the spec's order, in [`mod@pull`].

pub mod connection;
pub mod index;
pub mod publish;
pub mod pull;
pub mod source;
pub mod state;

pub use connection::{parse_connection, Auth, Connection, Location};
pub use index::{check_bundle_paths, parse_feed, Feed, StreamEntry};
pub use publish::{collectable, next_published_at, render_feed, PublishState};
pub use pull::{
    pull, Delivered, IndexOutcome, KeySetOutcome, PullOptions, PullReport, StreamOutcome,
};
#[cfg(not(target_arch = "wasm32"))]
pub use source::DirSource;
pub use source::{Fetched, KeySetFiles, KeySource, NoKeySource, Source};
pub use state::{ReaderState, Signer, StreamState};

/// The most a feed index (`feed.json`, or `feed.json.age` and what it
/// decrypts to), its `feed.sig`, or a key set may hold.
pub const MAX_INDEX_BYTES: u64 = 1 << 20;
