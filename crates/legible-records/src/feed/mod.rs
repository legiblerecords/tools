//! Feeds (`spec/feeds.md`): the feed index, connection files, reader state,
//! and reading a feed with [`pull()`], which does no I/O of its own: it reads
//! through a [`Source`] and a [`KeySource`].
//!
//! - `feed.json`, in [`index`];
//! - connection files, in [`connection`];
//! - what a reader keeps between polls, in [`state`];
//! - where a feed's files and key sets come from, in [`source`];
//! - one poll, in the spec's order, in [`mod@pull`].

pub mod connection;
pub mod index;
pub mod pull;
pub mod source;
pub mod state;

pub use connection::{parse_connection, Auth, Connection, Location};
pub use index::{check_bundle_paths, parse_feed, Feed, StreamEntry};
pub use pull::{pull, Delivered, IndexOutcome, PullOptions, PullReport, StreamOutcome};
#[cfg(not(target_arch = "wasm32"))]
pub use source::DirSource;
pub use source::{Fetched, KeySetFiles, KeySource, NoKeySource, Source};
pub use state::{ReaderState, StreamState};
