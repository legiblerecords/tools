//! The outcome codes of the spec (`spec/feeds.md` § Outcomes). Readers return
//! these exact strings, and the test vectors expect them.

/// An outcome code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    BadSignatureFile,
    UnknownAlg,
    UnknownKey,
    BadSignature,
    RevokedKey,
    PublisherMismatch,
    UnsignedFromPinnedPublisher,
    StaleFeed,
    PlainAndEncrypted,
    DownloadMismatch,
    BadBundle,
    MissingPublishedAt,
    WrongFeed,
    WrongStream,
    Replay,
    BadEndorsement,
    NeedsApproval,
    KeySetRollback,
    BadKeySet,
    BadFeed,
}

impl Code {
    /// Every code, in the order of the spec's table.
    pub const ALL: &'static [Code] = &[
        Code::BadSignatureFile,
        Code::UnknownAlg,
        Code::UnknownKey,
        Code::BadSignature,
        Code::RevokedKey,
        Code::PublisherMismatch,
        Code::UnsignedFromPinnedPublisher,
        Code::StaleFeed,
        Code::PlainAndEncrypted,
        Code::DownloadMismatch,
        Code::BadBundle,
        Code::MissingPublishedAt,
        Code::WrongFeed,
        Code::WrongStream,
        Code::Replay,
        Code::BadEndorsement,
        Code::NeedsApproval,
        Code::KeySetRollback,
        Code::BadKeySet,
        Code::BadFeed,
    ];

    /// The code as the spec and the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::BadSignatureFile => "bad_signature_file",
            Code::UnknownAlg => "unknown_alg",
            Code::UnknownKey => "unknown_key",
            Code::BadSignature => "bad_signature",
            Code::RevokedKey => "revoked_key",
            Code::PublisherMismatch => "publisher_mismatch",
            Code::UnsignedFromPinnedPublisher => "unsigned_from_pinned_publisher",
            Code::StaleFeed => "stale_feed",
            Code::PlainAndEncrypted => "plain_and_encrypted",
            Code::DownloadMismatch => "download_mismatch",
            Code::BadBundle => "bad_bundle",
            Code::MissingPublishedAt => "missing_published_at",
            Code::WrongFeed => "wrong_feed",
            Code::WrongStream => "wrong_stream",
            Code::Replay => "replay",
            Code::BadEndorsement => "bad_endorsement",
            Code::NeedsApproval => "needs_approval",
            Code::KeySetRollback => "key_set_rollback",
            Code::BadKeySet => "bad_key_set",
            Code::BadFeed => "bad_feed",
        }
    }

    /// The code for a string, or `None` if it isn't one of them.
    pub fn parse(s: &str) -> Option<Code> {
        Code::ALL.iter().copied().find(|code| code.as_str() == s)
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
