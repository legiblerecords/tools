//! The `legible` binary: bundles keep their signature through unpack and pack.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use legible_records::bundle::{pack_with, PackOptions, SIGNATURE};
use legible_records::sign::SigningKey;

/// A directory under the system temp dir, removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Temp {
        let dir = std::env::temp_dir().join(format!("legible-cli-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Temp(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn legible(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_legible"))
        .args(args)
        .output()
        .unwrap()
}

fn arg(text: &str) -> &Path {
    Path::new(text)
}

/// A signed bundle, written to `dir/signed.zip`. The key is test-only.
fn write_signed(dir: &Temp) -> PathBuf {
    let key = SigningKey::from_seed("acme.example", "2026-11", [7; 32]).unwrap();
    let inputs = [legible_records::bundle::Input {
        name: "mfa.json".to_owned(),
        bytes:
            br#"{"$type":"tech.monorail.controls.control","version":1,"id":"mfa","title":"MFA"}"#
                .to_vec(),
    }];
    let options = PackOptions {
        published_at: Some("2026-11-24T10:00:00Z".to_owned()),
        feed: Some(("acme.example/controls".to_owned(), "main".to_owned())),
        signer: Some(&key),
        ..PackOptions::default()
    };
    let packed = pack_with(&inputs, &[], &options).unwrap();
    let path = dir.path("signed.zip");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&packed.zip).unwrap();
    path
}

fn zip_entry(zip: &Path, name: &str) -> Vec<u8> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip).unwrap()).unwrap();
    let mut bytes = Vec::new();
    archive
        .by_name(name)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[test]
fn unpack_keeps_signature_bytes() {
    let temp = Temp::new("unpack");
    let zip = write_signed(&temp);
    let out = temp.path("out");
    let result = legible(&[arg("bundle"), arg("unpack"), &zip, arg("-d"), &out]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        std::fs::read(out.join("manifest.json")).unwrap(),
        zip_entry(&zip, "manifest.json")
    );
    assert_eq!(
        std::fs::read(out.join(SIGNATURE)).unwrap(),
        zip_entry(&zip, SIGNATURE)
    );
}

#[test]
fn repacked_bundle_is_unverified() {
    let temp = Temp::new("repack");
    let zip = write_signed(&temp);
    let out = temp.path("out");
    let unpacked = legible(&[arg("bundle"), arg("unpack"), &zip, arg("-d"), &out]);
    assert!(unpacked.status.success(), "{unpacked:?}");
    let again = temp.path("again.zip");
    let packed = legible(&[arg("bundle"), arg("pack"), &out, arg("-o"), &again]);
    assert!(packed.status.success(), "{packed:?}");
    let warning = String::from_utf8_lossy(&packed.stderr);
    assert!(
        warning.contains("new, unsigned bundle"),
        "stderr was: {warning}"
    );
    let verified = legible(&[arg("bundle"), arg("verify"), &again]);
    assert!(verified.status.success(), "{verified:?}");
    let stdout = String::from_utf8_lossy(&verified.stdout);
    assert!(stdout.contains("unverified"), "stdout was: {stdout}");
    // The repacked bundle carries no signature.
    let mut archive = zip::ZipArchive::new(std::fs::File::open(&again).unwrap()).unwrap();
    assert!(archive.by_name(SIGNATURE).is_err());
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Runs `legible keys new` and returns the printed key-set entry.
fn keys_new(dir: &Temp, file: &str, publisher: &str, id: &str) -> serde_json::Value {
    let out = dir.path(file);
    let result = legible(&[
        arg("keys"),
        arg("new"),
        arg("--publisher"),
        arg(publisher),
        arg("--id"),
        arg(id),
        arg("-o"),
        &out,
    ]);
    assert!(result.status.success(), "{result:?}");
    serde_json::from_slice(&result.stdout).unwrap()
}

/// A packed (unsigned) bundle at `dir/plain.zip`.
fn write_plain(dir: &Temp) -> PathBuf {
    let record = dir.path("mfa.json");
    std::fs::write(
        &record,
        br#"{"$type":"tech.monorail.controls.control","version":1,"id":"mfa","title":"MFA"}"#,
    )
    .unwrap();
    let zip = dir.path("plain.zip");
    let packed = legible(&[arg("bundle"), arg("pack"), &record, arg("-o"), &zip]);
    assert!(packed.status.success(), "{packed:?}");
    zip
}

fn sign_bundle(dir: &Temp, plain: &Path, key: &str) -> PathBuf {
    let signed = dir.path("signed-by-cli.zip");
    let result = legible(&[
        arg("bundle"),
        arg("sign"),
        plain,
        arg("-k"),
        &dir.path(key),
        arg("-o"),
        &signed,
    ]);
    assert!(result.status.success(), "{result:?}");
    signed
}

fn pin_of(entry: &serde_json::Value, publisher: &str) -> String {
    format!(
        "{publisher}/{}={}",
        entry["id"].as_str().unwrap(),
        entry["public_key"].as_str().unwrap()
    )
}

#[cfg(unix)]
#[test]
fn keys_new_writes_0600_and_refuses_overwrite() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new("keys-new");
    let entry = keys_new(&temp, "key.json", "acme.example", "2026-11");
    let mode = std::fs::metadata(temp.path("key.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(entry["id"], "2026-11");
    assert_eq!(entry["alg"], "ed25519");
    assert!(entry["created_at"].as_str().unwrap().ends_with('Z'));
    // The secret is in the file, never on stdout.
    let secret: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.path("key.json")).unwrap()).unwrap();
    let seed = secret["seed"].as_str().unwrap();
    assert!(!entry.to_string().contains(seed));
    // An existing file is refused and left as it was.
    let before = std::fs::read(temp.path("key.json")).unwrap();
    let again = legible(&[
        arg("keys"),
        arg("new"),
        arg("--publisher"),
        arg("acme.example"),
        arg("--id"),
        arg("2026-12"),
        arg("-o"),
        &temp.path("key.json"),
    ]);
    assert_eq!(again.status.code(), Some(2), "{again:?}");
    assert!(again.stdout.is_empty());
    assert_eq!(std::fs::read(temp.path("key.json")).unwrap(), before);
}

#[test]
fn sign_then_verify_with_pin() {
    let temp = Temp::new("pin");
    let entry = keys_new(&temp, "key.json", "acme.example", "2026-11");
    let plain = write_plain(&temp);
    let signed = sign_bundle(&temp, &plain, "key.json");
    let pin = pin_of(&entry, "acme.example");
    let result = legible(&[
        arg("bundle"),
        arg("verify"),
        &signed,
        arg("--pin"),
        arg(&pin),
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(
        text(&result.stdout).contains("signature: verified (acme.example 2026-11)"),
        "{}",
        text(&result.stdout)
    );
    // Unpack takes the same flags.
    let out = temp.path("out");
    let unpacked = legible(&[
        arg("bundle"),
        arg("unpack"),
        &signed,
        arg("-d"),
        &out,
        arg("--pin"),
        arg(&pin),
    ]);
    assert!(unpacked.status.success(), "{unpacked:?}");
}

#[test]
fn verify_with_key_set_file() {
    let temp = Temp::new("key-set");
    let entry = keys_new(&temp, "key.json", "acme.example", "2026-11");
    let set = serde_json::json!({
        "$type": "org.legiblerecords.keys",
        "version": 1,
        "publisher": "acme.example",
        "updated_at": "2026-11-24T00:00:00Z",
        "keys": [entry],
    });
    std::fs::write(temp.path("keys.json"), serde_json::to_vec(&set).unwrap()).unwrap();
    let plain = write_plain(&temp);
    let signed = sign_bundle(&temp, &plain, "key.json");
    let result = legible(&[
        arg("bundle"),
        arg("verify"),
        &signed,
        arg("--key-set"),
        &temp.path("keys.json"),
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(
        text(&result.stdout).contains("signature: verified (acme.example 2026-11)"),
        "{}",
        text(&result.stdout)
    );
}

#[test]
fn verify_unsigned_prints_unverified() {
    let temp = Temp::new("unsigned");
    let plain = write_plain(&temp);
    let result = legible(&[arg("bundle"), arg("verify"), &plain]);
    assert!(result.status.success(), "{result:?}");
    let stdout = text(&result.stdout);
    assert!(
        stdout.lines().any(|l| l == "signature: unverified"),
        "{stdout}"
    );
}

#[test]
fn verify_signed_without_trust_says_so_and_passes() {
    let temp = Temp::new("no-trust");
    keys_new(&temp, "key.json", "acme.example", "2026-11");
    let signed = sign_bundle(&temp, &write_plain(&temp), "key.json");
    let result = legible(&[arg("bundle"), arg("verify"), &signed]);
    assert!(result.status.success(), "{result:?}");
    assert!(
        text(&result.stdout).contains(
            "signature: unverified (signed by acme.example 2026-11; no trusted keys given)"
        ),
        "{}",
        text(&result.stdout)
    );
}

#[test]
fn verify_wrong_pin_exits_1_with_unknown_key() {
    let temp = Temp::new("wrong-pin");
    keys_new(&temp, "key.json", "acme.example", "2026-11");
    let other = keys_new(&temp, "other.json", "acme.example", "2026-10");
    let signed = sign_bundle(&temp, &write_plain(&temp), "key.json");
    let pin = pin_of(&other, "acme.example");
    let result = legible(&[
        arg("bundle"),
        arg("verify"),
        &signed,
        arg("--pin"),
        arg(&pin),
    ]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        text(&result.stdout).contains("unknown_key"),
        "{}",
        text(&result.stdout)
    );
    // The right id with another key's bytes: the signature doesn't verify.
    let wrong = format!(
        "acme.example/2026-11={}",
        other["public_key"].as_str().unwrap()
    );
    let result = legible(&[
        arg("bundle"),
        arg("verify"),
        &signed,
        arg("--pin"),
        arg(&wrong),
    ]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(
        text(&result.stdout).contains("bad_signature"),
        "{}",
        text(&result.stdout)
    );
}

#[test]
fn malformed_pin_exits_2() {
    let temp = Temp::new("bad-pin");
    let plain = write_plain(&temp);
    for pin in [
        "nonsense",
        "acme.example/2026-11",
        "acme.example=AAAA",
        "acme.example/2026-11=AAAA",
        "Acme.Example/2026-11=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let result = legible(&[arg("bundle"), arg("verify"), &plain, arg("--pin"), arg(pin)]);
        assert_eq!(result.status.code(), Some(2), "{pin}: {result:?}");
        assert!(
            text(&result.stderr).contains("--pin"),
            "{pin}: {}",
            text(&result.stderr)
        );
    }
}

#[test]
fn keys_sign_output_endorses() {
    use legible_records::keys::KeySet;
    use legible_records::sign::{self, Context, SignatureFile};
    let temp = Temp::new("endorse");
    let old = keys_new(&temp, "old.json", "acme.example", "2026-11");
    let new = keys_new(&temp, "new.json", "acme.example", "2027-05");
    let set = serde_json::json!({
        "$type": "org.legiblerecords.keys",
        "version": 1,
        "publisher": "acme.example",
        "updated_at": "2027-05-01T00:00:00Z",
        "keys": [old, new],
    });
    let keys = temp.path("keys.json");
    std::fs::write(&keys, serde_json::to_vec(&set).unwrap()).unwrap();
    let sig = temp.path("keys.sig");
    let result = legible(&[
        arg("keys"),
        arg("sign"),
        &keys,
        arg("-k"),
        &temp.path("old.json"),
        arg("-o"),
        &sig,
    ]);
    assert!(result.status.success(), "{result:?}");
    let file = SignatureFile::parse(&std::fs::read(&sig).unwrap()).unwrap();
    assert_eq!(
        (file.publisher.as_str(), file.key.as_str()),
        ("acme.example", "2026-11")
    );
    let stored = std::fs::read(&keys).unwrap();
    let parsed = KeySet::parse(&stored).unwrap();
    let endorser = parsed.get("2026-11").unwrap();
    let public = sign::PublicKey {
        publisher: "acme.example".to_owned(),
        id: "2026-11".to_owned(),
        key: endorser.public_key,
    };
    assert_eq!(sign::verify(&public, Context::Keys, &stored, &file), Ok(()));
    // It covers the keys file's bytes: another file doesn't verify.
    let mut other = stored.clone();
    other.push(b'\n');
    assert!(sign::verify(&public, Context::Keys, &other, &file).is_err());
}

#[test]
fn bundle_sign_refuses_a_signed_bundle() {
    let temp = Temp::new("twice");
    keys_new(&temp, "key.json", "acme.example", "2026-11");
    let signed = sign_bundle(&temp, &write_plain(&temp), "key.json");
    let result = legible(&[
        arg("bundle"),
        arg("sign"),
        &signed,
        arg("-k"),
        &temp.path("key.json"),
        arg("-o"),
        &temp.path("again.zip"),
    ]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert!(!temp.path("again.zip").exists());
}

#[test]
fn verify_decrypts_with_identity() {
    use age::secrecy::ExposeSecret;
    let temp = Temp::new("age");
    let zip = write_signed(&temp);
    let identity = age::x25519::Identity::generate();
    let sealed = legible_records::age::encrypt(
        &std::fs::read(&zip).unwrap(),
        &[identity.to_public().to_string()],
    )
    .unwrap();
    let encrypted = temp.path("signed.zip.age");
    std::fs::write(&encrypted, sealed).unwrap();
    let identity_file = temp.path("identity.txt");
    std::fs::write(&identity_file, identity.to_string().expose_secret()).unwrap();

    // With the identity: verified like the plain bundle.
    let result = legible(&[
        arg("bundle"),
        arg("verify"),
        &encrypted,
        arg("-i"),
        &identity_file,
    ]);
    assert!(result.status.success(), "{result:?}");
    assert!(text(&result.stdout).contains("signature:"), "{result:?}");
    let out = temp.path("out");
    let unpacked = legible(&[
        arg("bundle"),
        arg("unpack"),
        &encrypted,
        arg("-i"),
        &identity_file,
        arg("-d"),
        &out,
    ]);
    assert!(unpacked.status.success(), "{unpacked:?}");
    assert!(out.join("manifest.json").exists());

    // Without one: exit 2, and it says what to give.
    let missing = legible(&[arg("bundle"), arg("verify"), &encrypted]);
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
    assert!(text(&missing.stderr).contains("-i"), "{missing:?}");

    // With another identity: exit 1, and the secret isn't printed.
    let other = age::x25519::Identity::generate();
    let other_file = temp.path("other.txt");
    std::fs::write(&other_file, other.to_string().expose_secret()).unwrap();
    let wrong = legible(&[
        arg("bundle"),
        arg("verify"),
        &encrypted,
        arg("-i"),
        &other_file,
    ]);
    assert_eq!(wrong.status.code(), Some(1), "{wrong:?}");
    assert!(!text(&wrong.stdout).contains(other.to_string().expose_secret()));
}

// ---- legible feed publish ----

mod feed_publish {
    use super::*;
    use age::secrecy::ExposeSecret;
    use legible_records::feed::{
        next_published_at, parse_feed, pull, Auth, Connection, IndexOutcome, Location, NoKeySource,
        PullOptions, ReaderState, StreamOutcome,
    };
    use legible_records::keys::Pin;
    use legible_records::time;

    const FEED: &str = "acme.example/track";

    /// A publisher's directory, a record to publish and a test-only key.
    struct Setup {
        temp: Temp,
        feed_dir: PathBuf,
        key: PathBuf,
        pin: Pin,
    }

    fn setup(name: &str) -> Setup {
        let temp = Temp::new(name);
        let entry = keys_new(&temp, "key.json", "acme.example", "2026-11");
        let public = legible_records::sign::from_b64url(entry["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let feed_dir = temp.path("feed");
        std::fs::write(
            temp.path("ack.json"),
            br#"{"$type":"tech.monorail.policy.acknowledgment","version":1,"id":"ack-1","title":"Acknowledged"}"#,
        )
        .unwrap();
        let key = temp.path("key.json");
        Setup {
            temp,
            feed_dir,
            key,
            pin: Pin {
                publisher: "acme.example".to_owned(),
                id: "2026-11".to_owned(),
                public_key: public,
            },
        }
    }

    fn os(args: &[&Path]) -> Output {
        legible(args)
    }

    /// `legible feed publish` with the usual arguments, then `extra`.
    fn publish(s: &Setup, stream: &str, extra: &[&Path]) -> Output {
        let record = s.temp.path("ack.json");
        let mut args: Vec<&Path> = vec![
            arg("feed"),
            arg("publish"),
            &s.feed_dir,
            arg("--feed"),
            arg(FEED),
            arg("--audience"),
            arg("Monorail, for Track"),
            arg("--stream"),
            arg(stream),
            arg("--title"),
            arg("Policy acknowledgments"),
        ];
        args.extend_from_slice(extra);
        if !extra.contains(&arg("--withdraw")) {
            args.push(&record);
        }
        os(&args)
    }

    fn connection(s: &Setup, signed: bool) -> Connection {
        Connection {
            feed: FEED.to_owned(),
            location: Location::Https {
                url: "https://feeds.acme.example/track/".to_owned(),
            },
            auth: Auth::None,
            pins: if signed { vec![s.pin.clone()] } else { vec![] },
            age_identity_env: None,
        }
    }

    fn poll(
        s: &Setup,
        signed: bool,
        state: &mut ReaderState,
        identity: Option<&str>,
    ) -> legible_records::feed::PullReport {
        let mut source = legible_records::feed::DirSource {
            root: s.feed_dir.clone(),
        };
        let options = PullOptions {
            identity,
            ..PullOptions::default()
        };
        pull(
            &mut source,
            &mut NoKeySource,
            &connection(s, signed),
            Some(state),
            &mut |_| Ok(()),
            &options,
        )
    }

    fn bundles(s: &Setup) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(s.feed_dir.join("bundles"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn publish_then_pull_round_trip() {
        let s = setup("t8-round");
        let result = publish(&s, "policy-acknowledgments", &[arg("-k"), &s.key]);
        assert!(result.status.success(), "{result:?}");

        // The bundle is named by the hash of the stored file.
        let index_bytes = std::fs::read(s.feed_dir.join("feed.json")).unwrap();
        let feed = parse_feed(&index_bytes).unwrap();
        assert_eq!(feed.id, FEED);
        assert_eq!(feed.publisher, "acme.example");
        assert_eq!(feed.audience, "Monorail, for Track");
        let entry = &feed.streams[0];
        assert_eq!(
            entry.record_types,
            ["tech.monorail.policy.acknowledgment"],
            "defaults to the inputs' $types"
        );
        let stored = std::fs::read(s.feed_dir.join(&entry.bundle)).unwrap();
        let sha = legible_records::bundle::sha256_hex(&stored);
        assert_eq!(entry.bundle, format!("bundles/{sha}.zip"));
        assert_eq!(entry.sha256, sha);
        assert!(!s.feed_dir.join("feed.json.age").exists());

        // feed.sig signs the stored index.
        let sig = std::fs::read(s.feed_dir.join("feed.sig")).unwrap();
        let file = legible_records::sign::SignatureFile::parse(&sig).unwrap();
        assert_eq!(
            (file.publisher.as_str(), file.key.as_str()),
            ("acme.example", "2026-11")
        );

        // A reader built in T5-T7 accepts it, and verifies the signature.
        let mut state = ReaderState::default();
        let mut delivered = Vec::new();
        let mut source = legible_records::feed::DirSource {
            root: s.feed_dir.clone(),
        };
        let report = pull(
            &mut source,
            &mut NoKeySource,
            &connection(&s, true),
            Some(&mut state),
            &mut |d| {
                delivered.push(d);
                Ok(())
            },
            &PullOptions::default(),
        );
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert_eq!(
            report.streams["policy-acknowledgments"],
            StreamOutcome::Accepted,
            "{report:?}"
        );
        assert!(
            matches!(
                delivered[0].signature,
                legible_records::bundle::SignatureStatus::Verified { .. }
            ),
            "{:?}",
            delivered[0].signature
        );
        assert_eq!(delivered[0].published_at, entry.published_at);
    }

    #[test]
    fn publish_twice_same_instant_is_later() {
        let t = time::parse("2026-11-24T10:00:00.123Z").unwrap();
        let first = time::format(t);
        assert!(
            time::parse(&next_published_at(t, Some(&first))).unwrap()
                > time::parse(&first).unwrap()
        );

        let s = setup("t8-twice");
        let mut state = ReaderState::default();
        for round in 0..2 {
            let result = publish(&s, "policy-acknowledgments", &[arg("-k"), &s.key]);
            assert!(result.status.success(), "{result:?}");
            let report = poll(&s, true, &mut state, None);
            assert_eq!(report.index, IndexOutcome::Accepted, "{round}: {report:?}");
            assert_eq!(
                report.streams["policy-acknowledgments"],
                StreamOutcome::Accepted,
                "{round}: {report:?}"
            );
        }
        // Back to back, the second is strictly later in both places.
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        assert!(feed.updated_at >= feed.streams[0].published_at);
    }

    #[test]
    fn published_at_follows_a_previous_one_in_the_future() {
        let s = setup("t8-future");
        assert!(publish(&s, "a", &[arg("-k"), &s.key]).status.success());
        // Pretend the last publish was a minute from now: the next must still be later.
        let path = s.feed_dir.join("feed.json");
        let mut feed = parse_feed(&std::fs::read(&path).unwrap()).unwrap();
        let ahead = time::format(time::now().plus_millis(60_000));
        feed.updated_at = ahead.clone();
        feed.streams[0].published_at = ahead.clone();
        let bytes = legible_records::feed::render_feed(&feed);
        std::fs::write(&path, &bytes).unwrap();
        let sig = legible_records::sign::sign(
            &legible_records::sign::SigningKey::from_json(&std::fs::read(&s.key).unwrap()).unwrap(),
            legible_records::sign::Context::Feed,
            &bytes,
        );
        std::fs::write(s.feed_dir.join("feed.sig"), sig.to_bytes()).unwrap();

        assert!(publish(&s, "a", &[arg("-k"), &s.key]).status.success());
        let feed = parse_feed(&std::fs::read(&path).unwrap()).unwrap();
        assert!(time::parse(&feed.updated_at).unwrap() > time::parse(&ahead).unwrap());
        assert!(time::parse(&feed.streams[0].published_at).unwrap() > time::parse(&ahead).unwrap());
    }

    #[test]
    fn withdraw_removes_stream() {
        let s = setup("t8-withdraw");
        assert!(publish(&s, "one", &[arg("-k"), &s.key]).status.success());
        assert!(publish(&s, "two", &[arg("-k"), &s.key]).status.success());
        let mut state = ReaderState::default();
        let report = poll(&s, true, &mut state, None);
        assert_eq!(report.stream_ids, ["one", "two"], "{report:?}");

        let withdrawn = publish(&s, "one", &[arg("--withdraw"), arg("-k"), &s.key]);
        assert!(withdrawn.status.success(), "{withdrawn:?}");
        let report = poll(&s, true, &mut state, None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert_eq!(report.stream_ids, ["two"]);
        assert_eq!(report.streams["one"], StreamOutcome::Withdrawn);

        // A stream that isn't there can't be withdrawn.
        let again = publish(&s, "one", &[arg("--withdraw"), arg("-k"), &s.key]);
        assert_eq!(again.status.code(), Some(2), "{again:?}");
    }

    #[test]
    fn gc_respects_grace() {
        let s = setup("t8-gc");
        let state_file = s.temp.path("publish-state.json");
        let with_state = [arg("-k"), &s.key, arg("--state"), &state_file];
        assert!(publish(&s, "main", &with_state).status.success());
        let first = bundles(&s);
        assert_eq!(first.len(), 1);

        // Replacing the bundle makes the old one unreferenced, not deleted.
        assert!(publish(&s, "main", &with_state).status.success());
        let both = bundles(&s);
        assert_eq!(both.len(), 2, "{both:?}");
        let state = std::fs::read_to_string(&state_file).unwrap();
        assert!(state.contains(&first[0]), "{state}");

        // Within the grace it stays.
        assert!(publish(&s, "main", &with_state).status.success());
        assert!(bundles(&s).contains(&first[0]));

        // Past the grace, it goes, and the current ones stay.
        let mut value: serde_json::Value = serde_json::from_str(&state).unwrap();
        for (_, since) in value["unreferenced_since"].as_object_mut().unwrap() {
            *since = serde_json::json!("2020-01-01T00:00:00.000Z");
        }
        std::fs::write(&state_file, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(publish(&s, "main", &with_state).status.success());
        let after = bundles(&s);
        assert!(!after.contains(&first[0]), "{after:?}");
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        assert!(after.contains(&feed.streams[0].bundle["bundles/".len()..].to_owned()));
        let report = poll(&s, true, &mut ReaderState::default(), None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");

        // Without --state nothing is ever deleted.
        let before = bundles(&s).len();
        assert!(publish(&s, "main", &[arg("-k"), &s.key]).status.success());
        assert_eq!(bundles(&s).len(), before + 1);
    }

    #[test]
    fn grace_under_one_hour_refused() {
        let s = setup("t8-grace");
        let state_file = s.temp.path("publish-state.json");
        let result = publish(
            &s,
            "main",
            &[
                arg("-k"),
                &s.key,
                arg("--state"),
                &state_file,
                arg("--grace"),
                arg("0.5"),
            ],
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(text(&result.stderr).contains("grace"), "{result:?}");
        assert!(!s.feed_dir.join("feed.json").exists());
        assert!(!state_file.exists());
        // An hour exactly is fine.
        let ok = publish(&s, "main", &[arg("-k"), &s.key, arg("--grace"), arg("1")]);
        assert!(ok.status.success(), "{ok:?}");
    }

    #[test]
    fn encrypted_publish_pulls_with_identity() {
        let s = setup("t8-age");
        let identity = age::x25519::Identity::generate();
        let identity_file = s.temp.path("identity.txt");
        std::fs::write(&identity_file, identity.to_string().expose_secret()).unwrap();
        let recipient = identity.to_public().to_string();
        let encrypted = [arg("-k"), &s.key, arg("-r"), arg(&recipient)];
        let result = publish(&s, "main", &encrypted);
        assert!(result.status.success(), "{result:?}");
        assert!(s.feed_dir.join("feed.json.age").exists());
        assert!(!s.feed_dir.join("feed.json").exists());
        let names = bundles(&s);
        assert!(names[0].ends_with(".zip.age"), "{names:?}");
        let stored = std::fs::read(s.feed_dir.join("bundles").join(&names[0])).unwrap();
        assert!(legible_records::age::is_encrypted(&stored));
        assert_eq!(
            names[0],
            format!("{}.zip.age", legible_records::bundle::sha256_hex(&stored))
        );
        // feed.sig signs the ciphertext.
        let sealed = std::fs::read(s.feed_dir.join("feed.json.age")).unwrap();
        let sig = std::fs::read(s.feed_dir.join("feed.sig")).unwrap();
        let trust = legible_records::keys::Trust {
            pins: vec![s.pin.clone()],
            ..Default::default()
        };
        legible_records::bundle::check_signed(
            Some(&sig),
            legible_records::sign::Context::Feed,
            &sealed,
            &trust,
            Some("acme.example"),
        )
        .unwrap();

        let secret = identity.to_string();
        let mut state = ReaderState::default();
        let report = poll(&s, true, &mut state, Some(secret.expose_secret()));
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert_eq!(
            report.streams["main"],
            StreamOutcome::Accepted,
            "{report:?}"
        );
        // Without the identity a reader can't read it.
        let blind = poll(&s, true, &mut ReaderState::default(), None);
        assert!(matches!(blind.index, IndexOutcome::Failed(_)), "{blind:?}");

        // Adding to an encrypted feed needs the identity to read the old index.
        let without = publish(&s, "other", &encrypted);
        assert_eq!(without.status.code(), Some(2), "{without:?}");
        assert!(text(&without.stderr).contains("-i"), "{without:?}");
        assert!(!s.feed_dir.join("feed.json").exists());
        let mut with = encrypted.to_vec();
        with.extend([arg("-i"), identity_file.as_path()]);
        let ok = publish(&s, "other", &with);
        assert!(ok.status.success(), "{ok:?}");
        let report = poll(&s, true, &mut state, Some(secret.expose_secret()));
        assert_eq!(report.stream_ids, ["main", "other"], "{report:?}");
        assert_eq!(
            report.streams["other"],
            StreamOutcome::Accepted,
            "{report:?}"
        );

        // Never both, and never the other mode.
        let plain = publish(&s, "main", &[arg("-k"), &s.key, arg("-i"), &identity_file]);
        assert_eq!(plain.status.code(), Some(2), "{plain:?}");
        assert!(text(&plain.stderr).contains("encrypted"), "{plain:?}");
        assert!(!s.feed_dir.join("feed.json").exists());
    }

    #[test]
    fn plain_feed_refuses_recipients() {
        let s = setup("t8-mode");
        assert!(publish(&s, "main", &[arg("-k"), &s.key]).status.success());
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let result = publish(&s, "main", &[arg("-k"), &s.key, arg("-r"), arg(&recipient)]);
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(text(&result.stderr).contains("plain"), "{result:?}");
        assert!(!s.feed_dir.join("feed.json.age").exists());
    }

    #[test]
    fn unsigned_publish_needs_a_publisher_and_pulls_unverified() {
        let s = setup("t8-unsigned");
        let missing = publish(&s, "main", &[]);
        assert_eq!(missing.status.code(), Some(2), "{missing:?}");
        assert!(text(&missing.stderr).contains("--publisher"), "{missing:?}");

        let wrong = publish(&s, "main", &[arg("--publisher"), arg("other.example")]);
        assert_eq!(wrong.status.code(), Some(2), "{wrong:?}");
        assert!(!s.feed_dir.join("feed.json").exists());

        let ok = publish(&s, "main", &[arg("--publisher"), arg("acme.example")]);
        assert!(ok.status.success(), "{ok:?}");
        assert!(!s.feed_dir.join("feed.sig").exists());
        let report = poll(&s, false, &mut ReaderState::default(), None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert_eq!(
            report.streams["main"],
            StreamOutcome::Accepted,
            "{report:?}"
        );

        // A feed that has a signature isn't republished without one.
        assert!(publish(&s, "main", &[arg("-k"), &s.key]).status.success());
        let strip = publish(&s, "main", &[arg("--publisher"), arg("acme.example")]);
        assert_eq!(strip.status.code(), Some(2), "{strip:?}");
        assert!(text(&strip.stderr).contains("feed.sig"), "{strip:?}");
    }

    #[test]
    fn publish_refuses_a_feed_it_cannot_read_or_that_is_not_its_own() {
        let s = setup("t8-existing");
        std::fs::create_dir_all(&s.feed_dir).unwrap();
        std::fs::write(s.feed_dir.join("feed.json"), b"not json").unwrap();
        let broken = publish(&s, "main", &[arg("-k"), &s.key]);
        assert_eq!(broken.status.code(), Some(2), "{broken:?}");
        assert_eq!(
            std::fs::read(s.feed_dir.join("feed.json")).unwrap(),
            b"not json"
        );

        std::fs::remove_file(s.feed_dir.join("feed.json")).unwrap();
        assert!(publish(&s, "main", &[arg("-k"), &s.key]).status.success());
        let record = s.temp.path("ack.json");
        let other = legible(&[
            arg("feed"),
            arg("publish"),
            &s.feed_dir,
            arg("--feed"),
            arg("acme.example/other"),
            arg("--audience"),
            arg("x"),
            arg("--stream"),
            arg("main"),
            arg("--title"),
            arg("t"),
            arg("-k"),
            &s.key,
            &record,
        ]);
        assert_eq!(other.status.code(), Some(2), "{other:?}");
        assert!(
            text(&other.stderr).contains("acme.example/track"),
            "{other:?}"
        );

        // Both forms present: refused.
        std::fs::write(s.feed_dir.join("feed.json.age"), b"x").unwrap();
        let both = publish(&s, "main", &[arg("-k"), &s.key]);
        assert_eq!(both.status.code(), Some(2), "{both:?}");
    }

    #[test]
    fn record_type_flag_overrides_the_default() {
        let s = setup("t8-types");
        let result = publish(
            &s,
            "main",
            &[
                arg("-k"),
                &s.key,
                arg("--record-type"),
                arg("tech.monorail.a"),
                arg("--record-type"),
                arg("tech.monorail.b"),
            ],
        );
        assert!(result.status.success(), "{result:?}");
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        assert_eq!(
            feed.streams[0].record_types,
            ["tech.monorail.a", "tech.monorail.b"]
        );
    }
}

// ---- legible feed check | pull ----

mod feed_read {
    use super::*;
    use legible_records::feed::ReaderState;
    use std::sync::Arc;

    const FEED: &str = "acme.example/track";
    const TOKEN: &str = "s3cret-test-token";

    /// A feed served over HTTP on 127.0.0.1 from a directory, behind a bearer token, with
    /// the publisher's key set at `/.well-known/legible-records/` from another.
    struct Server {
        server: Arc<tiny_http::Server>,
        port: u16,
        /// Requests seen for `feed.json`, with their `If-None-Match`.
        index_requests: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.server.unblock();
        }
    }

    fn serve(feed_dir: PathBuf, keys_dir: PathBuf, etags: bool) -> Server {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = server.server_addr().to_ip().unwrap().port();
        let index_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (thread_server, log) = (Arc::clone(&server), Arc::clone(&index_requests));
        std::thread::spawn(move || {
            for request in thread_server.incoming_requests() {
                let url = request.url().to_owned();
                let headers: Vec<(String, String)> = request
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_lowercase(),
                            h.value.to_string(),
                        )
                    })
                    .collect();
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(k, _)| k == name)
                        .map(|(_, v)| v.clone())
                };
                let (file, authorized) =
                    if let Some(name) = url.strip_prefix("/.well-known/legible-records/") {
                        (keys_dir.join(name), true)
                    } else if let Some(path) = url.strip_prefix("/track/") {
                        (
                            feed_dir.join(path),
                            header("authorization").as_deref() == Some(&format!("Bearer {TOKEN}")),
                        )
                    } else {
                        (PathBuf::from("/nonexistent/x"), true)
                    };
                if url == "/track/feed.json" {
                    log.lock().unwrap().push(header("if-none-match"));
                }
                let respond = |status: u16, body: Vec<u8>, etag: Option<String>| {
                    let mut response = tiny_http::Response::from_data(body)
                        .with_status_code(tiny_http::StatusCode(status));
                    if let Some(etag) = etag {
                        response.add_header(
                            tiny_http::Header::from_bytes(&b"ETag"[..], etag.as_bytes()).unwrap(),
                        );
                    }
                    let _ = request.respond(response);
                };
                if !authorized {
                    respond(401, Vec::new(), None);
                } else if let Ok(bytes) = std::fs::read(&file) {
                    let etag = (etags && url == "/track/feed.json")
                        .then(|| format!("\"{}\"", legible_records::bundle::sha256_hex(&bytes)));
                    if etag.is_some() && header("if-none-match") == etag {
                        respond(304, Vec::new(), etag);
                    } else {
                        respond(200, bytes, etag);
                    }
                } else {
                    respond(404, Vec::new(), None);
                }
            }
        });
        Server {
            server,
            port,
            index_requests,
        }
    }

    struct Setup {
        temp: Temp,
        feed_dir: PathBuf,
        keys_dir: PathBuf,
        entry: serde_json::Value,
        key: PathBuf,
    }

    impl Setup {
        fn state_file(&self) -> PathBuf {
            self.temp.path("state/acme.example__track.json")
        }
        fn state(&self) -> ReaderState {
            ReaderState::parse(&std::fs::read(self.state_file()).unwrap()).unwrap()
        }
    }

    /// A signed feed with the streams given, published by the CLI, and its keys.
    fn setup(name: &str, streams: &[&str]) -> Setup {
        let temp = Temp::new(name);
        let entry = keys_new(&temp, "key.json", "acme.example", "2026-11");
        let feed_dir = temp.path("feed");
        let keys_dir = temp.path("wellknown");
        std::fs::create_dir_all(&keys_dir).unwrap();
        let set = serde_json::json!({
            "$type": "org.legiblerecords.keys",
            "version": 1,
            "publisher": "acme.example",
            "updated_at": "2026-11-24T00:00:00Z",
            "keys": [entry],
        });
        std::fs::write(
            keys_dir.join("keys.json"),
            serde_json::to_vec(&set).unwrap(),
        )
        .unwrap();
        std::fs::write(
            temp.path("ack.json"),
            br#"{"$type":"tech.monorail.policy.acknowledgment","version":1,"id":"ack-1","title":"Acknowledged"}"#,
        )
        .unwrap();
        let key = temp.path("key.json");
        let s = Setup {
            temp,
            feed_dir,
            keys_dir,
            entry,
            key,
        };
        for stream in streams {
            let record = s.temp.path("ack.json");
            let published = legible(&[
                arg("feed"),
                arg("publish"),
                &s.feed_dir,
                arg("--feed"),
                arg(FEED),
                arg("--audience"),
                arg("Monorail, for Track"),
                arg("--stream"),
                arg(stream),
                arg("--title"),
                arg("Acknowledgments"),
                arg("-k"),
                &s.key,
                &record,
            ]);
            assert!(published.status.success(), "{published:?}");
        }
        s
    }

    fn public_key(s: &Setup) -> String {
        s.entry["public_key"].as_str().unwrap().to_owned()
    }

    /// A connection file for `server`; `pinned` puts the publisher's key in it.
    fn write_connection(s: &Setup, port: u16, pinned: bool) -> PathBuf {
        write_connection_pinning(s, port, pinned.then(|| public_key(s)))
    }

    fn write_connection_pinning(s: &Setup, port: u16, pin: Option<String>) -> PathBuf {
        let keys = if let Some(public_key) = pin {
            serde_json::json!([{
                "publisher": "acme.example", "id": "2026-11", "alg": "ed25519",
                "public_key": public_key,
            }])
        } else {
            serde_json::json!([])
        };
        let connection = serde_json::json!({
            "$type": "org.legiblerecords.feed-connection",
            "version": 1,
            "feed": FEED,
            "location": {"kind": "https", "url": format!("http://127.0.0.1:{port}/track/")},
            "auth": {"method": "bearer", "token_env": "TRACK_FEED_TOKEN"},
            "keys": keys,
        });
        let path = s.temp.path("connection.json");
        std::fs::write(&path, serde_json::to_vec(&connection).unwrap()).unwrap();
        path
    }

    /// `legible feed <sub> ...` with the token in its environment and the key
    /// sets read from `origin`.
    fn run(sub: &str, args: &[&Path], origin: Option<u16>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_legible"));
        command.arg("feed").arg(sub).args(args);
        command.env("TRACK_FEED_TOKEN", TOKEN);
        if let Some(port) = origin {
            command
                .arg("--key-origin")
                .arg(format!("http://127.0.0.1:{port}"));
        }
        command.output().unwrap()
    }

    fn pull_args<'a>(
        s: &'a Setup,
        connection: &'a Path,
        state: &'a Path,
        out: &'a Path,
    ) -> Vec<&'a Path> {
        let _ = s;
        vec![connection, arg("--state"), state, arg("--out"), out]
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn out_files(out: &Path) -> Vec<String> {
        let mut found = Vec::new();
        if let Ok(streams) = std::fs::read_dir(out) {
            for stream in streams {
                let stream = stream.unwrap();
                for file in std::fs::read_dir(stream.path()).unwrap() {
                    found.push(format!(
                        "{}/{}",
                        stream.file_name().to_string_lossy(),
                        file.unwrap().file_name().to_string_lossy()
                    ));
                }
            }
        }
        found.sort();
        found
    }

    #[test]
    fn check_prints_each_stream() {
        let s = setup("t9-check", &["alpha", "beta"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let result = run("check", &[&connection], Some(server.port));
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        let out = text(&result.stdout);
        assert!(
            out.contains("alpha: accepted (verified acme.example 2026-11)"),
            "{out}"
        );
        assert!(
            out.contains("beta: accepted (verified acme.example 2026-11)"),
            "{out}"
        );
        // Stateless, and it delivers nothing: only the files it was given exist.
        assert!(!s.state_file().exists());
        assert!(!s.temp.path("state").exists());
    }

    #[test]
    fn check_reports_a_refusal_and_exits_1() {
        let s = setup("t9-check-refused", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        // Another key under the same id: the signature doesn't verify.
        let other = keys_new(&s.temp, "other.json", "acme.example", "2026-11");
        let wrong = other["public_key"].as_str().unwrap().to_owned();
        let connection = write_connection_pinning(&s, server.port, Some(wrong));
        let result = run("check", &[&connection], Some(server.port));
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        // The index is signed by the key that isn't the pinned one.
        assert!(
            text(&result.stdout).contains("index: bad_signature"),
            "{result:?}"
        );
    }

    #[test]
    fn a_refused_stream_is_named_and_exits_1() {
        let s = setup("t9-stream-refused", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        for entry in std::fs::read_dir(s.feed_dir.join("bundles")).unwrap() {
            std::fs::write(entry.unwrap().path(), b"not the bundle").unwrap();
        }
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let result = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(server.port),
        );
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(
            text(&result.stdout).contains("alpha: download_mismatch"),
            "{result:?}"
        );
        assert!(out_files(&out).is_empty());
        // Tried again next poll: the stream isn't recorded as held.
        assert!(s.state().streams.is_empty());
    }

    #[test]
    fn pull_writes_bundles_and_state() {
        let s = setup("t9-pull", &["alpha", "beta"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let result = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(server.port),
        );
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        let said = text(&result.stdout);
        assert!(
            said.contains("alpha: accepted (verified acme.example 2026-11)"),
            "{said}"
        );

        // One zip per stream, named by published_at with ':' as '-'.
        let held = s.state();
        let files = out_files(&out);
        assert_eq!(files.len(), 2, "{files:?}");
        for id in ["alpha", "beta"] {
            let published = &held.streams[id].published_at;
            let name = format!("{id}/{}.zip", published.replace(':', "-"));
            assert!(files.contains(&name), "{name} in {files:?}");
            // Decrypted and whole: the CLI verifies it, signature included.
            let verified = legible(&[
                arg("bundle"),
                arg("verify"),
                &out.join(&name),
                arg("--pin"),
                arg(&format!("acme.example/2026-11={}", public_key(&s))),
            ]);
            assert!(verified.status.success(), "{verified:?}");
            assert!(
                text(&verified.stdout).contains("signature: verified"),
                "{verified:?}"
            );
        }
        assert!(held.feed_updated_at.is_some());
    }

    #[test]
    fn second_pull_is_unchanged() {
        let s = setup("t9-second", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);
        assert!(run("pull", &args, Some(server.port)).status.success());
        let (state_before, files_before) =
            (std::fs::read(s.state_file()).unwrap(), out_files(&out));

        let again = run("pull", &args, Some(server.port));
        assert_eq!(again.status.code(), Some(0), "{again:?}");
        assert!(
            text(&again.stdout).contains("alpha: unchanged"),
            "{again:?}"
        );
        assert_eq!(std::fs::read(s.state_file()).unwrap(), state_before);
        assert_eq!(out_files(&out), files_before);
    }

    #[test]
    fn etag_is_kept_in_state_and_sent() {
        let s = setup("t9-etag", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), true);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);
        assert!(run("pull", &args, Some(server.port)).status.success());
        let kept: serde_json::Value =
            serde_json::from_slice(&std::fs::read(s.state_file()).unwrap()).unwrap();
        let etag = kept["etag"]
            .as_str()
            .expect("the ETag is in the state file");
        assert!(etag.starts_with('"'), "{etag}");
        // Still a state file a reader of the state alone can read.
        assert!(s.state().streams.contains_key("alpha"));

        let before = std::fs::read(s.state_file()).unwrap();
        let again = run("pull", &args, Some(server.port));
        assert_eq!(again.status.code(), Some(0), "{again:?}");
        assert!(text(&again.stdout).contains("not modified"), "{again:?}");
        let sent = server.index_requests.lock().unwrap().clone();
        assert_eq!(sent.last().unwrap().as_deref(), Some(etag), "{sent:?}");
        assert_eq!(std::fs::read(s.state_file()).unwrap(), before);
    }

    #[test]
    fn pending_key_exit_1_prints_approve_arg() {
        let s = setup("t9-pending", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, false);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let result = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(server.port),
        );
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let line = format!(
            "pending key: --approve acme.example/2026-11={}",
            public_key(&s)
        );
        assert!(text(&result.stdout).contains(&line), "{result:?}");
        assert!(out_files(&out).is_empty());
    }

    #[test]
    fn approve_then_pull_accepts() {
        let s = setup("t9-approve", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, false);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let first = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(server.port),
        );
        assert_eq!(first.status.code(), Some(1), "{first:?}");
        let said = text(&first.stdout);
        let approve = said
            .lines()
            .find_map(|l| l.strip_prefix("pending key: --approve "))
            .expect("an --approve argument is printed")
            .to_owned();

        let mut args = pull_args(&s, &connection, &state, &out);
        args.extend([arg("--approve"), arg(&approve)]);
        let second = run("pull", &args, Some(server.port));
        assert_eq!(second.status.code(), Some(0), "{second:?}");
        assert!(
            text(&second.stdout).contains("alpha: accepted (verified acme.example 2026-11)"),
            "{second:?}"
        );
        let held = s.state();
        assert_eq!(held.approved.len(), 1);
        assert_eq!(out_files(&out).len(), 1);

        // Kept: the next pull needs no --approve.
        let third = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(server.port),
        );
        assert_eq!(third.status.code(), Some(0), "{third:?}");
        assert!(
            text(&third.stdout).contains("alpha: unchanged"),
            "{third:?}"
        );
    }

    #[test]
    fn malformed_approve_is_exit_2() {
        let s = setup("t9-badapprove", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let mut args = pull_args(&s, &connection, &state, &out);
        args.extend([arg("--approve"), arg("acme.example/2026-11")]);
        let result = run("pull", &args, Some(server.port));
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(!s.state_file().exists());
    }

    #[test]
    fn unreachable_source_exit_2() {
        let s = setup("t9-down", &["alpha"]);
        // Nothing listens on the port a closed server held.
        let port = {
            let gone = tiny_http::Server::http("127.0.0.1:0").unwrap();
            gone.server_addr().to_ip().unwrap().port()
        };
        let connection = write_connection(&s, port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let result = run(
            "pull",
            &pull_args(&s, &connection, &state, &out),
            Some(port),
        );
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(!s.state_file().exists(), "a failed index leaves no state");
        let checked = run("check", &[&connection], Some(port));
        assert_eq!(checked.status.code(), Some(2), "{checked:?}");
    }

    #[test]
    fn missing_connection_file_is_exit_2() {
        let temp = Temp::new("t9-noconn");
        let missing = temp.path("nope.json");
        let result = run("check", &[&missing], None);
        assert_eq!(result.status.code(), Some(2), "{result:?}");
    }

    #[test]
    fn refused_index_leaves_state_untouched() {
        let s = setup("t9-refused", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);
        assert!(run("pull", &args, Some(server.port)).status.success());
        let before = std::fs::read(s.state_file()).unwrap();

        std::fs::write(s.feed_dir.join("feed.sig"), b"not a signature").unwrap();
        let result = run("pull", &args, Some(server.port));
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(
            text(&result.stdout).contains("index: bad_signature_file"),
            "{result:?}"
        );
        assert_eq!(std::fs::read(s.state_file()).unwrap(), before);
    }

    #[test]
    fn state_dir_write_is_atomic() {
        let s = setup("t9-atomic", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);
        for _ in 0..2 {
            assert!(run("pull", &args, Some(server.port)).status.success());
        }
        let names: Vec<String> = std::fs::read_dir(&state)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names,
            ["acme.example__track.json"],
            "no temp file is left behind"
        );
        for stream in std::fs::read_dir(&out).unwrap() {
            for file in std::fs::read_dir(stream.unwrap().path()).unwrap() {
                let name = file.unwrap().file_name().into_string().unwrap();
                assert!(name.ends_with(".zip") && !name.contains(".tmp"), "{name}");
            }
        }
    }
}
