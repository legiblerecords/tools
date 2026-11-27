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
fn validate_names_a_broken_rule_by_its_message() {
    let dir = Temp::new("validate-rule");
    let schema = dir.path("window.json");
    std::fs::write(
        &schema,
        serde_json::json!({
            "$id": "https://example.org/schemas/org.example.window/v1.json",
            "type": "object",
            "properties": {
                "$type": {"const": "org.example.window"},
                "version": {"const": 1},
                "opened_on": {"$ref": format!("{}#/$defs/date", legible_records::COMMON_V1_ID)},
                "closed_on": {"$ref": format!("{}#/$defs/date", legible_records::COMMON_V1_ID)}
            },
            "required": ["$type", "version"],
            "allOf": [{"x-rule": "before(opened_on, closed_on)"}]
        })
        .to_string(),
    )
    .unwrap();
    let good = dir.path("good.json");
    std::fs::write(
        &good,
        r#"{"$type": "org.example.window", "version": 1, "opened_on": "2026-01-01", "closed_on": "2026-01-02"}"#,
    )
    .unwrap();
    let bad = dir.path("bad.json");
    std::fs::write(
        &bad,
        r#"{"$type": "org.example.window", "version": 1, "opened_on": "2026-02-01", "closed_on": "2026-01-31"}"#,
    )
    .unwrap();

    let result = legible(&[arg("validate"), arg("--schema"), &schema, &good]);
    assert!(result.status.success(), "{result:?}");

    let result = legible(&[arg("validate"), arg("--schema"), &schema, &good, &bad]);
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        text(&result.stdout),
        format!(
            "{}: /: opened_on 2026-02-01 isn't before closed_on 2026-01-31\n",
            bad.display()
        )
    );
}

#[test]
fn bundle_and_identity_cannot_both_be_stdin() {
    for sub in ["verify", "unpack"] {
        let mut args = vec![arg("bundle"), arg(sub), arg("-"), arg("-i"), arg("-")];
        if sub == "unpack" {
            args.extend([arg("-d"), arg("/nonexistent/out")]);
        }
        let result = legible(&args);
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("-i -"),
            "{result:?}"
        );
    }
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
                alg: "ed25519".to_owned(),
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
    fn publish_builds_only_on_an_index_its_key_signed() {
        let s = setup("t-i3-verify");
        let state_file = s.temp.path("publish-state.json");
        let signed = [arg("-k"), &s.key, arg("--state"), &state_file];
        assert!(publish(&s, "one", &signed).status.success());
        assert!(publish(&s, "two", &signed).status.success());

        // Whoever can write the directory changes the index: refused, and
        // nothing is written.
        let index = s.feed_dir.join("feed.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        value["audience"] = serde_json::json!("Someone else");
        let tampered = serde_json::to_vec_pretty(&value).unwrap();
        std::fs::write(&index, &tampered).unwrap();
        let before = bundles(&s);
        let refused = publish(&s, "one", &signed);
        assert_eq!(refused.status.code(), Some(2), "{refused:?}");
        assert!(text(&refused.stderr).contains("feed.sig"), "{refused:?}");
        assert_eq!(std::fs::read(&index).unwrap(), tampered);
        assert_eq!(bundles(&s), before);

        // No feed.sig at all: refused too.
        let sig = std::fs::read(s.feed_dir.join("feed.sig")).unwrap();
        std::fs::remove_file(s.feed_dir.join("feed.sig")).unwrap();
        assert_eq!(publish(&s, "one", &signed).status.code(), Some(2));
        std::fs::write(s.feed_dir.join("feed.sig"), sig).unwrap();

        // --rebuild starts the index from this stream only, and says so.
        let mut rebuild = signed.to_vec();
        rebuild.push(arg("--rebuild"));
        let rebuilt = publish(&s, "one", &rebuild);
        assert!(rebuilt.status.success(), "{rebuilt:?}");
        assert!(text(&rebuilt.stderr).contains("--rebuild"), "{rebuilt:?}");
        let feed = parse_feed(&std::fs::read(&index).unwrap()).unwrap();
        assert_eq!(feed.streams.len(), 1);
        assert_eq!(feed.streams[0].id, "one");
        assert_eq!(feed.audience, "Monorail, for Track");
        let report = poll(&s, true, &mut ReaderState::default(), None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert_eq!(report.streams["one"], StreamOutcome::Accepted);

        // An unreadable --state stops the publish before anything is written.
        std::fs::write(&state_file, b"not a state file").unwrap();
        let before = (std::fs::read(&index).unwrap(), bundles(&s));
        let bad_state = publish(&s, "one", &signed);
        assert_eq!(bad_state.status.code(), Some(2), "{bad_state:?}");
        assert_eq!((std::fs::read(&index).unwrap(), bundles(&s)), before);
    }

    #[test]
    fn rebuild_dates_after_the_dropped_index_and_notes_its_bundles() {
        let s = setup("t-rebuild-floor");
        let state_file = s.temp.path("publish-state.json");
        let signed = [arg("-k"), &s.key, arg("--state"), &state_file];
        assert!(publish(&s, "one", &signed).status.success());
        assert!(publish(&s, "two", &signed).status.success());
        let index = s.feed_dir.join("feed.json");
        let old = parse_feed(&std::fs::read(&index).unwrap()).unwrap();
        let two = old
            .streams
            .iter()
            .find(|e| e.id == "two")
            .unwrap()
            .bundle
            .clone();

        // The index is changed, so it must be rebuilt. It is dated an hour
        // ahead, as readers may already hold it (another host's clock).
        let ahead = time::format(time::now().plus_millis(3_600_000));
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        value["updated_at"] = serde_json::json!(ahead);
        std::fs::write(&index, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let mut rebuild = signed.to_vec();
        rebuild.push(arg("--rebuild"));
        let rebuilt = publish(&s, "one", &rebuild);
        assert!(rebuilt.status.success(), "{rebuilt:?}");
        let feed = parse_feed(&std::fs::read(&index).unwrap()).unwrap();
        assert!(
            time::parse(&feed.updated_at).unwrap() > time::parse(&ahead).unwrap(),
            "{} after {ahead}",
            feed.updated_at
        );
        // The dropped stream's bundle waits for the grace, then goes.
        assert!(unreferenced(&state_file).contains(&two), "{rebuilt:?}");
        // The state keeps the index's date, for a rebuild over an index that
        // can't be read.
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
        assert_eq!(value["updated_at"], serde_json::json!(feed.updated_at));
        std::fs::write(&index, b"not json").unwrap();
        assert!(publish(&s, "one", &rebuild).status.success());
        let again = parse_feed(&std::fs::read(&index).unwrap()).unwrap();
        assert!(time::parse(&again.updated_at).unwrap() > time::parse(&feed.updated_at).unwrap());

        // A date further ahead than a reader accepts isn't followed.
        let far = "2099-01-01T00:00:00Z";
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        value["updated_at"] = serde_json::json!(far);
        std::fs::write(&index, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(publish(&s, "one", &rebuild).status.success());
        let feed = parse_feed(&std::fs::read(&index).unwrap()).unwrap();
        assert!(time::parse(&feed.updated_at).unwrap() < time::parse(far).unwrap());
        let report = poll(&s, true, &mut ReaderState::default(), None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
    }

    #[test]
    fn previous_key_keeps_every_stream_after_a_rotation() {
        let s = setup("t-previous-key");
        assert!(publish(&s, "one", &[arg("-k"), &s.key]).status.success());
        assert!(publish(&s, "two", &[arg("-k"), &s.key]).status.success());
        keys_new(&s.temp, "key-2027.json", "acme.example", "2027-03");
        let new_key = s.temp.path("key-2027.json");

        // The new key didn't sign the index: refused, pointing at the flag.
        let refused = publish(&s, "one", &[arg("-k"), &new_key]);
        assert_eq!(refused.status.code(), Some(2), "{refused:?}");
        assert!(
            text(&refused.stderr).contains("--previous-key"),
            "{refused:?}"
        );

        // A secret key file is refused, and nothing of it is printed.
        let old: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&s.key).unwrap()).unwrap();
        let seed = old["seed"].as_str().unwrap().to_owned();
        let secret = publish(
            &s,
            "one",
            &[arg("-k"), &new_key, arg("--previous-key"), &s.key],
        );
        assert_eq!(secret.status.code(), Some(2), "{secret:?}");
        let said = format!("{}{}", text(&secret.stdout), text(&secret.stderr));
        assert!(said.contains("not a key file"), "{said}");
        assert!(!said.contains(&seed), "{said}");
        let inline = publish(
            &s,
            "one",
            &[
                arg("-k"),
                &new_key,
                arg("--previous-key"),
                arg(&old.to_string()),
            ],
        );
        assert_eq!(inline.status.code(), Some(2), "{inline:?}");
        let said = format!("{}{}", text(&inline.stdout), text(&inline.stderr));
        assert!(!said.contains(&seed), "{said}");

        // With the old public key to check feed.sig, both streams are kept.
        let old_public = format!(
            "acme.example/2026-11={}",
            legible_records::sign::b64url(
                &legible_records::sign::SigningKey::from_json(&std::fs::read(&s.key).unwrap())
                    .unwrap()
                    .public()
                    .key
            )
        );
        let rotated = publish(
            &s,
            "one",
            &[arg("-k"), &new_key, arg("--previous-key"), arg(&old_public)],
        );
        assert!(rotated.status.success(), "{rotated:?}");
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        let ids: Vec<&str> = feed.streams.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["one", "two"]);
        let sig = std::fs::read(s.feed_dir.join("feed.sig")).unwrap();
        let file = legible_records::sign::SignatureFile::parse(&sig).unwrap();
        assert_eq!(file.key, "2027-03");

        // A key of another publisher isn't a previous key.
        let other = publish(
            &s,
            "one",
            &[
                arg("-k"),
                &new_key,
                arg("--previous-key"),
                arg(&format!("other.example/1={}", "A".repeat(43))),
            ],
        );
        assert_eq!(other.status.code(), Some(2), "{other:?}");
        assert!(text(&other.stderr).contains("other.example"), "{other:?}");

        // Text that isn't a public key is refused with the expected shape.
        let bad = publish(
            &s,
            "one",
            &[arg("-k"), &new_key, arg("--previous-key"), arg("nonsense")],
        );
        assert_eq!(bad.status.code(), Some(2), "{bad:?}");
        assert!(text(&bad.stderr).contains("<publisher>/<id>="), "{bad:?}");
    }

    #[test]
    fn published_at_high_water_mark_outlives_a_withdraw() {
        let s = setup("t-hwm");
        let state_file = s.temp.path("publish-state.json");
        let signed = [arg("-k"), &s.key, arg("--state"), &state_file];
        assert!(publish(&s, "main", &signed).status.success());
        assert!(publish(&s, "other", &signed).status.success());
        let mut withdraw = signed.to_vec();
        withdraw.push(arg("--withdraw"));
        assert!(publish(&s, "main", &withdraw).status.success());
        // The mark stays after the withdraw. Move it ahead of the clock (within
        // the skew a reader allows), as another publisher host's clock might.
        let ahead = time::format(time::now().plus_millis(3_600_000));
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
        assert!(value["published_at"]["main"].is_string(), "{value}");
        value["published_at"]["main"] = serde_json::json!(ahead);
        std::fs::write(&state_file, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(publish(&s, "main", &signed).status.success());
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        let main = feed.streams.iter().find(|s| s.id == "main").unwrap();
        assert!(
            time::parse(&main.published_at).unwrap() > time::parse(&ahead).unwrap(),
            "{} after {ahead}",
            main.published_at
        );
    }

    /// Adds a stream to an unsigned feed's index by hand, pointing at the
    /// bundle `like` points at.
    fn add_stream_like(s: &Setup, id: &str, like: &str) {
        let index = s.feed_dir.join("feed.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        let streams = value["streams"].as_array_mut().unwrap();
        let mut copy = streams.iter().find(|e| e["id"] == like).unwrap().clone();
        copy["id"] = serde_json::json!(id);
        streams.push(copy);
        std::fs::write(&index, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn unreferenced(state_file: &Path) -> Vec<String> {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(state_file).unwrap()).unwrap();
        value["unreferenced_since"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn gc_keeps_a_bundle_another_stream_shares_or_points_at_again() {
        let s = setup("t-gc-shared");
        let state_file = s.temp.path("publish-state.json");
        let unsigned = [
            arg("--publisher"),
            arg("acme.example"),
            arg("--state"),
            &state_file,
        ];
        assert!(publish(&s, "a", &unsigned).status.success());
        let shared = format!("bundles/{}", bundles(&s)[0]);
        add_stream_like(&s, "b", "a");
        let mut withdraw = unsigned.to_vec();
        withdraw.push(arg("--withdraw"));

        // Withdrawing a leaves b pointing at the bundle: it isn't unreferenced.
        assert!(publish(&s, "a", &withdraw).status.success());
        assert!(!unreferenced(&state_file).contains(&shared));
        // Withdrawing b too makes it unreferenced.
        assert!(publish(&s, "b", &withdraw).status.success());
        assert_eq!(unreferenced(&state_file), std::slice::from_ref(&shared));

        // A stream points at it again within the grace: it is forgotten, and
        // even an old date can't get it deleted.
        add_stream_like_bundle(&s, "c", &shared);
        assert!(publish(&s, "d", &unsigned).status.success());
        assert!(!unreferenced(&state_file).contains(&shared));
        assert!(s.feed_dir.join(&shared).exists());
    }

    /// Adds a stream to an unsigned feed's index by hand, pointing at `bundle`.
    fn add_stream_like_bundle(s: &Setup, id: &str, bundle: &str) {
        let index = s.feed_dir.join("feed.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
        let sha256 = bundle
            .trim_start_matches("bundles/")
            .trim_end_matches(".zip")
            .to_owned();
        value["streams"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": id, "title": "Shared", "record_types": [], "bundle": bundle,
                "sha256": sha256, "published_at": "2026-11-24T10:00:00Z",
            }));
        std::fs::write(&index, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    #[test]
    fn gc_deletes_after_a_withdraw_and_a_feed_can_have_no_streams() {
        let s = setup("t-gc-withdraw");
        let state_file = s.temp.path("publish-state.json");
        let signed = [arg("-k"), &s.key, arg("--state"), &state_file];
        assert!(publish(&s, "x", &signed).status.success());
        assert!(publish(&s, "y", &signed).status.success());
        let mut withdraw = signed.to_vec();
        withdraw.push(arg("--withdraw"));
        let feed = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        let bundle_of = |id: &str| {
            feed.streams
                .iter()
                .find(|e| e.id == id)
                .unwrap()
                .bundle
                .clone()
        };
        let (x, y) = (bundle_of("x"), bundle_of("y"));

        assert!(publish(&s, "x", &withdraw).status.success());
        assert_eq!(unreferenced(&state_file), std::slice::from_ref(&x));
        // Past the grace, the next publish deletes it: here, withdrawing the
        // last stream, which leaves a feed with no streams.
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_file).unwrap()).unwrap();
        value["unreferenced_since"][&x] = serde_json::json!("2020-01-01T00:00:00.000Z");
        std::fs::write(&state_file, serde_json::to_vec(&value).unwrap()).unwrap();
        let last = publish(&s, "y", &withdraw);
        assert!(last.status.success(), "{last:?}");
        assert!(!s.feed_dir.join(&x).exists());
        assert!(s.feed_dir.join(&y).exists(), "within its grace");
        assert_eq!(unreferenced(&state_file), [y]);

        let empty = parse_feed(&std::fs::read(s.feed_dir.join("feed.json")).unwrap()).unwrap();
        assert!(empty.streams.is_empty());
        let mut state = ReaderState::default();
        let report = poll(&s, true, &mut state, None);
        assert_eq!(report.index, IndexOutcome::Accepted, "{report:?}");
        assert!(report.streams.is_empty() && report.stream_ids.is_empty());
        // And a stream can be published into it again.
        assert!(publish(&s, "x", &signed).status.success());
        let report = poll(&s, true, &mut state, None);
        assert_eq!(report.streams["x"], StreamOutcome::Accepted, "{report:?}");
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

        // Signing over an unsigned index means trusting what nobody signed:
        // refused, unless the index is rebuilt.
        let over = publish(&s, "main", &[arg("-k"), &s.key]);
        assert_eq!(over.status.code(), Some(2), "{over:?}");
        assert!(text(&over.stderr).contains("--rebuild"), "{over:?}");
        let rebuilt = publish(&s, "main", &[arg("-k"), &s.key, arg("--rebuild")]);
        assert!(rebuilt.status.success(), "{rebuilt:?}");
        assert!(text(&rebuilt.stderr).contains("--rebuild"), "{rebuilt:?}");
        // A feed that has a signature isn't republished without one.
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
                // `<file>.status` holding a status code makes the server answer
                // that for the file, for failures other than 404.
                let forced = std::fs::read_to_string(file.with_extension("status"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u16>().ok());
                if !authorized {
                    respond(401, Vec::new(), None);
                } else if let Some(status) = forced {
                    respond(status, Vec::new(), None);
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
            "age_identity_env": "TRACK_AGE_IDENTITY",
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
        command.env("TRACK_AGE_IDENTITY", identity_text());
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

    /// A test-only age identity, made once per run.
    fn identity_text() -> String {
        use age::secrecy::ExposeSecret;
        static IDENTITY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        IDENTITY
            .get_or_init(|| {
                age::x25519::Identity::generate()
                    .to_string()
                    .expose_secret()
                    .to_owned()
            })
            .clone()
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
    fn a_refused_key_set_is_keys_code_and_exit_1() {
        let s = setup("t-i2-refused", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        // A key set that names another domain is bad_key_set.
        let mut set: serde_json::Value =
            serde_json::from_slice(&std::fs::read(s.keys_dir.join("keys.json")).unwrap()).unwrap();
        set["publisher"] = serde_json::json!("other.example");
        std::fs::write(
            s.keys_dir.join("keys.json"),
            serde_json::to_vec(&set).unwrap(),
        )
        .unwrap();
        let result = run("check", &[&connection], Some(server.port));
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        let stdout = text(&result.stdout);
        assert!(stdout.lines().any(|l| l == "keys: bad_key_set"), "{stdout}");
        // The pin still checks the feed.
        assert!(
            stdout.contains("alpha: accepted (verified acme.example 2026-11)"),
            "{stdout}"
        );
    }

    #[test]
    fn an_unreachable_key_set_with_a_pin_is_stderr_and_exit_0() {
        let s = setup("t-i2-unreachable", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        std::fs::write(s.keys_dir.join("keys.status"), "503").unwrap();
        let connection = write_connection(&s, server.port, true);
        let result = run("check", &[&connection], Some(server.port));
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert!(text(&result.stderr).contains("keys: failed"), "{result:?}");
        assert!(!text(&result.stdout).contains("keys:"), "{result:?}");
        assert!(text(&result.stdout).contains("alpha: accepted (verified"));
    }

    #[test]
    fn an_unreachable_key_set_with_nothing_else_is_exit_2() {
        // R2: a 403 on keys.json can't make a signing publisher look like one
        // with no key set.
        let s = setup("t-i2-unreachable-unpinned", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        std::fs::write(s.keys_dir.join("keys.status"), "403").unwrap();
        let connection = write_connection(&s, server.port, false);
        let result = run("check", &[&connection], Some(server.port));
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(text(&result.stderr).contains("key set"), "{result:?}");
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

        // One zip per stream, named by published_at with ':' as '-', and the
        // first 12 hex of the file's own SHA-256.
        let held = s.state();
        let files = out_files(&out);
        assert_eq!(files.len(), 2, "{files:?}");
        for id in ["alpha", "beta"] {
            let published = held.streams[id].published_at.replace(':', "-");
            let name = files
                .iter()
                .find(|f| f.starts_with(&format!("{id}/{published}-")))
                .unwrap_or_else(|| panic!("{id}/{published}-<hash>.zip in {files:?}"));
            let path = out.join(name);
            let hash = legible_records::bundle::sha256_hex(&std::fs::read(&path).unwrap());
            assert_eq!(*name, format!("{id}/{published}-{}.zip", &hash[..12]));
            // Whole: the CLI verifies it, signature included.
            let verified = legible(&[
                arg("bundle"),
                arg("verify"),
                &path,
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

    #[test]
    fn a_failed_write_is_retried_next_pull() {
        let s = setup("t9-retry", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), true);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);
        // <out>/alpha is a file, so alpha's bundle can't be written.
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("alpha"), b"in the way").unwrap();
        let result = run("pull", &args, Some(server.port));
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert!(
            text(&result.stdout).contains("alpha: failed: "),
            "{result:?}"
        );
        assert!(s.state().streams.is_empty());
        let kept: serde_json::Value =
            serde_json::from_slice(&std::fs::read(s.state_file()).unwrap()).unwrap();
        assert!(kept.get("etag").is_none(), "no ETag saved: {kept}");

        std::fs::remove_file(out.join("alpha")).unwrap();
        let again = run("pull", &args, Some(server.port));
        assert_eq!(again.status.code(), Some(0), "{again:?}");
        assert!(
            text(&again.stdout).contains("alpha: accepted (verified acme.example 2026-11)"),
            "{again:?}"
        );
        assert_eq!(out_files(&out).len(), 1);
        assert!(s.state().streams.contains_key("alpha"));
    }

    #[test]
    fn different_bundles_with_one_published_at_get_different_files() {
        use legible_records::bundle::{pack_with, sha256_hex, Input, PackOptions};
        use legible_records::feed::{render_feed, Feed, StreamEntry};
        let s = setup("t9-collide", &[]);
        std::fs::create_dir_all(s.feed_dir.join("bundles")).unwrap();
        // Unsigned bundles, so nothing checks one's published_at against the last.
        let publish_unsigned = |id: &str, updated_at: &str| {
            let input = Input {
                name: "ack.json".to_owned(),
                bytes: format!(
                    r#"{{"$type":"tech.monorail.policy.acknowledgment","version":1,"id":"{id}","title":"{id}"}}"#
                )
                .into_bytes(),
            };
            let options = PackOptions {
                published_at: Some("2026-11-24T10:00:00Z".to_owned()),
                ..PackOptions::default()
            };
            let zip = pack_with(&[input], &[], &options).unwrap().zip;
            let sha256 = sha256_hex(&zip);
            let bundle = format!("bundles/{sha256}.zip");
            std::fs::write(s.feed_dir.join(&bundle), &zip).unwrap();
            let feed = Feed {
                id: FEED.to_owned(),
                publisher: "acme.example".to_owned(),
                audience: "Monorail, for Track".to_owned(),
                updated_at: updated_at.to_owned(),
                streams: vec![StreamEntry {
                    id: "alpha".to_owned(),
                    title: "Acknowledgments".to_owned(),
                    record_types: vec![],
                    bundle,
                    sha256,
                    published_at: "2026-11-24T10:00:00Z".to_owned(),
                }],
            };
            std::fs::write(s.feed_dir.join("feed.json"), render_feed(&feed)).unwrap();
        };
        std::fs::remove_file(s.keys_dir.join("keys.json")).unwrap();
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, false);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let args = pull_args(&s, &connection, &state, &out);

        publish_unsigned("one", "2026-11-24T10:00:01Z");
        let first = run("pull", &args, Some(server.port));
        assert_eq!(first.status.code(), Some(0), "{first:?}");
        publish_unsigned("two", "2026-11-24T10:00:02Z");
        let second = run("pull", &args, Some(server.port));
        assert_eq!(second.status.code(), Some(0), "{second:?}");
        assert!(
            text(&second.stdout).contains("alpha: accepted (unverified)"),
            "{second:?}"
        );
        let files = out_files(&out);
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(
            files
                .iter()
                .all(|f| f.starts_with("alpha/2026-11-24T10-00-00Z-")),
            "{files:?}"
        );
    }

    #[test]
    fn secrets_never_reach_the_output() {
        let s = setup("t9-secrets", &["alpha"]);
        let server = serve(s.feed_dir.clone(), s.keys_dir.clone(), false);
        let connection = write_connection(&s, server.port, true);
        let (state, out) = (s.temp.path("state"), s.temp.path("out"));
        let down = {
            let gone = tiny_http::Server::http("127.0.0.1:0").unwrap();
            gone.server_addr().to_ip().unwrap().port()
        };
        let unreachable = write_connection(&s, down, true);
        let pull = pull_args(&s, &connection, &state, &out);
        let pull_down = pull_args(&s, &unreachable, &state, &out);
        let runs = [
            run("check", &[&connection], Some(server.port)),
            run("pull", &pull, Some(server.port)),
            run("pull", &pull, Some(server.port)),
            run("check", &[&unreachable], Some(down)),
            run("pull", &pull_down, Some(down)),
        ];
        let identity = identity_text();
        for result in &runs {
            let all = format!("{}{}", text(&result.stdout), text(&result.stderr));
            assert!(!all.contains(TOKEN), "{all}");
            assert!(!all.contains(&identity), "{all}");
        }
        assert_eq!(runs[3].status.code(), Some(2));

        // An encrypted feed, read with the identity from the environment, and
        // then with one that can't decrypt it: neither echoes a secret.
        let recipient = identity
            .parse::<age::x25519::Identity>()
            .unwrap()
            .to_public()
            .to_string();
        let sealed_dir = s.temp.path("sealed");
        let record = s.temp.path("ack.json");
        let published = legible(&[
            arg("feed"),
            arg("publish"),
            &sealed_dir,
            arg("--feed"),
            arg(FEED),
            arg("--audience"),
            arg("Monorail, for Track"),
            arg("--stream"),
            arg("alpha"),
            arg("--title"),
            arg("Acknowledgments"),
            arg("-k"),
            &s.key,
            arg("-r"),
            arg(&recipient),
            &record,
        ]);
        assert!(published.status.success(), "{published:?}");
        assert!(sealed_dir.join("feed.json.age").exists());
        let sealed = serve(sealed_dir.clone(), s.keys_dir.clone(), false);
        let sealed_connection = write_connection(&s, sealed.port, true);
        let (sealed_state, sealed_out) = (s.temp.path("sealed-state"), s.temp.path("sealed-out"));
        let sealed_pull = pull_args(&s, &sealed_connection, &sealed_state, &sealed_out);
        let ok = run("pull", &sealed_pull, Some(sealed.port));
        assert_eq!(ok.status.code(), Some(0), "{ok:?}");
        assert!(
            text(&ok.stdout).contains("alpha: accepted (verified"),
            "{ok:?}"
        );
        let other = age::x25519::Identity::generate();
        let wrong = Command::new(env!("CARGO_BIN_EXE_legible"))
            .args(["feed", "check"])
            .arg(&sealed_connection)
            .arg("--key-origin")
            .arg(format!("http://127.0.0.1:{}", sealed.port))
            .env("TRACK_FEED_TOKEN", TOKEN)
            .env(
                "TRACK_AGE_IDENTITY",
                age::secrecy::ExposeSecret::expose_secret(&other.to_string()),
            )
            .output()
            .unwrap();
        assert_eq!(wrong.status.code(), Some(2), "{wrong:?}");
        for result in [&ok, &wrong] {
            let all = format!("{}{}", text(&result.stdout), text(&result.stderr));
            assert!(!all.contains(TOKEN), "{all}");
            assert!(!all.contains(&identity), "{all}");
            assert!(
                !all.contains(age::secrecy::ExposeSecret::expose_secret(
                    &other.to_string()
                )),
                "{all}"
            );
        }
    }

    #[test]
    fn key_origin_must_be_loopback() {
        let s = setup("t9-origin", &["alpha"]);
        let connection = write_connection(&s, 1, true);
        let mut command = Command::new(env!("CARGO_BIN_EXE_legible"));
        command.args(["feed", "check"]).arg(&connection);
        command.args(["--key-origin", "https://keys.example.net"]);
        command.env("TRACK_FEED_TOKEN", TOKEN);
        let result = command.output().unwrap();
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(text(&result.stderr).contains("loopback"), "{result:?}");
    }
}

mod record_sets {
    use super::*;

    fn alert(id: &str) -> String {
        format!(r#"{{"$type":"example.alert","id":"{id}","severity":"high","version":1}}"#)
    }

    fn write_alerts(dir: &Temp, ids: &[&str]) {
        std::fs::create_dir_all(dir.path("in")).unwrap();
        for id in ids {
            std::fs::write(dir.path(&format!("in/{id}.json")), alert(id)).unwrap();
        }
    }

    #[test]
    fn pack_ndjson_input_then_verify() {
        let dir = Temp::new("set-ndjson");
        let set = format!("{}\n{}\n", alert("a-1"), alert("a-2"));
        std::fs::write(dir.path("alert.ndjson"), &set).unwrap();
        let packed = legible(&[
            arg("bundle"),
            arg("pack"),
            &dir.path("alert.ndjson"),
            arg("-o"),
            &dir.path("b.zip"),
        ]);
        assert_eq!(packed.status.code(), Some(0), "{packed:?}");
        let verified = legible(&[arg("bundle"), arg("verify"), &dir.path("b.zip")]);
        assert_eq!(verified.status.code(), Some(0), "{verified:?}");
        let unpacked = legible(&[
            arg("bundle"),
            arg("unpack"),
            &dir.path("b.zip"),
            arg("-d"),
            &dir.path("out"),
        ]);
        assert_eq!(unpacked.status.code(), Some(0), "{unpacked:?}");
        assert_eq!(
            std::fs::read(dir.path("out/records/alert.ndjson")).unwrap(),
            set.as_bytes(),
            "unpack writes the set byte for byte"
        );
    }

    #[test]
    fn pack_set_flag_writes_set_and_no_sets_writes_files() {
        let dir = Temp::new("set-flag");
        write_alerts(&dir, &["a-1", "a-2"]);
        let packed = legible(&[
            arg("bundle"),
            arg("pack"),
            &dir.path("in"),
            arg("--set"),
            arg("alert"),
            arg("-o"),
            &dir.path("set.zip"),
        ]);
        assert_eq!(packed.status.code(), Some(0), "{packed:?}");
        let opened = legible_records::bundle::open(
            &std::fs::read(dir.path("set.zip")).unwrap(),
            Default::default(),
        )
        .unwrap();
        assert!(opened.files.contains_key("records/alert.ndjson"));
        let plain = legible(&[
            arg("bundle"),
            arg("pack"),
            &dir.path("in"),
            arg("--no-sets"),
            arg("-o"),
            &dir.path("files.zip"),
        ]);
        assert_eq!(plain.status.code(), Some(0), "{plain:?}");
        let opened = legible_records::bundle::open(
            &std::fs::read(dir.path("files.zip")).unwrap(),
            Default::default(),
        )
        .unwrap();
        assert!(opened.files.contains_key("records/alert/a-1.json"));
        let both = legible(&[
            arg("bundle"),
            arg("pack"),
            &dir.path("in"),
            arg("--set"),
            arg("alert"),
            arg("--no-sets"),
            arg("-o"),
            &dir.path("x.zip"),
        ]);
        assert_eq!(both.status.code(), Some(2), "{both:?}");
    }

    #[test]
    fn pack_bad_ndjson_exits_1_naming_line() {
        let dir = Temp::new("set-bad");
        let unsorted = format!("{}\n{}\n", alert("b"), alert("a"));
        std::fs::write(dir.path("alert.ndjson"), unsorted).unwrap();
        let packed = legible(&[
            arg("bundle"),
            arg("pack"),
            &dir.path("alert.ndjson"),
            arg("-o"),
            &dir.path("b.zip"),
        ]);
        assert_eq!(packed.status.code(), Some(1), "{packed:?}");
        assert!(
            String::from_utf8_lossy(&packed.stderr).contains("line 2"),
            "{packed:?}"
        );
    }

    #[test]
    fn verify_bad_set_exits_1_naming_line() {
        let dir = Temp::new("set-verify-bad");
        let bundle = format!(
            "{}/../legible-records/tests/vectors/bundles/unsorted-lines/bundle.zip",
            env!("CARGO_MANIFEST_DIR")
        );
        let verified = legible(&[arg("bundle"), arg("verify"), Path::new(&bundle)]);
        drop(dir);
        assert_eq!(verified.status.code(), Some(1), "{verified:?}");
        let said = String::from_utf8_lossy(&verified.stdout);
        assert!(
            said.contains("records/alert.ndjson") && said.contains("line 2"),
            "{said}"
        );
    }
}

#[test]
fn pack_set_for_an_unknown_kind_exits_1() {
    let dir = Temp::new("set-unknown-kind");
    std::fs::create_dir_all(dir.path("in")).unwrap();
    std::fs::write(
        dir.path("in/a-1.json"),
        r#"{"$type":"example.alert","id":"a-1","version":1}"#,
    )
    .unwrap();
    let packed = legible(&[
        arg("bundle"),
        arg("pack"),
        &dir.path("in"),
        arg("--set"),
        arg("alret"),
        arg("-o"),
        &dir.path("b.zip"),
    ]);
    assert_eq!(packed.status.code(), Some(1), "{packed:?}");
    assert!(
        String::from_utf8_lossy(&packed.stderr).contains("alret"),
        "{packed:?}"
    );
}

#[test]
fn record_hash_prints_sha256() {
    let dir = Temp::new("record-hash");
    let file = dir.path("policy.json");
    // The spec's "plain" content-line case, with provenance that doesn't count.
    std::fs::write(
        &file,
        r##"{
  "$type": "tech.monorail.policy.document",
  "version": 1,
  "id": "access-control",
  "title": "Access control",
  "revision": 3,
  "effective_date": "2026-11-01",
  "status": "published",
  "body": "# Access control\n\nEveryone uses MFA.",
  "produced_by": {"app": "outpost"}
}
"##,
    )
    .unwrap();
    let out = legible(&[arg("record"), arg("hash"), &file]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("55d39db55254"),
        "unexpected output {stdout}"
    );
    assert!(stdout
        .trim_end()
        .ends_with(&format!("  {}", file.display())));
}

#[test]
fn record_hash_refuses_non_object() {
    let dir = Temp::new("record-hash-array");
    let file = dir.path("list.json");
    std::fs::write(&file, "[1, 2]\n").unwrap();
    let out = legible(&[arg("record"), arg("hash"), &file]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a JSON object"));
}

#[test]
fn record_hash_refuses_duplicate_keys() {
    let dir = Temp::new("record-hash-dupes");
    let file = dir.path("dupes.json");
    std::fs::write(&file, r#"{"id": "a", "id": "b"}"#).unwrap();
    let out = legible(&[arg("record"), arg("hash"), &file]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("twice"));
}

/// A published type with rules, in the short form. `extra` is appended to
/// its document `rules`.
fn thing_with_rules(extra: &str) -> String {
    format!(
        "type: org.example.thing\nversion: 1\nfields:\n  at?: datetime\n  on?: date\n  notes?: string[]\n  owner?: string\n  status: known(open, closed)\n  steps?:\n    items:\n      fields:\n        n: integer\n        m?: integer\n      rules:\n        - before(n, m)\nrules:\n  - one_of(at, on)\n  - requires(status = closed, any_of(notes, owner))\n{extra}"
    )
}

#[test]
fn lint_passes_a_type_with_rules() {
    let dir = Temp::new("lint-rules");
    let file = dir.path("thing.yaml");
    std::fs::write(&file, thing_with_rules("  - at_most_one(notes, owner)\n")).unwrap();
    let out = legible(&[
        arg("lint"),
        &file,
        arg("--base"),
        arg("https://example.org/schemas/"),
    ]);
    assert_eq!(
        (out.status.code(), text(&out.stdout), text(&out.stderr)),
        (Some(0), String::new(), String::new())
    );
}

#[test]
fn check_compat_reports_an_added_rule() {
    let dir = Temp::new("compat-rules");
    let old = dir.path("old.yaml");
    let new = dir.path("new.yaml");
    std::fs::write(&old, thing_with_rules("")).unwrap();
    std::fs::write(&new, thing_with_rules("  - at_most_one(notes,   owner)\n")).unwrap();
    let base = ["--base", "https://example.org/schemas/"].map(arg);
    let out = legible(&[&[arg("check-compat"), &old, &new], &base[..]].concat());
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "{}: /: rule added: at_most_one(notes, owner)\n",
            old.display()
        )
    );
    // The other way, the rule is removed, which is compatible.
    let out = legible(&[&[arg("check-compat"), &new, &old], &base[..]].concat());
    assert_eq!(
        (out.status.code(), text(&out.stdout)),
        (Some(0), String::new())
    );
}
