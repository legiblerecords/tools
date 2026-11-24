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
