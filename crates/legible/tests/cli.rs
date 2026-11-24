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
