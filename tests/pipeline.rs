//! End-to-end tests against a synthetic CVD and (optionally) a real official CVD.

use defender::cvd::header::{CvdHeader, CVD_HEADER_SIZE};
use defender::cvd::load_bytes;
use defender::cvd::unpack::{pack_cvd, unpack_cvd};
use defender::cvd::verify::{md5_hex, verify_cvd_bytes, verify_legacy_md5, VerifyMode};
use defender::engine::{hash_bytes, Engine, EICAR};
use defender::signatures::hash::HashSig;
use defender::signatures::ldb::LogicalSig;
use defender::signatures::ndb::NdbSig;
use md5::{Digest, Md5};
use sha2::Sha256;

#[test]
fn official_bytecode_cvd_header_md5_and_unpack() {
    let path = "/tmp/clamav-sample/bytecode.cvd";
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skip: {path} not present");
        return;
    };
    let header = CvdHeader::parse(&bytes).expect("header");
    assert_eq!(header.magic, "ClamAV-VDB");
    assert!(header.version > 0);
    assert_eq!(header.md5.len(), 32);
    verify_cvd_bytes(&bytes, &header, VerifyMode::Integrity).unwrap();
    let unpacked = unpack_cvd(&bytes).unwrap();
    assert!(!unpacked.is_empty());
    // Official RSA: try legacy then accept either success or documented failure
    // so we still assert MD5 integrity (the container checksum).
    let official = verify_cvd_bytes(&bytes, &header, VerifyMode::Official);
    assert!(official.is_ok(), "official RSA dsig failed: {official:?}");
    assert!(verify_legacy_md5(&header.md5, &header.dsig));
    let _ = load_bytes(&bytes, VerifyMode::Integrity).unwrap();
}

#[test]
fn load_official_daily_cvd_if_present() {
    if std::env::var("DEFENDER_TEST_OFFICIAL").is_err() {
        eprintln!("skip: set DEFENDER_TEST_OFFICIAL=1 to load daily.cvd");
        return;
    }
    let path = "/tmp/defender-db/daily.cvd";
    let Ok(bytes) = std::fs::read(path) else {
        eprintln!("skip: {path} not present");
        return;
    };
    let t0 = std::time::Instant::now();
    let eng = Engine::from_cvd_bytes("daily.cvd", &bytes, VerifyMode::Official, false)
        .expect("official daily.cvd must verify and load");
    eprintln!(
        "daily loaded in {:?}: hashes={} body={} logical={} skipped={} version={:?}",
        t0.elapsed(),
        eng.meta.file_hashes,
        eng.meta.body_sigs,
        eng.meta.logical_sigs,
        eng.meta.skipped_sigs,
        eng.meta
            .databases
            .iter()
            .map(|d| d.version)
            .collect::<Vec<_>>()
    );
    match eng.scan(EICAR).verdict {
        defender::ScanVerdict::Infected { signature } => {
            eprintln!("EICAR detected as {signature}");
        }
        defender::ScanVerdict::Clean => {
            // daily.cvd may rely on main.cvd for the EICAR hash; body sig may still hit.
            eprintln!("EICAR not detected in daily-only engine (ok if hashes live in main)");
        }
    }
    assert!(eng.meta.file_hashes + eng.meta.body_sigs + eng.meta.logical_sigs > 0);
}

#[test]
fn synthetic_cvd_scan_pipeline() {
    let md5 = hex::encode(Md5::digest(EICAR));
    let sha = hex::encode(Sha256::digest(EICAR));
    let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
    let hsb = format!("{sha}:68:Eicar-SHA\n");
    let ndb = "Body.Eicar:0:*:58354f21\n";
    let ldb = "Log.Eicar;Target:0;0&1;58354f21;50254041\n";
    let cvd = pack_cvd(
        &[
            ("s.hdb", hdb.as_bytes()),
            ("s.hsb", hsb.as_bytes()),
            ("s.ndb", ndb.as_bytes()),
            ("s.ldb", ldb.as_bytes()),
        ],
        9,
        "ci",
    )
    .unwrap();
    assert_eq!(cvd.len() >= CVD_HEADER_SIZE, true);
    let (header, unpacked) = load_bytes(&cvd, VerifyMode::Integrity).unwrap();
    assert_eq!(header.version, 9);
    assert_eq!(unpacked.files.len(), 4);
    assert_eq!(md5_hex(&cvd[CVD_HEADER_SIZE..]), header.md5);

    let eng = Engine::from_cvd_bytes("s.cvd", &cvd, VerifyMode::Integrity, false).unwrap();
    assert!(eng.meta.file_hashes >= 2);
    assert!(eng.meta.body_sigs >= 1);
    assert!(eng.meta.logical_sigs >= 1);
    match eng.scan(EICAR).verdict {
        defender::ScanVerdict::Infected { .. } => {}
        defender::ScanVerdict::Clean => panic!("expected detection"),
    }
    let h = hash_bytes(EICAR);
    assert!(eng.lookup_hashes(&h).is_some());
}

#[test]
fn parsers_reject_garbage() {
    assert!(HashSig::parse_line("not-a-sig", None).is_err());
    assert!(NdbSig::parse_line("nope").is_err());
    assert!(LogicalSig::parse_line("x").is_err());
    assert!(CvdHeader::parse(&[0; 10]).is_err());
}

#[test]
fn load_dir_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let md5 = hex::encode(Md5::digest(EICAR));
    let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
    let cvd = pack_cvd(&[("d.hdb", hdb.as_bytes())], 3, "dir").unwrap();
    std::fs::write(dir.path().join("daily.cvd"), cvd).unwrap();
    let eng = Engine::load_dir(dir.path(), VerifyMode::Integrity, false).unwrap();
    assert!(matches!(
        eng.scan(EICAR).verdict,
        defender::ScanVerdict::Infected { .. }
    ));
}

#[test]
fn load_dir_skips_tmp_and_unknown_files() {
    let dir = tempfile::tempdir().unwrap();
    let md5 = hex::encode(Md5::digest(EICAR));
    let hdb = format!("{md5}:68:Eicar-Test-Signature\n");
    let cvd = pack_cvd(&[("d.hdb", hdb.as_bytes())], 3, "dir").unwrap();
    std::fs::write(dir.path().join("daily.cvd"), &cvd).unwrap();
    std::fs::write(dir.path().join("daily.cvd.tmp"), b"not a cvd").unwrap();
    std::fs::write(dir.path().join("README.txt"), b"ignore me").unwrap();
    let eng = Engine::load_dir(dir.path(), VerifyMode::Integrity, false).unwrap();
    assert!(matches!(
        eng.scan(EICAR).verdict,
        defender::ScanVerdict::Infected { .. }
    ));
}
