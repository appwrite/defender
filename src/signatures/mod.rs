//! ClamAV on-disk signature formats: hash, extended (NDB), and logical (LDB).

pub mod hash;
pub mod hexpat;
pub mod ldb;
pub mod ndb;

pub use hash::{FpSet, HashAlgo, HashDb, HashSig};
pub use hexpat::HexPattern;
pub use ldb::{load_ldb, LogicalSig};
pub use ndb::{load_ndb, NdbSig, OffsetKind, TargetType};

/// True if `name` is a signature file the engine can ingest.
pub fn is_signature_member(name: &str, load_pua: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "hdb" | "hsb" | "mdb" | "msb" | "ndb" | "ldb" | "fp" | "sfp" | "ign" | "ign2" => true,
        "hdu" | "hsu" | "mdu" | "msu" | "ndu" | "ldu" => load_pua,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_members() {
        assert!(is_signature_member("main.mdb", false));
        assert!(is_signature_member("daily.ldb", false));
        assert!(!is_signature_member("main.mdu", false));
        assert!(is_signature_member("main.mdu", true));
        assert!(!is_signature_member("bytecode.cbc", true));
        assert!(!is_signature_member("main.cvd.tmp", false));
    }
}
