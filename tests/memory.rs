//! Memory-stability tests: repeated scans and engine swaps must not grow RSS without bound.

use defender::cvd::unpack::pack_cvd;
use defender::cvd::VerifyMode;
use defender::engine::{Database, Engine, EICAR};
use md5::{Digest, Md5};

fn rss_kb() -> u64 {
    let ok = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in ok.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let n = rest.split_whitespace().next().unwrap_or("0");
            return n.parse().unwrap_or(0);
        }
    }
    0
}

fn tiny_engine(tag: u32) -> Engine {
    let md5 = hex::encode(Md5::digest(EICAR));
    let hdb = format!("{md5}:68:Eicar-{tag}\n");
    let ndb = "Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a\n";
    let cvd = pack_cvd(
        &[("t.hdb", hdb.as_bytes()), ("t.ndb", ndb.as_bytes())],
        tag,
        "mem",
    )
    .unwrap();
    Engine::from_cvd_bytes("t.cvd", &cvd, VerifyMode::Integrity, false).unwrap()
}

#[test]
fn rss_stable_after_many_scans() {
    let eng = tiny_engine(1);
    // Warm-up / page in.
    for _ in 0..100 {
        let _ = eng.scan(EICAR);
        let _ = eng.scan(b"clean payload for rss test");
    }
    let start = rss_kb();
    for i in 0..20_000 {
        let payload = if i % 2 == 0 {
            EICAR.to_vec()
        } else {
            vec![i as u8; 256]
        };
        let r = eng.scan(&payload);
        std::mem::drop(r);
    }
    let end = rss_kb();
    // Allow allocator slack / page rounding, but catch unbounded growth.
    assert!(
        end < start + 32 * 1024,
        "RSS grew too much: start={start} kB end={end} kB"
    );
}

#[test]
fn rss_stable_after_engine_swaps() {
    let db = Database::new(tiny_engine(1));
    for _ in 0..50 {
        let _ = db.current().scan(EICAR);
    }
    let start = rss_kb();
    for i in 0..200 {
        db.swap(tiny_engine(2 + i));
        for _ in 0..20 {
            let _ = db.current().scan(EICAR);
            let _ = db.current().scan(&[7u8; 128]);
        }
    }
    // Force drop of old engines.
    db.swap(tiny_engine(9999));
    defender::alloc::reclaim_unused_pages();
    for _ in 0..10 {
        let _ = db.current().scan(EICAR);
    }
    let end = rss_kb();
    assert!(
        end < start + 64 * 1024,
        "RSS grew too much across swaps: start={start} kB end={end} kB"
    );
}
