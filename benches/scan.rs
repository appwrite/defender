use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use defender::cvd::unpack::pack_cvd;
use defender::cvd::VerifyMode;
use defender::engine::{hash_bytes, Engine, IncrementalHashers, EICAR};
use md5::{Digest, Md5};

fn built_engine(hash_count: usize, body_count: usize) -> Engine {
    let mut hdb = String::new();
    let eicar_md5 = hex::encode(Md5::digest(EICAR));
    hdb.push_str(&format!("{eicar_md5}:68:Eicar-Test-Signature\n"));
    for i in 0..hash_count {
        let d = Md5::digest(i.to_le_bytes());
        hdb.push_str(&format!(
            "{}:{}:Win.Test.Bench-{i}\n",
            hex::encode(d),
            16 + (i % 100)
        ));
    }
    let mut ndb = String::new();
    ndb.push_str("Eicar-Test-Signature:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a\n");
    for i in 0..body_count {
        let lit = format!("DEAD{i:04x}BEEF");
        let hex: String = lit.bytes().map(|b| format!("{b:02x}")).collect();
        ndb.push_str(&format!("Win.Test.Body-{i}:0:*:{hex}\n"));
    }
    let cvd = pack_cvd(
        &[("bench.hdb", hdb.as_bytes()), ("bench.ndb", ndb.as_bytes())],
        1,
        "bench",
    )
    .unwrap();
    Engine::from_cvd_bytes("bench.cvd", &cvd, VerifyMode::Integrity, false).unwrap()
}

fn bench_hash_lookup(c: &mut Criterion) {
    let eng = built_engine(50_000, 0);
    let h = hash_bytes(EICAR);
    let mut g = c.benchmark_group("hash_lookup");
    g.throughput(Throughput::Elements(1));
    g.bench_function("eicar_sha256", |b| {
        b.iter(|| {
            black_box(eng.lookup_hashes(black_box(&h)));
        })
    });
    g.finish();
}

fn bench_scan(c: &mut Criterion) {
    let eng = built_engine(10_000, 2_000);
    let clean = vec![0u8; 64 * 1024];
    let mut infected_body = vec![0u8; 4096];
    infected_body.extend_from_slice(EICAR);
    infected_body.extend_from_slice(&[1u8; 4096]);

    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(clean.len() as u64));
    g.bench_function("clean_64k", |b| {
        b.iter(|| black_box(eng.scan(black_box(&clean))))
    });
    g.throughput(Throughput::Bytes(EICAR.len() as u64));
    g.bench_function("eicar_68b", |b| {
        b.iter(|| black_box(eng.scan(black_box(EICAR))))
    });
    g.throughput(Throughput::Bytes(infected_body.len() as u64));
    g.bench_function("eicar_embedded_8k", |b| {
        b.iter(|| black_box(eng.scan(black_box(&infected_body))))
    });
    g.finish();
}

fn bench_streaming_hash(c: &mut Criterion) {
    let chunk = vec![0xA5u8; 16 * 1024];
    let mut g = c.benchmark_group("stream_hash");
    g.throughput(Throughput::Bytes((chunk.len() * 8) as u64));
    g.bench_function("md5_sha1_sha256_128k", |b| {
        b.iter(|| {
            let mut h = IncrementalHashers::new();
            for _ in 0..8 {
                h.update(black_box(&chunk));
            }
            black_box(h.finalize())
        })
    });
    g.finish();
}

fn bench_cvd_parse(c: &mut Criterion) {
    let hdb = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n";
    let cvd = pack_cvd(&[("t.hdb", hdb.as_bytes())], 7, "unit").unwrap();
    c.bench_function("cvd_parse_unpack", |b| {
        b.iter(|| {
            black_box(defender::cvd::load_bytes(black_box(&cvd), VerifyMode::Integrity).unwrap())
        })
    });
}

fn bench_hot_swap(c: &mut Criterion) {
    use defender::engine::Database;
    c.bench_function("arcswap_scan", |b| {
        let db = Database::new(built_engine(1000, 10));
        b.iter(|| {
            let eng = db.current();
            black_box(eng.scan(black_box(EICAR)))
        })
    });
}

criterion_group!(
    benches,
    bench_hash_lookup,
    bench_scan,
    bench_streaming_hash,
    bench_cvd_parse,
    bench_hot_swap
);
criterion_main!(benches);
