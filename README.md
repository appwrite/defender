# defender

High-performance Rust HTTP virus scanner that **parses ClamAV public databases** (CVD/CLD) natively — no `libclamav`, no `clamd`.

It accepts **streamable file uploads** and **hash lookups**, scans them with hash, PE-section, extended (NDB), and logical (LDB) signatures, and hot-reloads a verified database **without restarting** the process.

## HTTP API

| Method | Path | Body | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | | Liveness |
| `GET` | `/ready` | | Readiness (signatures loaded) |
| `GET` | `/info` | | CVD versions and signature counts |
| `POST` | `/scan` | raw bytes or `multipart/form-data` | Stream a file; hashes as it arrives |
| `POST` | `/scan/hash` | JSON `{ "md5"\|"sha1"\|"sha256"\|"hash", "size"? }` | Hash-only lookup |
| `POST` | `/scan/hashes` | NDJSON or one digest per line | Stream many hash lookups |

`POST /scan` example:

```bash
curl -sS -X POST --data-binary @sample.bin http://127.0.0.1:8080/scan
```

Response:

```json
{
  "result": "infected",
  "signature": "Eicar-Test-Signature",
  "size": 68,
  "md5": "44d88612fea8a8f36de82e1278abb02f",
  "sha1": "...",
  "sha256": "...",
  "duration_us": 42
}
```

## ClamAV formats implemented

**CVD container** (512-byte header + gzip tar), parsed from the [official spec](https://docs.clamav.net/manual/Signatures.html):

```
ClamAV-VDB:{time}:{version}:{signatures}:{flevel}:{md5}:{dsig}:{builder}:{stime}
```

Verification (from `libclamav/dsig.c` / `cvd.c`):

1. MD5 of the gzip body must equal the header MD5
2. RSA digital signature using ClamAV’s historical public key (`CLI_NSTR` / `CLI_ESTR`) and the custom little-endian radix-64 encoding (`cli_versig`)
3. RSASSA-PSS-style `cli_versig2` over SHA-256 as a fallback

**Signature files inside the archive:**

| Extension | Role |
| --- | --- |
| `.hdb` / `.hsb` | Whole-file MD5 / SHA1 / SHA256 (`Hash:Size:Name`, size may be `*`) |
| `.mdb` / `.msb` | PE section hashes |
| `.ndb` | Extended body signatures (`Name:Target:Offset:HexSig`) |
| `.ldb` | Logical signatures (`Name;TDB;expr;subsig…`) |
| `.fp` / `.sfp` | False-positive allow-list |
| `.ign` / `.ign2` | Ignored signature names |

Hex wildcards: `??`, nibble `a?`/`?a`, `{n}` / `{n-m}` / `{n-}` / `{-n}`, `*`, `[n-m]`, `(aa\|bb)`, `(B)` `(L)` `(W)`.

Bytecode (`.cbc`) and YARA are not executed; PUA `*u` files are skipped unless `DEFENDER_LOAD_PUA=1`.

## Zero-downtime updates

A background task (same process, independent Tokio task):

1. `Range: bytes=0-511` against configured mirrors to read the remote CVD header
2. Downloads `main.cvd` / `daily.cvd` when the version/MD5 is newer
3. Verifies MD5 + RSA
4. Compiles a **new** `Engine` off the request path
5. Atomically swaps it with `arc-swap`

In-flight scans keep the previous `Arc<Engine>` until they finish. No connection drop, no restart.

Default mirrors:

- `https://database.clamav.net`
- `https://packages.microsoft.com/clamav`

## Docker

The image **bakes in the current official CVDs** at build time and still refreshes them at runtime.

```bash
docker build -t defender .
docker run --rm -p 8080:8080 defender
```

## Configuration

| Variable | Default |
| --- | --- |
| `DEFENDER_LISTEN` | `0.0.0.0:8080` |
| `DEFENDER_DB_DIR` | `/var/lib/defender/db` |
| `DEFENDER_UPDATE_INTERVAL_SECS` | `3600` |
| `DEFENDER_MIRRORS` | ClamAV + Microsoft |
| `DEFENDER_DATABASES` | `main,daily` |
| `DEFENDER_MAX_BYTES` | `67108864` |
| `DEFENDER_LOAD_PUA` | `false` |
| `DEFENDER_SKIP_DSIG` | `false` (set to skip RSA; MD5 still checked) |
| `DEFENDER_USER_AGENT` | `ClamAV/1.4.2 (defender; rust-http)` |
| `RUST_LOG` | `info` |

## Virus database sizes

Official ClamAV CVD files as of 18 Aug 2026 (from `database.clamav.net`):

| File | On disk | Unpacked | Header signatures | Notes |
| --- | ---: | ---: | ---: | --- |
| `main.cvd` | **84.95 MiB** (89,072,577 B) | 225.39 MiB | 3,287,027 | Base set; largest member `main.mdb` 159 MiB |
| `daily.cvd` | **22.34 MiB** (23,426,416 B) | 82.14 MiB | 355,605 | Daily deltas; largest member `daily.ldb` 73 MiB |
| `bytecode.cvd` | **0.27 MiB** (281,702 B) | 1.24 MiB | 80 | Not executed (no bytecode VM) |
| **Total baked** | **107.56 MiB** | **308.8 MiB** | | Image includes `main` + `daily` |

Loaded into the scanner (main + daily, PUA off): ~540k file hashes, ~102k body signatures, ~307k logical signatures. Resident set with that engine is about **1.4 GiB**.

## Development

```bash
cargo test
cargo bench              # engine + HTTP e2e
cargo bench --bench http # TCP loopback only
cargo run
```

Place CVD files in `DEFENDER_DB_DIR` or let the updater download them on first start.

## Benchmarks

Release mode, 4× x86_64, Criterion (this environment).

### Engine (in-process)

| Benchmark | Time | Throughput |
| --- | --- | --- |
| SHA-256 hash lookup (50k signatures) | 5.48 ns | 183 M lookups/s |
| Scan clean 64 KiB | 166 µs | 376 MiB/s |
| Scan EICAR (68 B) | 542 ns | 120 MiB/s |
| Scan EICAR embedded in 8 KiB | 21.3 µs | 369 MiB/s |
| Stream MD5+SHA1+SHA256 over 128 KiB | 330 µs | 378 MiB/s |
| CVD header parse + gzip/tar unpack (tiny) | 6.02 µs | |
| Scan via `ArcSwap` (hot-reload path) | 542 ns | |

### HTTP e2e (live TCP loopback)

`cargo bench --bench http` binds `127.0.0.1:0`, serves the real Axum router, and uses a keep-alive `reqwest` client.

Synthetic engine (10k hashes + EICAR body sig):

| Endpoint | Time | Throughput |
| --- | --- | --- |
| `GET /health` | 36.2 µs | 27.7 k req/s |
| `GET /info` | 36.4 µs | 27.5 k req/s |
| `POST /scan` EICAR | 44.8 µs | 22.3 k req/s |
| `POST /scan/hash` EICAR MD5 | 44.6 µs | 22.4 k req/s |
| `POST /scan/hashes` (3 lines) | 45.3 µs | 22.1 k req/s |
| `POST /scan` clean 1 KiB | 47.2 µs | 20.7 MiB/s |
| `POST /scan` clean 64 KiB | 241 µs | 259 MiB/s |
| `POST /scan` clean 1 MiB | 3.37 ms | 296 MiB/s |
| `POST /scan` EICAR ×32 concurrent | 583 µs / batch | **54.9 k req/s** |

Official `daily.cvd` over the same HTTP path:

| Endpoint | Time | Throughput |
| --- | --- | --- |
| `POST /scan` EICAR | 44.5 µs | 22.5 k req/s |
| `POST /scan/hash` EICAR MD5 | 43.6 µs | 22.9 k req/s |
| `POST /scan` clean 64 KiB | 667 µs | 93.7 MiB/s |
| `POST /scan` EICAR ×16 concurrent | 296 µs / batch | **54.0 k req/s** |

Tiny requests are loopback/HTTP-latency bound; large bodies are bounded by MD5+SHA1+SHA256. RSS tests (`tests/memory.rs`) stay stable across 20k scans and 200 engine swaps.

## Architecture

```
upload bytes ──► incremental MD5/SHA1/SHA256 + buffer
                      │
                      ▼
               hash maps (O(1))
                      │ miss
                      ▼
               PE section hashes
                      │ miss
                      ▼
               Aho-Corasick over NDB/LDB literals
                      │
                      ▼
               JSON { clean | infected }
```

The live engine is `ArcSwap<Engine>`. The updater never mutates a published engine in place.
