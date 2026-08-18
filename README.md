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

## Development

```bash
cargo test
cargo bench
cargo run
```

Place CVD files in `DEFENDER_DB_DIR` or let the updater download them on first start.

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
