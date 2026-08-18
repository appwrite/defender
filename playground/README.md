# Defender UI

Web UI for the defender HTTP API. The browser talks to same-origin `/api/*` routes; the Node server proxies those to the scanner (`DEFENDER_URL`).

## Run with Docker Compose

From the repository root (first build compiles Rust and downloads ClamAV CVDs):

```bash
docker compose up --build
```

- Playground: http://127.0.0.1:3100 (`PLAYGROUND_PORT` overrides the host port)
- Defender API: http://127.0.0.1:8080

The playground waits until `GET /ready` succeeds so scans run against a loaded engine.

## Local development

Start defender, then the UI:

```bash
# terminal 1
DEFENDER_DB_DIR=./db cargo run

# terminal 2
cd playground
DEFENDER_URL=http://127.0.0.1:8080 npm run dev
```

`npm run dev` serves the UI on port 3000. After `npm run build`, `npm start` runs the production preview server on the same port.

## Parsed payloads

Scan responses are normalized in `src/lib/payload.ts`:

| API field | UI field | Meaning |
| --- | --- | --- |
| `result` | `result` | `clean` or `infected` |
| `signature` | `signature` | ClamAV signature name when infected |
| `size` | `size` | Bytes scanned or supplied hash size |
| `md5` / `sha1` / `sha256` | same | Hex digests (empty string if unused) |
| `duration_us` | `durationUs` | Engine time in microseconds |

Batch `POST /scan/hashes` items become rows with `result`, `hash`, `signature`, and `error`.

The EICAR test string is harmless and should always match in a stock ClamAV database.
