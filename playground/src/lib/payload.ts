export const EICAR =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

export const EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"

export type ScanVerdict = "clean" | "infected"

export interface ScanPayload {
  result: ScanVerdict
  signature: string | null
  size: number
  md5: string
  sha1: string
  sha256: string
  durationUs: number
}

export interface HealthPayload {
  status: string
}

export interface ReadyPayload {
  ready: boolean
  fileHashes: number
  bodySigs: number
}

export interface DatabasePayload {
  name: string
  version: number
  headerSignatures: number
  flevel: number
  builder: string
  time: string
  md5: string
}

export interface InfoPayload {
  databases: DatabasePayload[]
  signatures: {
    fileHash: number
    sectionHash: number
    body: number
    logical: number
    skipped: number
  }
  loadedAtUnix: number
}

export interface HashBatchItem {
  result: ScanVerdict | null
  hash: string | null
  signature: string | null
  error: string | null
  line: string | null
}

export interface ApiErrorPayload {
  error: string
  detail?: string
}

export interface ParsedResponse<T> {
  ok: boolean
  status: number
  payload: T | null
  error: ApiErrorPayload | null
  raw: unknown
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

export function parseApiError(value: unknown): ApiErrorPayload | null {
  if (!isRecord(value)) return null
  const error = asString(value.error)
  if (!error) return null
  const detail = asString(value.detail)
  return detail ? { error, detail } : { error }
}

export function parseScanPayload(value: unknown): ScanPayload | null {
  if (!isRecord(value)) return null
  const result = value.result
  if (result !== "clean" && result !== "infected") return null
  const signature = value.signature
  return {
    result,
    signature: typeof signature === "string" ? signature : null,
    size: asNumber(value.size),
    md5: asString(value.md5),
    sha1: asString(value.sha1),
    sha256: asString(value.sha256),
    durationUs: asNumber(value.duration_us),
  }
}

export function parseHealthPayload(value: unknown): HealthPayload | null {
  if (!isRecord(value)) return null
  const status = asString(value.status)
  if (!status) return null
  return { status }
}

export function parseReadyPayload(value: unknown): ReadyPayload | null {
  if (!isRecord(value)) return null
  if (typeof value.ready !== "boolean") return null
  return {
    ready: value.ready,
    fileHashes: asNumber(value.file_hashes),
    bodySigs: asNumber(value.body_sigs),
  }
}

export function parseInfoPayload(value: unknown): InfoPayload | null {
  if (
    !isRecord(value) ||
    !Array.isArray(value.databases) ||
    !isRecord(value.signatures)
  ) {
    return null
  }
  return {
    databases: value.databases.flatMap((entry) => {
      if (!isRecord(entry)) return []
      return [
        {
          name: asString(entry.name, "unknown"),
          version: asNumber(entry.version),
          headerSignatures: asNumber(entry.header_signatures),
          flevel: asNumber(entry.flevel),
          builder: asString(entry.builder),
          time: asString(entry.time),
          md5: asString(entry.md5),
        },
      ]
    }),
    signatures: {
      fileHash: asNumber(value.signatures.file_hash),
      sectionHash: asNumber(value.signatures.section_hash),
      body: asNumber(value.signatures.body),
      logical: asNumber(value.signatures.logical),
      skipped: asNumber(value.signatures.skipped),
    },
    loadedAtUnix: asNumber(value.loaded_at_unix),
  }
}

export function parseHashBatch(value: unknown): HashBatchItem[] | null {
  if (!Array.isArray(value)) return null
  return value.map((entry) => {
    if (!isRecord(entry)) {
      return {
        result: null,
        hash: null,
        signature: null,
        error: "invalid batch item",
        line: null,
      }
    }
    const result = entry.result
    return {
      result: result === "clean" || result === "infected" ? result : null,
      hash: typeof entry.hash === "string" ? entry.hash : null,
      signature: typeof entry.signature === "string" ? entry.signature : null,
      error: typeof entry.error === "string" ? entry.error : null,
      line: typeof entry.line === "string" ? entry.line : null,
    }
  })
}

export function wrapParsed<T>(
  status: number,
  raw: unknown,
  parser: (value: unknown) => T | null
): ParsedResponse<T> {
  const error = parseApiError(raw)
  const payload = parser(raw)
  return {
    ok: status >= 200 && status < 300 && payload !== null && error === null,
    status,
    payload,
    error,
    raw,
  }
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`
}

export function formatDurationUs(durationUs: number): string {
  if (durationUs < 1000) return `${durationUs} µs`
  if (durationUs < 1_000_000) return `${(durationUs / 1000).toFixed(2)} ms`
  return `${(durationUs / 1_000_000).toFixed(2)} s`
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat("en-US").format(n)
}

export function formatUnix(seconds: number): string {
  if (!seconds) return "unknown"
  return new Date(seconds * 1000)
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d+Z$/, " UTC")
}

export function hashAlgorithm(
  hex: string
): "md5" | "sha1" | "sha256" | "unknown" {
  const value = hex.trim()
  if (/^[0-9a-fA-F]{32}$/.test(value)) return "md5"
  if (/^[0-9a-fA-F]{40}$/.test(value)) return "sha1"
  if (/^[0-9a-fA-F]{64}$/.test(value)) return "sha256"
  return "unknown"
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
}
