import { describe, expect, it } from "vitest"
import {
  formatBytes,
  formatDurationUs,
  hashAlgorithm,
  parseHashBatch,
  parseScanPayload,
  wrapParsed,
} from "./payload"

describe("parseScanPayload", () => {
  it("parses a clean scan response", () => {
    const payload = parseScanPayload({
      result: "clean",
      size: 11,
      md5: "abc",
      sha1: "def",
      sha256: "ghi",
      duration_us: 42,
    })
    expect(payload).toEqual({
      result: "clean",
      signature: null,
      size: 11,
      md5: "abc",
      sha1: "def",
      sha256: "ghi",
      durationUs: 42,
    })
  })

  it("parses an infected scan response", () => {
    const payload = parseScanPayload({
      result: "infected",
      signature: "Eicar-Test-Signature",
      size: 68,
      md5: "44d88612fea8a8f36de82e1278abb02f",
      sha1: "sha1",
      sha256: "sha256",
      duration_us: 12,
    })
    expect(payload?.result).toBe("infected")
    expect(payload?.signature).toBe("Eicar-Test-Signature")
  })

  it("rejects unknown result values", () => {
    expect(parseScanPayload({ result: "maybe" })).toBeNull()
  })
})

describe("parseHashBatch", () => {
  it("parses mixed batch lines", () => {
    const items = parseHashBatch([
      { result: "infected", hash: "aa", signature: "Eicar" },
      { result: "clean", hash: "bb" },
      { error: "invalid json", line: "{" },
    ])
    expect(items).toHaveLength(3)
    expect(items?.[0]?.result).toBe("infected")
    expect(items?.[1]?.result).toBe("clean")
    expect(items?.[2]?.error).toBe("invalid json")
  })
})

describe("wrapParsed", () => {
  it("surfaces API errors instead of a payload", () => {
    const parsed = wrapParsed(
      413,
      { error: "payload too large" },
      parseScanPayload
    )
    expect(parsed.ok).toBe(false)
    expect(parsed.error?.error).toBe("payload too large")
    expect(parsed.payload).toBeNull()
  })
})

describe("formatters", () => {
  it("formats bytes and durations", () => {
    expect(formatBytes(68)).toBe("68 B")
    expect(formatBytes(2048)).toBe("2.0 KiB")
    expect(formatDurationUs(42)).toBe("42 µs")
    expect(formatDurationUs(2500)).toBe("2.50 ms")
  })

  it("detects hash algorithms by length", () => {
    expect(hashAlgorithm("44d88612fea8a8f36de82e1278abb02f")).toBe("md5")
    expect(hashAlgorithm("a".repeat(40))).toBe("sha1")
    expect(hashAlgorithm("b".repeat(64))).toBe("sha256")
    expect(hashAlgorithm("nope")).toBe("unknown")
  })
})
