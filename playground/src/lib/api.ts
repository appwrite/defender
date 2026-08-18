export interface ApiCall {
  status: number
  ok: boolean
  json: unknown
  raw: string
  elapsedMs: number
  method: string
  path: string
}

function scannerUrl(path: string): string {
  if (typeof window !== "undefined") {
    return `/api${path}`
  }
  return `${(process.env.DEFENDER_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "")}${path}`
}

async function readApiCall(
  path: string,
  init: RequestInit | undefined,
  res: Response,
  started: number
): Promise<ApiCall> {
  const raw = await res.text()
  let json: unknown = raw
  try {
    json = raw ? JSON.parse(raw) : null
  } catch {
    json = raw
  }
  return {
    status: res.status,
    ok: res.ok,
    json,
    raw,
    elapsedMs: performance.now() - started,
    method: init?.method ?? "GET",
    path: `/api${path}`,
  }
}

export async function callDefender(
  path: string,
  init?: RequestInit
): Promise<ApiCall> {
  const started = performance.now()
  const res = await fetch(scannerUrl(path), init)
  return readApiCall(path, init, res, started)
}

export async function fetchScanner(path: string): Promise<ApiCall | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 1500)
  const started = performance.now()
  try {
    const res = await fetch(scannerUrl(path), { signal: controller.signal })
    return await readApiCall(path, undefined, res, started)
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

export async function fetchScannerSnapshot(): Promise<{
  health: ApiCall | null
  ready: ApiCall | null
  info: ApiCall | null
}> {
  const [health, ready, info] = await Promise.all([
    fetchScanner("/health"),
    fetchScanner("/ready"),
    fetchScanner("/info"),
  ])
  return { health, ready, info }
}
