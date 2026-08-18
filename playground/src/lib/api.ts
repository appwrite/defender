export interface ApiCall {
  status: number
  ok: boolean
  json: unknown
  raw: string
  elapsedMs: number
  method: string
  path: string
}

export async function callDefender(
  path: string,
  init?: RequestInit
): Promise<ApiCall> {
  const method = init?.method ?? "GET"
  const started = performance.now()
  const res = await fetch(`/api${path}`, init)
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
    method,
    path: `/api${path}`,
  }
}
