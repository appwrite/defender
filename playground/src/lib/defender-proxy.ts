function defenderBaseUrl(): string {
  return (process.env.DEFENDER_URL ?? "http://127.0.0.1:8080").replace(
    /\/$/,
    ""
  )
}

export async function proxyDefender(
  request: Request,
  path: string
): Promise<Response> {
  const target = `${defenderBaseUrl()}${path}${new URL(request.url).search}`
  const headers = new Headers()
  const contentType = request.headers.get("content-type")
  if (contentType) {
    headers.set("content-type", contentType)
  }

  try {
    const res = await fetch(target, {
      method: request.method,
      headers,
      body:
        request.method === "GET" || request.method === "HEAD"
          ? undefined
          : await request.arrayBuffer(),
    })
    const body = await res.arrayBuffer()
    const out = new Headers()
    const responseType = res.headers.get("content-type")
    if (responseType) {
      out.set("content-type", responseType)
    }
    out.set("x-defender-upstream", target.split("?")[0] ?? target)
    return new Response(body, { status: res.status, headers: out })
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error"
    return Response.json(
      {
        error: "defender unreachable",
        detail,
        upstream: defenderBaseUrl(),
      },
      { status: 502 }
    )
  }
}
