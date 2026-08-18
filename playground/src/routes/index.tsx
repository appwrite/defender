import { useMutation, useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import {
  BugIcon,
  FileScanIcon,
  HashIcon,
  ListIcon,
  ShieldCheckIcon,
} from "lucide-react"
import { useState, type ReactNode } from "react"
import { toast } from "sonner"

import {
  HashBatchCard,
  RawJsonCard,
  ScanPayloadCard,
} from "@/components/scan-result"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Spinner } from "@/components/ui/spinner"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { callDefender, type ApiCall } from "@/lib/api"
import {
  EICAR,
  EICAR_MD5,
  formatCount,
  formatUnix,
  hashAlgorithm,
  parseHashBatch,
  parseHealthPayload,
  parseInfoPayload,
  parseReadyPayload,
  parseScanPayload,
  wrapParsed,
} from "@/lib/payload"

export const Route = createFileRoute("/")({ component: Playground })

type BodyMode = "raw" | "multipart"

function Playground() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => callDefender("/health"),
    refetchInterval: 5_000,
  })
  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => callDefender("/ready"),
    refetchInterval: 5_000,
  })
  const info = useQuery({
    queryKey: ["info"],
    queryFn: () => callDefender("/info"),
    refetchInterval: 15_000,
  })

  const healthPayload = health.data
    ? parseHealthPayload(health.data.json)
    : null
  const readyParsed = ready.data ? parseReadyPayload(ready.data.json) : null
  const infoParsed = info.data ? parseInfoPayload(info.data.json) : null
  const upstreamError =
    parseHealthPayload(health.data?.json)?.status === "ok"
      ? null
      : health.data && health.data.status >= 400
        ? String(
            (health.data.json as { error?: string } | null)?.error ??
              `HTTP ${health.data.status}`
          )
        : health.error
          ? health.error.message
          : null

  return (
    <main className="mx-auto flex min-h-svh max-w-5xl flex-col gap-6 p-6">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="font-heading text-2xl font-medium">
            Defender playground
          </h1>
          <Badge variant="outline">TanStack Start + shadcn</Badge>
        </div>
        <p className="max-w-2xl text-sm text-muted-foreground">
          Send files and hashes to the Appwrite defender HTTP API. This UI
          proxies requests to the scanner container so you can inspect the
          parsed JSON payload.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge
            label="health"
            ok={healthPayload?.status === "ok"}
            loading={health.isLoading}
          />
          <StatusBadge
            label="ready"
            ok={readyParsed?.ready === true}
            loading={ready.isLoading}
          />
          {readyParsed ? (
            <Badge variant="secondary">
              {formatCount(readyParsed.fileHashes)} file hashes
            </Badge>
          ) : null}
        </div>
      </header>

      {upstreamError ? (
        <Alert variant="destructive">
          <AlertTitle>Defender is unreachable</AlertTitle>
          <AlertDescription>
            {upstreamError}. Start the stack with{" "}
            <code className="font-mono">docker compose up --build</code> or
            point <code className="font-mono">DEFENDER_URL</code> at a running
            scanner.
          </AlertDescription>
        </Alert>
      ) : null}

      {infoParsed ? (
        <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="File hashes"
            value={formatCount(infoParsed.signatures.fileHash)}
          />
          <StatCard
            label="PE section hashes"
            value={formatCount(infoParsed.signatures.sectionHash)}
          />
          <StatCard
            label="Body signatures"
            value={formatCount(infoParsed.signatures.body)}
          />
          <StatCard
            label="Logical signatures"
            value={formatCount(infoParsed.signatures.logical)}
          />
        </section>
      ) : null}

      {infoParsed?.databases.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Loaded databases</CardTitle>
            <CardDescription>
              Engine loaded {formatUnix(infoParsed.loadedAtUnix)}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {infoParsed.databases.map((db) => (
              <div
                key={`${db.name}-${db.version}`}
                className="flex flex-col gap-1"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium">{db.name}.cvd</p>
                  <Badge variant="outline">v{db.version}</Badge>
                  <Badge variant="secondary">
                    {formatCount(db.headerSignatures)} signatures
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {db.builder} · {db.time} · MD5 {db.md5}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      <Tabs defaultValue="file">
        <TabsList>
          <TabsTrigger value="file">
            <FileScanIcon data-icon="inline-start" />
            Scan file
          </TabsTrigger>
          <TabsTrigger value="hash">
            <HashIcon data-icon="inline-start" />
            Hash lookup
          </TabsTrigger>
          <TabsTrigger value="batch">
            <ListIcon data-icon="inline-start" />
            Batch hashes
          </TabsTrigger>
          <TabsTrigger value="docs">Docs</TabsTrigger>
        </TabsList>
        <TabsContent value="file">
          <ScanFilePanel />
        </TabsContent>
        <TabsContent value="hash">
          <HashPanel />
        </TabsContent>
        <TabsContent value="batch">
          <BatchPanel />
        </TabsContent>
        <TabsContent value="docs">
          <DocsPanel />
        </TabsContent>
      </Tabs>
    </main>
  )
}

function StatusBadge({
  label,
  ok,
  loading,
}: {
  label: string
  ok: boolean
  loading: boolean
}) {
  if (loading) {
    return (
      <Badge variant="outline">
        <Spinner />
        {label}
      </Badge>
    )
  }
  return (
    <Badge variant={ok ? "secondary" : "destructive"}>
      {label}: {ok ? "ok" : "down"}
    </Badge>
  )
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle>{value}</CardTitle>
      </CardHeader>
    </Card>
  )
}

function ScanFilePanel() {
  const [mode, setMode] = useState<BodyMode>("raw")
  const [file, setFile] = useState<File | null>(null)
  const [call, setCall] = useState<ApiCall | null>(null)

  const scan = useMutation({
    mutationFn: async (payload: { file: File; mode: BodyMode }) => {
      if (payload.mode === "multipart") {
        const body = new FormData()
        body.append("file", payload.file, payload.file.name)
        return callDefender("/scan", { method: "POST", body })
      }
      return callDefender("/scan", {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: payload.file,
      })
    },
    onSuccess: (result) => {
      setCall(result)
      const parsed = wrapParsed(result.status, result.json, parseScanPayload)
      if (parsed.payload?.result === "infected") {
        toast.warning(
          `Infected: ${parsed.payload.signature ?? "signature matched"}`
        )
      } else if (parsed.ok) {
        toast.success("File is clean")
      } else {
        toast.error(parsed.error?.error ?? `Scan failed (${result.status})`)
      }
    },
    onError: (error) => toast.error(error.message),
  })

  const parsed = call
    ? wrapParsed(call.status, call.json, parseScanPayload)
    : null

  return (
    <div className="flex flex-col gap-4 pt-4">
      <Card>
        <CardHeader>
          <CardTitle>POST /scan</CardTitle>
          <CardDescription>
            Stream a file as raw bytes or multipart form-data. Defender hashes
            the body incrementally and returns a parsed verdict.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-5"
            onSubmit={(event) => {
              event.preventDefault()
              if (!file) {
                toast.error("Choose a file first")
                return
              }
              scan.mutate({ file, mode })
            }}
          >
            <FieldGroup>
              <Field>
                <FieldLabel>Body format</FieldLabel>
                <ToggleGroup
                  value={[mode]}
                  onValueChange={(next) => {
                    const value = next[0]
                    if (value === "raw" || value === "multipart") setMode(value)
                  }}
                >
                  <ToggleGroupItem value="raw">Raw bytes</ToggleGroupItem>
                  <ToggleGroupItem value="multipart">Multipart</ToggleGroupItem>
                </ToggleGroup>
                <FieldDescription>
                  Raw uses{" "}
                  <code className="font-mono">application/octet-stream</code>.
                  Multipart sends a <code className="font-mono">file</code>{" "}
                  field.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="scan-file">File</FieldLabel>
                <Input
                  id="scan-file"
                  type="file"
                  onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                />
              </Field>
            </FieldGroup>
            <div className="flex flex-wrap gap-2">
              <Button type="submit" disabled={scan.isPending}>
                {scan.isPending ? (
                  <Spinner />
                ) : (
                  <FileScanIcon data-icon="inline-start" />
                )}
                Scan file
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={scan.isPending}
                onClick={() => {
                  const eicar = new File([EICAR], "eicar.com", {
                    type: "text/plain",
                  })
                  setFile(eicar)
                  scan.mutate({ file: eicar, mode })
                }}
              >
                <BugIcon data-icon="inline-start" />
                Scan EICAR
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        emptyTitle="No scan yet"
        emptyDescription="Upload a file or scan the EICAR test string. The parsed payload will appear here."
        call={call}
        parsedOk={parsed?.ok ?? false}
        error={parsed?.error?.error}
      >
        {parsed?.payload && call ? (
          <ScanPayloadCard call={call} payload={parsed.payload} />
        ) : null}
        {call ? <RawJsonCard value={call.json} /> : null}
      </ResultArea>
    </div>
  )
}

function HashPanel() {
  const [digest, setDigest] = useState(EICAR_MD5)
  const [size, setSize] = useState("68")
  const [call, setCall] = useState<ApiCall | null>(null)
  const algo = hashAlgorithm(digest)

  const lookup = useMutation({
    mutationFn: async () => {
      const body: Record<string, string | number> = { hash: digest.trim() }
      const parsedSize = Number(size)
      if (Number.isFinite(parsedSize) && size.trim() !== "") {
        body.size = parsedSize
      }
      return callDefender("/scan/hash", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      })
    },
    onSuccess: (result) => {
      setCall(result)
      const parsed = wrapParsed(result.status, result.json, parseScanPayload)
      if (parsed.payload?.result === "infected") {
        toast.warning(`Hit: ${parsed.payload.signature ?? "infected"}`)
      } else if (parsed.ok) {
        toast.success("Hash not listed")
      } else {
        toast.error(parsed.error?.error ?? `Lookup failed (${result.status})`)
      }
    },
    onError: (error) => toast.error(error.message),
  })

  const parsed = call
    ? wrapParsed(call.status, call.json, parseScanPayload)
    : null

  return (
    <div className="flex flex-col gap-4 pt-4">
      <Card>
        <CardHeader>
          <CardTitle>POST /scan/hash</CardTitle>
          <CardDescription>
            Look up a single MD5, SHA-1, or SHA-256 digest. Size is optional and
            used when the signature is size-specific.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-5"
            onSubmit={(event) => {
              event.preventDefault()
              lookup.mutate()
            }}
          >
            <FieldGroup>
              <Field data-invalid={algo === "unknown" || undefined}>
                <FieldLabel htmlFor="digest">Hash</FieldLabel>
                <Input
                  id="digest"
                  aria-invalid={algo === "unknown"}
                  value={digest}
                  onChange={(event) => setDigest(event.target.value)}
                  placeholder="MD5, SHA-1, or SHA-256 hex"
                />
                <FieldDescription>
                  Detected algorithm:{" "}
                  {algo === "unknown" ? "unknown length" : algo.toUpperCase()}
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="hash-size">Size (optional)</FieldLabel>
                <Input
                  id="hash-size"
                  inputMode="numeric"
                  value={size}
                  onChange={(event) => setSize(event.target.value)}
                />
              </Field>
            </FieldGroup>
            <div className="flex flex-wrap gap-2">
              <Button
                type="submit"
                disabled={lookup.isPending || algo === "unknown"}
              >
                {lookup.isPending ? (
                  <Spinner />
                ) : (
                  <HashIcon data-icon="inline-start" />
                )}
                Look up hash
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setDigest(EICAR_MD5)
                  setSize("68")
                }}
              >
                Use EICAR MD5
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        emptyTitle="No lookup yet"
        emptyDescription="Paste a digest or use the EICAR MD5 to see a parsed hash verdict."
        call={call}
        parsedOk={parsed?.ok ?? false}
        error={parsed?.error?.error}
      >
        {parsed?.payload && call ? (
          <ScanPayloadCard call={call} payload={parsed.payload} />
        ) : null}
        {call ? <RawJsonCard value={call.json} /> : null}
      </ResultArea>
    </div>
  )
}

function BatchPanel() {
  const [lines, setLines] = useState(
    `${EICAR_MD5}\n00000000000000000000000000000000\n`
  )
  const [call, setCall] = useState<ApiCall | null>(null)

  const lookup = useMutation({
    mutationFn: () =>
      callDefender("/scan/hashes", {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: lines,
      }),
    onSuccess: (result) => {
      setCall(result)
      const items = parseHashBatch(result.json)
      if (!result.ok) {
        toast.error(`Batch failed (${result.status})`)
      } else if (items) {
        toast.success(`Looked up ${items.length} hashes`)
      }
    },
    onError: (error) => toast.error(error.message),
  })

  const items = call ? parseHashBatch(call.json) : null

  return (
    <div className="flex flex-col gap-4 pt-4">
      <Card>
        <CardHeader>
          <CardTitle>POST /scan/hashes</CardTitle>
          <CardDescription>
            One digest per line, optional{" "}
            <code className="font-mono">algo:hex</code>, or NDJSON objects with{" "}
            <code className="font-mono">md5</code>/
            <code className="font-mono">sha1</code>/
            <code className="font-mono">sha256</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-5"
            onSubmit={(event) => {
              event.preventDefault()
              lookup.mutate()
            }}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="batch">Hashes</FieldLabel>
                <Textarea
                  id="batch"
                  rows={8}
                  className="font-mono"
                  value={lines}
                  onChange={(event) => setLines(event.target.value)}
                />
              </Field>
            </FieldGroup>
            <Button type="submit" disabled={lookup.isPending}>
              {lookup.isPending ? (
                <Spinner />
              ) : (
                <ListIcon data-icon="inline-start" />
              )}
              Scan hashes
            </Button>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        emptyTitle="No batch yet"
        emptyDescription="Submit one digest per line. Infected, clean, and error rows are parsed into a table."
        call={call}
        parsedOk={Boolean(items)}
        error={call && !call.ok ? `HTTP ${call.status}` : undefined}
      >
        {items && call ? <HashBatchCard call={call} items={items} /> : null}
        {call ? <RawJsonCard value={call.json} /> : null}
      </ResultArea>
    </div>
  )
}

function DocsPanel() {
  return (
    <div className="flex flex-col gap-4 pt-4">
      <Card>
        <CardHeader>
          <CardTitle>HTTP API</CardTitle>
          <CardDescription>
            The playground calls same-origin{" "}
            <code className="font-mono">/api/*</code> routes, which proxy to
            defender (<code className="font-mono">DEFENDER_URL</code>, default{" "}
            <code className="font-mono">http://127.0.0.1:8080</code>).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 text-sm">
          <Endpoint
            method="GET"
            path="/health"
            body="—"
            response='{ "status": "ok" }'
          />
          <Separator />
          <Endpoint
            method="GET"
            path="/ready"
            body="—"
            response='{ "ready": true, "file_hashes": 0, "body_sigs": 0 }'
          />
          <Separator />
          <Endpoint
            method="GET"
            path="/info"
            body="—"
            response="databases[], signatures, loaded_at_unix"
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan"
            body="raw bytes or multipart file"
            response='{ "result": "clean"|"infected", "signature"?, "size", "md5", "sha1", "sha256", "duration_us" }'
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan/hash"
            body='{ "md5"|"sha1"|"sha256"|"hash", "size"? }'
            response="Same scan payload. Empty hash fields are omitted for unused algorithms."
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan/hashes"
            body="one digest per line, algo:hex, or NDJSON"
            response='[{ "result", "hash", "signature"? }]'
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>EICAR</CardTitle>
          <CardDescription>
            The EICAR test file is harmless text that every ClamAV database
            should detect. It is not malware.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <p className="font-mono text-xs break-all">{EICAR}</p>
          <p className="text-sm text-muted-foreground">MD5 {EICAR_MD5}</p>
        </CardContent>
      </Card>
    </div>
  )
}

function Endpoint({
  method,
  path,
  body,
  response,
}: {
  method: string
  path: string
  body: string
  response: string
}) {
  return (
    <div className="flex flex-col gap-1">
      <p className="font-mono text-sm">
        <Badge variant="outline">{method}</Badge> {path}
      </p>
      <p className="text-muted-foreground">Request: {body}</p>
      <p className="text-muted-foreground">Response: {response}</p>
    </div>
  )
}

function ResultArea({
  emptyTitle,
  emptyDescription,
  call,
  parsedOk,
  error,
  children,
}: {
  emptyTitle: string
  emptyDescription: string
  call: ApiCall | null
  parsedOk: boolean
  error?: string
  children: ReactNode
}) {
  if (!call) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ShieldCheckIcon />
          </EmptyMedia>
          <EmptyTitle>{emptyTitle}</EmptyTitle>
          <EmptyDescription>{emptyDescription}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Request failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {!parsedOk && !error ? (
        <Alert>
          <AlertTitle>Unparsed payload</AlertTitle>
          <AlertDescription>
            HTTP {call.status}. The body did not match the expected defender
            JSON shape.
          </AlertDescription>
        </Alert>
      ) : null}
      {children}
    </div>
  )
}
