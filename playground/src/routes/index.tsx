import { useMutation, useQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import {
  CircleHelpIcon,
  FileScanIcon,
  HashIcon,
  ListIcon,
  ShieldCheckIcon,
} from "lucide-react"
import { useState, type ReactNode } from "react"
import { toast } from "sonner"

import {
  HashBatchCard,
  ScanPayloadCard,
  TechnicalDetails,
} from "@/components/scan-result"
import { ThemeToggle } from "@/components/theme-toggle"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { callDefender, fetchScannerSnapshot, type ApiCall } from "@/lib/api"
import {
  EICAR,
  EICAR_MD5,
  formatBytes,
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

export const Route = createFileRoute("/")({
  loader: fetchScannerSnapshot,
  component: App,
})

function databaseFileName(name: string) {
  return /\.(cvd|cld)$/i.test(name) ? name : `${name}.cvd`
}

type BodyMode = "raw" | "multipart"

function App() {
  const initial = Route.useLoaderData()
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => callDefender("/health"),
    refetchInterval: 5_000,
    ...(initial.health ? { initialData: initial.health } : {}),
  })
  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => callDefender("/ready"),
    refetchInterval: 5_000,
    ...(initial.ready ? { initialData: initial.ready } : {}),
  })
  const info = useQuery({
    queryKey: ["info"],
    queryFn: () => callDefender("/info"),
    refetchInterval: 15_000,
    ...(initial.info ? { initialData: initial.info } : {}),
  })

  const healthPayload = health.data
    ? parseHealthPayload(health.data.json)
    : null
  const readyParsed = ready.data ? parseReadyPayload(ready.data.json) : null
  const infoParsed = info.data ? parseInfoPayload(info.data.json) : null
  const healthy = healthPayload?.status === "ok"
  const scannerReady = readyParsed?.ready === true
  const upstreamError = healthy
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
    <div className="flex min-h-svh flex-col bg-muted/30">
      <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between gap-3 px-6">
          <div className="flex items-center gap-2">
            <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground [&_svg]:size-4">
              <ShieldCheckIcon />
            </span>
            <div className="flex flex-col">
              <p className="font-heading text-sm leading-none font-medium">
                Appwrite Defender
              </p>
              <p className="text-xs text-muted-foreground">Virus scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex h-5 min-w-52 items-center justify-end">
              <ScannerStatus
                loading={
                  (health.isPending && !health.isError) ||
                  (ready.isPending && !ready.isError)
                }
                healthy={healthy}
                ready={scannerReady}
                hashes={readyParsed?.fileHashes}
              />
            </div>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-8 px-6 py-8">
        <section className="flex max-w-2xl flex-col gap-2">
          <h1 className="font-heading text-2xl font-medium tracking-tight">
            Scan a file or hash
          </h1>
          <p className="text-sm text-muted-foreground">
            Check files against the official ClamAV databases. Upload something
            to get a clear verdict, or look up hashes if you already have
            fingerprints.
          </p>
        </section>

        {upstreamError ? (
          <Alert variant="destructive">
            <AlertTitle>Scanner is offline</AlertTitle>
            <AlertDescription>
              Defender is not reachable. Start it with{" "}
              <code className="font-mono">docker compose up --build</code>, or
              set <code className="font-mono">DEFENDER_URL</code> to a running
              scanner. {upstreamError}
            </AlertDescription>
          </Alert>
        ) : null}

        {infoParsed ? (
          <section className="grid min-h-[4.75rem] gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="File hashes"
              value={formatCount(infoParsed.signatures.fileHash)}
              hint="Fingerprints of entire files (MD5, SHA-1, SHA-256)."
            />
            <StatCard
              label="Windows sections"
              value={formatCount(infoParsed.signatures.sectionHash)}
              hint="Hashes of sections inside Windows executables (PE files)."
            />
            <StatCard
              label="Byte patterns"
              value={formatCount(infoParsed.signatures.body)}
              hint="Content signatures that match sequences of bytes inside a file."
            />
            <StatCard
              label="Logical rules"
              value={formatCount(infoParsed.signatures.logical)}
              hint="Multi-condition signatures that combine several matches."
            />
          </section>
        ) : info.isError ? null : (
          <section className="grid min-h-[4.75rem] gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
          </section>
        )}

        {infoParsed?.databases.length ? (
          <Card className="min-h-60">
            <CardHeader>
              <CardTitle>Signature databases</CardTitle>
              <CardDescription>
                Official ClamAV sets currently loaded into the scanner. Last
                loaded {formatUnix(infoParsed.loadedAtUnix)}.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {infoParsed.databases.map((db) => (
                <div
                  key={`${db.name}-${db.version}`}
                  className="flex flex-wrap items-center gap-2"
                >
                  <p className="font-medium">{databaseFileName(db.name)}</p>
                  <Badge variant="outline">v{db.version}</Badge>
                  <Badge variant="secondary">
                    {formatCount(db.headerSignatures)} signatures
                  </Badge>
                </div>
              ))}
            </CardContent>
            <CardFooter className="flex-col items-stretch">
              <Accordion className="w-full">
                <AccordionItem value="db-details" className="border-none">
                  <AccordionTrigger>Database details</AccordionTrigger>
                  <AccordionContent>
                    <div className="flex flex-col gap-3">
                      {infoParsed.databases.map((db) => (
                        <div
                          key={`${db.name}-${db.version}-detail`}
                          className="flex flex-col gap-1"
                        >
                          <p className="font-medium">
                            {databaseFileName(db.name)}
                          </p>
                          <p className="font-mono text-xs break-all text-muted-foreground">
                            {db.builder} · {db.time} · MD5 {db.md5}
                          </p>
                        </div>
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </CardFooter>
          </Card>
        ) : infoParsed || info.isError ? null : (
          <Card className="min-h-60">
            <CardHeader>
              <Skeleton className="h-5 w-40" />
              <Skeleton className="h-4 w-full max-w-md" />
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <Skeleton className="h-5 w-48" />
              <Skeleton className="h-5 w-56" />
            </CardContent>
            <CardFooter>
              <Skeleton className="h-5 w-36" />
            </CardFooter>
          </Card>
        )}

        <Tabs defaultValue="file">
          <TabsList variant="line" className="h-auto w-full justify-start">
            <TabsTrigger value="file">
              <FileScanIcon data-icon="inline-start" />
              File
            </TabsTrigger>
            <TabsTrigger value="hash">
              <HashIcon data-icon="inline-start" />
              Hash
            </TabsTrigger>
            <TabsTrigger value="batch">
              <ListIcon data-icon="inline-start" />
              Batch
            </TabsTrigger>
            <TabsTrigger value="api">API</TabsTrigger>
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
          <TabsContent value="api">
            <ApiPanel />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}

function Hint({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant="ghost"
            size="icon-xs"
            aria-label="More information"
          />
        }
      >
        <CircleHelpIcon />
      </TooltipTrigger>
      <TooltipContent>{text}</TooltipContent>
    </Tooltip>
  )
}

function ScannerStatus({
  loading,
  healthy,
  ready,
  hashes,
}: {
  loading: boolean
  healthy: boolean
  ready: boolean
  hashes?: number
}) {
  if (loading) {
    return (
      <Badge variant="outline">
        <Spinner />
        Connecting
      </Badge>
    )
  }
  if (!healthy) {
    return <Badge variant="destructive">Offline</Badge>
  }
  if (!ready) {
    return (
      <Badge variant="outline">
        <Spinner />
        Loading signatures
      </Badge>
    )
  }
  return (
    <Badge variant="secondary">
      Ready
      {typeof hashes === "number" ? ` · ${formatCount(hashes)} hashes` : ""}
    </Badge>
  )
}

function StatCardSkeleton() {
  return (
    <Card size="sm" className="h-[4.75rem]">
      <CardHeader>
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-5 w-20" />
      </CardHeader>
    </Card>
  )
}

function StatCard({
  label,
  value,
  hint,
}: {
  label: string
  value: string
  hint: string
}) {
  return (
    <Card size="sm" className="h-[4.75rem]">
      <CardHeader>
        <CardDescription className="flex h-6 items-center gap-1">
          {label}
          <Hint text={hint} />
        </CardDescription>
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
          <CardTitle>Scan a file</CardTitle>
          <CardDescription>
            Upload a file to check it for known malware. Defender streams the
            bytes and never stores the upload.
          </CardDescription>
          <CardAction>
            <Badge variant="outline">POST /scan</Badge>
          </CardAction>
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
                <FieldLabel htmlFor="scan-file">File</FieldLabel>
                <div
                  className="flex flex-col gap-3 rounded-xl border border-dashed p-4"
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault()
                    const next = event.dataTransfer.files[0]
                    if (next) setFile(next)
                  }}
                >
                  <Input
                    id="scan-file"
                    type="file"
                    onChange={(event) =>
                      setFile(event.target.files?.[0] ?? null)
                    }
                  />
                  <FieldDescription>
                    {file
                      ? `${file.name} · ${formatBytes(file.size)}`
                      : "Or drop a file here."}
                  </FieldDescription>
                </div>
              </Field>
              <Accordion>
                <AccordionItem value="advanced">
                  <AccordionTrigger>Advanced</AccordionTrigger>
                  <AccordionContent>
                    <Field>
                      <FieldLabel>How the file is sent</FieldLabel>
                      <ToggleGroup
                        value={[mode]}
                        onValueChange={(next) => {
                          const value = next[0]
                          if (value === "raw" || value === "multipart") {
                            setMode(value)
                          }
                        }}
                      >
                        <ToggleGroupItem value="raw">Raw bytes</ToggleGroupItem>
                        <ToggleGroupItem value="multipart">
                          Multipart
                        </ToggleGroupItem>
                      </ToggleGroup>
                      <FieldDescription>
                        Raw uses{" "}
                        <code className="font-mono">
                          application/octet-stream
                        </code>
                        . Multipart sends a{" "}
                        <code className="font-mono">file</code> field.
                      </FieldDescription>
                    </Field>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
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
                Try a safe test
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        call={call}
        parsedOk={parsed?.ok ?? false}
        error={parsed?.error?.error}
      >
        {parsed?.payload && call ? (
          <ScanPayloadCard call={call} payload={parsed.payload} />
        ) : null}
      </ResultArea>
    </div>
  )
}

function HashPanel() {
  const [digest, setDigest] = useState("")
  const [size, setSize] = useState("")
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
          <CardTitle>Look up a hash</CardTitle>
          <CardDescription>
            Check an MD5, SHA-1, or SHA-256 fingerprint without uploading the
            file.
          </CardDescription>
          <CardAction>
            <Badge variant="outline">POST /scan/hash</Badge>
          </CardAction>
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
              <Field
                data-invalid={
                  (digest !== "" && algo === "unknown") || undefined
                }
              >
                <FieldLabel htmlFor="digest">Hash</FieldLabel>
                <Input
                  id="digest"
                  aria-invalid={digest !== "" && algo === "unknown"}
                  value={digest}
                  onChange={(event) => setDigest(event.target.value)}
                  placeholder="Paste an MD5, SHA-1, or SHA-256 hex digest"
                />
                <FieldDescription>
                  {digest === ""
                    ? "32, 40, or 64 hexadecimal characters."
                    : algo === "unknown"
                      ? "This does not look like MD5, SHA-1, or SHA-256."
                      : `Detected ${algo.toUpperCase()}.`}
                </FieldDescription>
              </Field>
              <Accordion>
                <AccordionItem value="advanced">
                  <AccordionTrigger>Advanced</AccordionTrigger>
                  <AccordionContent>
                    <Field>
                      <FieldLabel htmlFor="hash-size">
                        File size (optional)
                      </FieldLabel>
                      <Input
                        id="hash-size"
                        inputMode="numeric"
                        value={size}
                        onChange={(event) => setSize(event.target.value)}
                        placeholder="Bytes, if the signature is size-specific"
                      />
                      <FieldDescription>
                        Some signatures only match a hash at a given size.
                      </FieldDescription>
                    </Field>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
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
                  toast.message("Filled the safe EICAR MD5")
                }}
              >
                Use safe test hash
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        call={call}
        parsedOk={parsed?.ok ?? false}
        error={parsed?.error?.error}
      >
        {parsed?.payload && call ? (
          <ScanPayloadCard call={call} payload={parsed.payload} />
        ) : null}
      </ResultArea>
    </div>
  )
}

function BatchPanel() {
  const [lines, setLines] = useState("")
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
          <CardTitle>Look up many hashes</CardTitle>
          <CardDescription>
            Paste one digest per line. Useful for threat intel, CI, or comparing
            a list of known files.
          </CardDescription>
          <CardAction>
            <Badge variant="outline">POST /scan/hashes</Badge>
          </CardAction>
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
                  placeholder={`${EICAR_MD5}\n00000000000000000000000000000000`}
                />
                <FieldDescription>
                  One hex digest per line. Experts can also send{" "}
                  <code className="font-mono">algo:hex</code> or NDJSON with{" "}
                  <code className="font-mono">md5</code>/
                  <code className="font-mono">sha1</code>/
                  <code className="font-mono">sha256</code>.
                </FieldDescription>
              </Field>
            </FieldGroup>
            <div className="flex flex-wrap gap-2">
              <Button
                type="submit"
                disabled={lookup.isPending || !lines.trim()}
              >
                {lookup.isPending ? (
                  <Spinner />
                ) : (
                  <ListIcon data-icon="inline-start" />
                )}
                Look up hashes
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() =>
                  setLines(`${EICAR_MD5}\n00000000000000000000000000000000\n`)
                }
              >
                Load example
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <ResultArea
        call={call}
        parsedOk={Boolean(items)}
        error={call && !call.ok ? `HTTP ${call.status}` : undefined}
      >
        {items && call ? <HashBatchCard call={call} items={items} /> : null}
      </ResultArea>
    </div>
  )
}

function ApiPanel() {
  return (
    <div className="flex flex-col gap-4 pt-4">
      <Card>
        <CardHeader>
          <CardTitle>HTTP API</CardTitle>
          <CardDescription>
            This UI calls same-origin <code className="font-mono">/api/*</code>{" "}
            routes, which proxy to Defender (
            <code className="font-mono">DEFENDER_URL</code>, default{" "}
            <code className="font-mono">http://127.0.0.1:8080</code>).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Endpoint
            method="GET"
            path="/health"
            purpose="Is the process up?"
            body="—"
            response='{ "status": "ok" }'
          />
          <Separator />
          <Endpoint
            method="GET"
            path="/ready"
            purpose="Are signatures loaded?"
            body="—"
            response='{ "ready": true, "file_hashes": 0, "body_sigs": 0 }'
          />
          <Separator />
          <Endpoint
            method="GET"
            path="/info"
            purpose="What databases and signature counts are loaded?"
            body="—"
            response="databases[], signatures, loaded_at_unix"
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan"
            purpose="Scan a file"
            body="raw bytes or multipart file"
            response='{ "result": "clean"|"infected", "signature"?, "size", "md5", "sha1", "sha256", "duration_us" }'
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan/hash"
            purpose="Look up one hash"
            body='{ "md5"|"sha1"|"sha256"|"hash", "size"? }'
            response="Same scan payload. Unused hash fields are omitted."
          />
          <Separator />
          <Endpoint
            method="POST"
            path="/scan/hashes"
            purpose="Look up many hashes"
            body="one digest per line, algo:hex, or NDJSON"
            response='[{ "result", "hash", "signature"? }]'
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Safe test sample</CardTitle>
          <CardDescription>
            EICAR is a standard harmless string. Every stock ClamAV database
            should flag it as infected. Use it to confirm Defender is working —
            it is not malware.
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
  purpose,
  body,
  response,
}: {
  method: string
  path: string
  purpose: string
  body: string
  response: string
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline">{method}</Badge>
        <p className="font-mono text-sm">{path}</p>
      </div>
      <p>{purpose}</p>
      <p className="text-muted-foreground">Request: {body}</p>
      <p className="text-muted-foreground">Response: {response}</p>
    </div>
  )
}

function ResultArea({
  call,
  parsedOk,
  error,
  children,
}: {
  call: ApiCall | null
  parsedOk: boolean
  error?: string
  children: ReactNode
}) {
  if (!call) {
    return null
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
          <AlertTitle>Unexpected response</AlertTitle>
          <AlertDescription>
            HTTP {call.status}. The body did not match the expected Defender
            JSON shape.
          </AlertDescription>
        </Alert>
      ) : null}
      {children}
      {!parsedOk ? (
        <Card>
          <CardHeader>
            <CardTitle>Response</CardTitle>
            <CardDescription>
              Raw scanner output for debugging this request.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TechnicalDetails call={call} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}
