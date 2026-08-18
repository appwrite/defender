import { CopyIcon } from "lucide-react"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import type { ApiCall } from "@/lib/api"
import {
  formatBytes,
  formatDurationUs,
  prettyJson,
  type HashBatchItem,
  type ScanPayload,
} from "@/lib/payload"

async function copyValue(label: string, value: string) {
  await navigator.clipboard.writeText(value)
  toast.success(`Copied ${label}`)
}

function HashField({ label, value }: { label: string; value: string }) {
  if (!value) return null
  const id = label.toLowerCase().replace(/[^a-z0-9]+/g, "-")
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <InputGroup>
        <InputGroupInput id={id} readOnly value={value} />
        <InputGroupAddon align="inline-end">
          <InputGroupButton
            type="button"
            size="icon-xs"
            aria-label={`Copy ${label}`}
            onClick={() => copyValue(label, value)}
          >
            <CopyIcon />
          </InputGroupButton>
        </InputGroupAddon>
      </InputGroup>
    </Field>
  )
}

export function ScanPayloadCard({
  call,
  payload,
}: {
  call: ApiCall
  payload: ScanPayload
}) {
  const infected = payload.result === "infected"
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Parsed payload
          <Badge variant={infected ? "destructive" : "secondary"}>
            {payload.result}
          </Badge>
        </CardTitle>
        <CardDescription>
          {call.method} {call.path} · HTTP {call.status} ·{" "}
          {call.elapsedMs.toFixed(0)} ms round-trip
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          {payload.signature ? (
            <Field>
              <FieldLabel>Signature</FieldLabel>
              <p className="font-mono text-sm">{payload.signature}</p>
              <FieldDescription>
                Matched ClamAV signature name.
              </FieldDescription>
            </Field>
          ) : null}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel>Size</FieldLabel>
              <p>
                {formatBytes(payload.size)}{" "}
                <span className="text-muted-foreground">
                  ({payload.size} bytes)
                </span>
              </p>
            </Field>
            <Field>
              <FieldLabel>Scan time</FieldLabel>
              <p>{formatDurationUs(payload.durationUs)}</p>
              <FieldDescription>
                Engine time only, from `duration_us`.
              </FieldDescription>
            </Field>
          </div>
          <HashField label="MD5" value={payload.md5} />
          <HashField label="SHA-1" value={payload.sha1} />
          <HashField label="SHA-256" value={payload.sha256} />
        </FieldGroup>
      </CardContent>
    </Card>
  )
}

export function HashBatchCard({
  call,
  items,
}: {
  call: ApiCall
  items: HashBatchItem[]
}) {
  const infected = items.filter((item) => item.result === "infected").length
  const clean = items.filter((item) => item.result === "clean").length
  const errors = items.filter((item) => item.error).length
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Parsed batch
          <Badge variant="secondary">{items.length} hashes</Badge>
        </CardTitle>
        <CardDescription>
          {call.method} {call.path} · HTTP {call.status} · {infected} infected ·{" "}
          {clean} clean · {errors} errors
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Result</TableHead>
              <TableHead>Hash</TableHead>
              <TableHead>Signature / error</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((item, index) => (
              <TableRow key={`${item.hash ?? item.line ?? "row"}-${index}`}>
                <TableCell>
                  {item.result ? (
                    <Badge
                      variant={
                        item.result === "infected" ? "destructive" : "secondary"
                      }
                    >
                      {item.result}
                    </Badge>
                  ) : (
                    <Badge variant="outline">error</Badge>
                  )}
                </TableCell>
                <TableCell className="max-w-56 truncate font-mono text-xs">
                  {item.hash ?? item.line ?? "—"}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {item.signature ?? item.error ?? "—"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

export function RawJsonCard({ value }: { value: unknown }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Raw JSON</CardTitle>
        <CardDescription>Unmodified body returned by defender.</CardDescription>
      </CardHeader>
      <CardContent>
        <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed">
          {prettyJson(value)}
        </pre>
      </CardContent>
    </Card>
  )
}
