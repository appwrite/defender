import { CopyIcon } from "lucide-react"
import { toast } from "sonner"

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
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

function defenderPath(path: string) {
  return path.replace(/^\/api/, "") || "/"
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
        <Badge variant={infected ? "destructive" : "secondary"}>
          {infected ? "Infected" : "Clean"}
        </Badge>
        <CardTitle>
          {infected
            ? (payload.signature ?? "Known threat detected")
            : "No known threats found"}
        </CardTitle>
        <CardDescription>
          {infected
            ? "This matched a signature in the loaded virus databases. The file itself is unchanged."
            : "Defender did not find a matching signature. That is not a guarantee the file is safe."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <FieldGroup>
          {payload.signature ? (
            <Field>
              <FieldLabel>Signature</FieldLabel>
              <p className="font-mono text-sm">{payload.signature}</p>
              <FieldDescription>
                Threat name from the ClamAV database.
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
                Engine time only, not the full HTTP round-trip.
              </FieldDescription>
            </Field>
          </div>
          <HashField label="MD5" value={payload.md5} />
          <HashField label="SHA-1" value={payload.sha1} />
          <HashField label="SHA-256" value={payload.sha256} />
        </FieldGroup>
      </CardContent>
      <CardFooter className="flex-col items-stretch">
        <TechnicalDetails call={call} />
      </CardFooter>
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
        <CardTitle>Batch results</CardTitle>
        <CardDescription>
          {items.length} hashes · {infected} infected · {clean} clean
          {errors ? ` · ${errors} errors` : ""}
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
                      {item.result === "infected" ? "Infected" : "Clean"}
                    </Badge>
                  ) : (
                    <Badge variant="outline">Error</Badge>
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
      <CardFooter className="flex-col items-stretch">
        <TechnicalDetails call={call} />
      </CardFooter>
    </Card>
  )
}

export function TechnicalDetails({ call }: { call: ApiCall }) {
  const json = prettyJson(call.json)
  return (
    <Accordion className="w-full">
      <AccordionItem value="technical" className="border-none">
        <AccordionTrigger>Technical details</AccordionTrigger>
        <AccordionContent>
          <div className="flex flex-col gap-3">
            <p className="text-muted-foreground">
              {call.method} {defenderPath(call.path)} · HTTP {call.status} ·{" "}
              {call.elapsedMs.toFixed(0)} ms round-trip
            </p>
            <div className="flex items-center justify-between gap-2">
              <p className="font-medium">Response JSON</p>
              <Button
                type="button"
                variant="outline"
                size="xs"
                onClick={() => copyValue("JSON", json)}
              >
                <CopyIcon data-icon="inline-start" />
                Copy
              </Button>
            </div>
            <pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed">
              {json}
            </pre>
          </div>
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  )
}
