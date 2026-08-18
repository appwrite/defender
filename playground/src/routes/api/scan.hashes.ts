import { createFileRoute } from "@tanstack/react-router"

import { proxyDefender } from "@/lib/defender-proxy"

export const Route = createFileRoute("/api/scan/hashes")({
  server: {
    handlers: {
      POST: ({ request }) => proxyDefender(request, "/scan/hashes"),
    },
  },
})
