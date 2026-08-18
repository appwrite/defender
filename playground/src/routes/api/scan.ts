import { createFileRoute } from "@tanstack/react-router"

import { proxyDefender } from "@/lib/defender-proxy"

export const Route = createFileRoute("/api/scan")({
  server: {
    handlers: {
      POST: ({ request }) => proxyDefender(request, "/scan"),
    },
  },
})
