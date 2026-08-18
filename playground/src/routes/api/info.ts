import { createFileRoute } from "@tanstack/react-router"

import { proxyDefender } from "@/lib/defender-proxy"

export const Route = createFileRoute("/api/info")({
  server: {
    handlers: {
      GET: ({ request }) => proxyDefender(request, "/info"),
    },
  },
})
