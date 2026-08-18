import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { HeadContent, Scripts, createRootRoute } from "@tanstack/react-router"
import { ThemeProvider } from "next-themes"
import type { ReactNode } from "react"

import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import geistLatin from "@fontsource-variable/geist/files/geist-latin-wght-normal.woff2?url"
import appCss from "../styles.css?url"

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        refetchOnWindowFocus: false,
        staleTime: 5_000,
      },
    },
  })
}

let browserQueryClient: QueryClient | undefined

function getQueryClient() {
  if (typeof window === "undefined") {
    return makeQueryClient()
  }
  return (browserQueryClient ??= makeQueryClient())
}

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1",
      },
      {
        title: "Appwrite Defender",
      },
      {
        name: "description",
        content: "Scan files and hashes against the official ClamAV databases.",
      },
      { name: "application-name", content: "Defender" },
      { name: "apple-mobile-web-app-title", content: "Defender" },
      { name: "apple-mobile-web-app-capable", content: "yes" },
      { name: "mobile-web-app-capable", content: "yes" },
      { name: "msapplication-TileColor", content: "#0a0a0a" },
      {
        name: "theme-color",
        content: "#fafafa",
        media: "(prefers-color-scheme: light)",
      },
      {
        name: "theme-color",
        content: "#0a0a0a",
        media: "(prefers-color-scheme: dark)",
      },
    ],
    links: [
      {
        rel: "preload",
        href: geistLatin,
        as: "font",
        type: "font/woff2",
        crossOrigin: "anonymous",
      },
      { rel: "stylesheet", href: appCss },
      { rel: "icon", href: "/favicon.ico", sizes: "48x48" },
      { rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
      {
        rel: "icon",
        href: "/favicon-32x32.png",
        type: "image/png",
        sizes: "32x32",
      },
      {
        rel: "icon",
        href: "/favicon-16x16.png",
        type: "image/png",
        sizes: "16x16",
      },
      {
        rel: "apple-touch-icon",
        href: "/apple-touch-icon.png",
        sizes: "180x180",
      },
      { rel: "mask-icon", href: "/safari-pinned-tab.svg", color: "#0a0a0a" },
      { rel: "manifest", href: "/site.webmanifest" },
    ],
  }),
  notFoundComponent: () => (
    <main className="mx-auto max-w-3xl p-6">
      <h1 className="font-heading text-lg font-medium">Not found</h1>
      <p className="text-muted-foreground">That page does not exist.</p>
    </main>
  ),
  shellComponent: RootDocument,
})

function RootDocument({ children }: { children: ReactNode }) {
  const queryClient = getQueryClient()
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <QueryClientProvider client={queryClient}>
            <TooltipProvider>
              {children}
              <Toaster />
            </TooltipProvider>
          </QueryClientProvider>
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  )
}
