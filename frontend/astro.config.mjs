// @ts-check
import { defineConfig } from "astro/config";

export default defineConfig({
  // Static output: every page is plain HTML with no client JavaScript unless a
  // component opts in. The FastAPI backend serves the API; this build serves
  // the pages, deployed to the same origin via the netlify.toml proxy rules so
  // the session cookie stays first-party.
  output: "static",

  build: {
    // Emit /login rather than /login/index.html so URLs match the routes the
    // FastAPI app already exposes and the existing links keep working.
    format: "file",
    // Hashed filenames, so the long cache lifetime on /static is safe.
    assets: "assets",
  },

  // Bundle every stylesheet into files rather than inlining them, which is what
  // lets the Content-Security-Policy drop 'unsafe-inline' for scripts.
  vite: {
    build: {
      assetsInlineLimit: 0,
    },
    server: {
      // Mirror the netlify.toml rules locally, so `npm run dev` is a single
      // origin too. The session cookie is first-party and SameSite=Lax; split
      // origins in development would break sign-in in ways production doesn't.
      proxy: Object.fromEntries(
        ["/api", "/auth", "/webhooks", "/admin", "/health", "/static"].map((path) => [
          path,
          {
            // process.env, not import.meta.env: the latter does not read arbitrary
            // shell variables here, so an override was silently ignored and the
            // proxy fell back to the default port.
            target: process.env.API_ORIGIN || "http://127.0.0.1:8000",
            changeOrigin: false,
          },
        ]),
      ),
    },
  },

  devToolbar: { enabled: false },
});
