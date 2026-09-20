// Playwright drives a real browser (real Worker, real WASM) — the one layer vitest's Node
// fakes can't reach. It runs LOCALLY on the host (Chromium downloads to
// ~/AppData/Local/ms-playwright, and the host policy allows running it — unlike the Rust/
// esbuild build scripts that force cargo/vitest into Docker). One-time setup:
//   cd apps && pnpm install --ignore-scripts && pnpm exec playwright install chromium
// Then: pnpm test:e2e. Playwright starts serve.mjs itself (webServer below). Tests live in
// ./e2e and are named *.e2e.ts, so vitest (which matches *.test/*.spec) never picks them up.
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    headless: true,
    baseURL: 'http://localhost:5173',
  },
  // serve.mjs is a plain static server; Playwright starts it and waits for the port.
  webServer: {
    command: 'node scripts/serve.mjs',
    // @integration tests need BOTH the demo affordance (one test) and the "start your family tree" onboarding
    // (the rest), so the welcome gate must show both — that's the 'test' landing mode. (Only applies to a
    // server Playwright STARTS; kill any stale serve first so it isn't reused with the wrong flag.)
    env: { ...process.env, OPENOM_LANDING: 'test' },
    port: 5173,
    reuseExistingServer: true,
    timeout: 30_000,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
