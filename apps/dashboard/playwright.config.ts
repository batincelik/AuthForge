import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  use: { baseURL: process.env.DASHBOARD_E2E_URL ?? "http://localhost:3000", trace: "retain-on-failure" },
  reporter: "list",
});

