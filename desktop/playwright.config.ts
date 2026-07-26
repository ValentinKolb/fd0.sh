import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.e2e.ts",
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    trace: "retain-on-failure",
  },
});
