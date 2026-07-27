import { resolve } from "node:path";
import { defineConfig, externalizeDepsPlugin } from "electron-vite";
import solid from "vite-plugin-solid";

const devContentSecurityPolicy = {
  name: "fd0-dev-content-security-policy",
  apply: "serve" as const,
  transformIndexHtml(html: string): string {
    return html
      .replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
      .replace("connect-src 'none'", "connect-src 'self' ws:");
  },
};

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
    build: {
      rollupOptions: {
        input: resolve(import.meta.dirname, "src/main/index.ts"),
      },
    },
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    build: {
      rollupOptions: {
        input: resolve(import.meta.dirname, "src/preload/index.ts"),
        output: {
          format: "cjs",
          entryFileNames: "index.cjs",
        },
      },
    },
  },
  renderer: {
    root: resolve(import.meta.dirname, "src/renderer"),
    plugins: [devContentSecurityPolicy, solid()],
    server: {
      host: "127.0.0.1",
      port: 5174,
      strictPort: true,
    },
    build: {
      rollupOptions: {
        input: resolve(import.meta.dirname, "src/renderer/index.html"),
      },
    },
  },
});
