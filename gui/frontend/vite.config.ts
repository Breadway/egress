import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

const host = process.env.TAURI_DEV_HOST;
const rustProjectDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src");

export default defineConfig({
  plugins: [sveltekit()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { ignored: [`${rustProjectDir}/**`] }
  }
});
