// Tauri has no Node server for SSR, so this is an SPA: adapter-static with an
// index.html fallback, matching the other bread desktop apps.
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({ fallback: "index.html" })
  }
};

export default config;
