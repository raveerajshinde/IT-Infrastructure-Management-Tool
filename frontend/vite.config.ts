import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
  preview: { proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } } },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 1200 },
  test: { environment: "jsdom", setupFiles: ["./src/test/setup.ts"], globals: true, css: false },
});
