import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  root: "web",
  build: {
    outDir: resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
});
