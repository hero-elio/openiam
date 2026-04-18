import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  base: "/__test/authn/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
