import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path from "path";
import { fileURLToPath } from "url";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Create a function to get the plugins
const getPlugins = () => {
  const plugins = [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
  ];

  if (process.env.NODE_ENV !== "production" && process.env.REPL_ID !== undefined) {
    import("@replit/vite-plugin-cartographer").then((m) => {
      plugins.push(m.cartographer());
    });
  }

  return plugins;
};

export default defineConfig({
  plugins: getPlugins(),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "client", "src"),
      "@shared": path.resolve(__dirname, "shared"),
      "@assets": path.resolve(__dirname, "attached_assets"),
    },
  },
  root: path.resolve(__dirname, "client"),
  build: {
    outDir: path.resolve(__dirname, "dist/public"),
    emptyOutDir: true,
  },
});
