import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: the FastAPI engine API runs on :8000 and Vite proxies every API route to it.
const API = process.env.ATTACKSTORY_API || "http://localhost:8000";
const routes = ["/incidents", "/events", "/stats", "/quality", "/health", "/reload", "/runs", "/kb", "/graph", "/jobs"];

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: Object.fromEntries(routes.map((r) => [r, API])) },
});
