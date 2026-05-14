import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/scan":     "http://localhost:8000",
      "/apis":     "http://localhost:8000",
      "/simulate": "http://localhost:8000",
      "/defend":   "http://localhost:8000",
      "/graph":    "http://localhost:8000",
      "/logs":     "http://localhost:8000",
      "/stats":    "http://localhost:8000",
      "/alerts":   "http://localhost:8000",
      "/threats":  "http://localhost:8000",
      "/ai":       "http://localhost:8000",
      "/terminal": "http://localhost:8000",
      "/report":   "http://localhost:8000",
      "/predict":  "http://localhost:8000",
      "/registry": "http://localhost:8000",
      "/attack":   "http://localhost:8000",
      "/scans":    "http://localhost:8000",
      "/hardware": "http://localhost:8000",
    },
  },
});