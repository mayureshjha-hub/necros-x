/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        necros: { dark: '#0a0f1e', panel: '#111827', accent: '#3b82f6', danger: '#ef4444', warning: '#f59e0b', success: '#10b981' }
      }
    }
  },
  plugins: []
}