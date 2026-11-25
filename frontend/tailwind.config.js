/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: { sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "Roboto", "sans-serif"],
                    mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Consolas", "monospace"] },
      colors: {
        brand: Object.fromEntries([50, 100, 200, 300, 400, 500, 600, 700, 800, 900].map((k) => [k, `rgb(var(--brand-${k}) / <alpha-value>)`])),
      },
      boxShadow: { card: "0 1px 2px 0 rgb(15 23 42 / 0.06), 0 1px 3px 0 rgb(15 23 42 / 0.08)" },
    },
  },
  plugins: [],
};
