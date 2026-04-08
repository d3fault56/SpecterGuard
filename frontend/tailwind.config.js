/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        danger: "#ef4444",
        warning: "#f59e0b",
        safe: "#10b981",
      },
    },
  },
  plugins: [],
};