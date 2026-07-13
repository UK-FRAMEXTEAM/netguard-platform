/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#4f8ef7',
        secondary: '#a78bfa',
        dark: '#0f1117',
        surface: '#1a1d27',
        card: '#1e2130',
        border: '#2a2d3e',
        safe: '#00e676',
        warning: '#ffa726',
        danger: '#ff3b5c',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
