/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#0b1120',
          card: '#111a2e',
          border: '#1e2a44',
        },
        primary: {
          DEFAULT: '#2563eb',
          hover: '#1d4ed8',
        },
        amber: {
          DEFAULT: '#f59e0b',
        },
        critical: '#dc2626',
        success: '#10b981',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}