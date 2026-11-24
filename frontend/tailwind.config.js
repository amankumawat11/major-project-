/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#080c14',
          panel: '#0e1726',
          panelLight: '#141f36',
          border: '#1f2e4d',
          accent: '#00f0ff',
          blue: '#3b82f6',
          purple: '#8b5cf6',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#10b981',
          info: '#06b6d4',
          text: '#f1f5f9',
          muted: '#94a3b8'
        }
      },
      boxShadow: {
        'cyber-glow': '0 0 20px -5px rgba(0, 240, 255, 0.25)',
        'cyber-glow-blue': '0 0 25px -5px rgba(59, 130, 246, 0.3)',
        'cyber-card': '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
      }
    },
  },
  plugins: [],
}
