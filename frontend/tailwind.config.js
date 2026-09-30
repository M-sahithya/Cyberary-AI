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
        // Cybersecurity dark theme palette
        cyber: {
          50: '#e6f9ff',
          100: '#b3ecff',
          200: '#80dfff',
          300: '#4dd2ff',
          400: '#1ac5ff',
          500: '#00b8e6',
          600: '#0090b3',
          700: '#006880',
          800: '#00404d',
          900: '#001a1f',
          950: '#000d10',
        },
        threat: {
          critical: '#ff1744',
          high: '#ff6d00',
          medium: '#ffc400',
          low: '#00e676',
          info: '#2979ff',
        },
        surface: {
          900: '#0a0e17',
          800: '#0f1623',
          700: '#151d2e',
          600: '#1b253a',
          500: '#212e46',
          400: '#2a3a56',
          300: '#354766',
        },
        accent: {
          cyan: '#00e5ff',
          purple: '#7c4dff',
          green: '#00e676',
          orange: '#ff9100',
          red: '#ff1744',
          blue: '#2979ff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px rgba(0, 229, 255, 0.15)',
        'glow-purple': '0 0 20px rgba(124, 77, 255, 0.15)',
        'glow-red': '0 0 20px rgba(255, 23, 68, 0.15)',
        'glow-green': '0 0 20px rgba(0, 230, 118, 0.15)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.5s ease-out',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 229, 255, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 229, 255, 0.4)' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
};
