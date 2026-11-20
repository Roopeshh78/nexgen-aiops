/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: { 950: '#05080f', 900: '#070c16', 800: '#0a111e', 700: '#0e1726', 600: '#141f31' },
        line: { DEFAULT: '#1a2637', soft: '#131d2c' },
        mint: '#2dd4bf',
        sky: '#38bdf8',
        violet: '#8b5cf6',
        amber: '#f59e0b',
        rose: '#f43f5e',
        lime: '#22c55e',
      },
      fontFamily: {
        sans: ['Inter', 'SF Pro Display', 'Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 0 0 rgba(255,255,255,0.03) inset, 0 18px 40px -24px rgba(0,0,0,0.9)',
        glow: '0 0 0 1px rgba(56,189,248,0.25), 0 0 40px -12px rgba(56,189,248,0.35)',
      },
      animation: {
        'fade-up': 'fadeUp .45s cubic-bezier(.16,.84,.44,1) both',
        breathe: 'breathe 2.6s ease-in-out infinite',
      },
      keyframes: {
        fadeUp: { '0%': { opacity: 0, transform: 'translateY(10px)' }, '100%': { opacity: 1, transform: 'none' } },
        breathe: { '0%,100%': { opacity: 1 }, '50%': { opacity: .35 } },
      },
    },
  },
  plugins: [],
}
