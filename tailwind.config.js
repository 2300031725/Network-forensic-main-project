/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Custom color palette for security dashboard
        'security-dark': '#0f172a',
        'security-light': '#1e293b',
        'security-accent': '#0ea5e9',
        'security-success': '#10b981',
        'security-warning': '#f59e0b',
        'security-danger': '#ef4444',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
