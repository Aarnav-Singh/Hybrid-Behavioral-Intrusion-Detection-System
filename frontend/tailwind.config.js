/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'neon-green': '#00FF41',
                'neon-cyan': '#00F3FF',
                'neon-red': '#FF003C',
                'neon-yellow': '#FCEE0A',
                'neon-purple': '#BD00FF',
                'bg-dark': '#050505',
                'bg-paper': '#0a0a0a',
                'bg-subtle': '#121212',
                'border-color': '#333333',
            },
            fontFamily: {
                'sans': ['Rajdhani', 'sans-serif'],
                'mono': ['Share Tech Mono', 'monospace'],
                'display': ['Orbitron', 'sans-serif'],
            },
            animation: {
                'glitch': 'glitch 1s linear infinite',
                'scanline': 'scanline 8s linear infinite',
                'pulse-glow': 'pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'flicker': 'flicker 0.15s infinite',
            },
            keyframes: {
                glitch: {
                    '2%, 64%': { transform: 'translate(2px,0) skew(0deg)' },
                    '4%, 60%': { transform: 'translate(-2px,0) skew(0deg)' },
                    '62%': { transform: 'translate(0,0) skew(5deg)' },
                },
                scanline: {
                    '0%': { transform: 'translateY(-100%)' },
                    '100%': { transform: 'translateY(100%)' },
                },
                'pulse-glow': {
                    '0%, 100%': { opacity: '1', boxShadow: '0 0 10px #00FF41, 0 0 20px #00FF41' },
                    '50%': { opacity: '.5', boxShadow: '0 0 5px #00FF41, 0 0 10px #00FF41' },
                },
                flicker: {
                    '0%': { opacity: '0.9' },
                    '50%': { opacity: '1.0' },
                    '100%': { opacity: '0.9' },
                }
            },
            backgroundImage: {
                'scanlines': 'linear-gradient(rgba(18, 16, 20, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06))',
            }
        },
    },
    plugins: [],
}
