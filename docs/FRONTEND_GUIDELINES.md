# Frontend Guidelines

## 1. Design Philosophy
>
> **"Security tools don't have to look boring."**

The Dashboard for the HB-IDS is envisioned as a **premium, high-performance command center**. It should not just "show data" but provide an immersive experience for the security analyst.

### Key Aesthetic Principles

- **Dark Mode First:** Default to a sleek, deep dark theme (e.g., `#0f172a` background) to reduce eye strain during long shifts.
- **Glassmorphism:** Use subtle transparency and background blur (`backdrop-filter: blur(10px)`) for panels and overlays to create depth.
- **Vibrant Accents:** Use neon/high-contrast colors for critical alerts (e.g., Cyberpunk Red `#ff003c`, Electric Blue `#00f3ff`) against the dark background.
- **Micro-Interactions:** Buttons, cards, and charts should react to hover and click events with smooth transitions (0.2s - 0.3s ease-out).

## 2. UI Component Standards

### Dashboards

- **Grid Layout:** Use a responsive grid system (CSS Grid) to organize widgets.
- **Real-Time Updates:** Charts must update live via WebSocket/SSE without full page reloads.
- **Data Density:** High density is allowed but must be balanced with adequate whitespace (padding) to avoid clutter.

### Typography

- **Font Family:** Use modern, geometric sans-serif fonts (e.g., **Inter**, **Roboto**, or **JetBrains Mono** for code/logs).
- **Hierarchy:** distinct H1/H2/H3 styles with clear weight differentiations (Light/Regular/Bold).

### Charts & Visualizations

- **Library:** Preference for robust libraries like **Recharts**, **Nivo**, or **Chart.js**.
- **Style:** Minimalist axes, removed grid lines where possible, and tooltips on hover.
- **Color Coding:** consistent use of colors (Green=Safe, Yellow=Warning, Red=Critical).

## 3. Technology Recommendations (Future Implementation)

### Framework

- **Next.js (React):** For a production-grade, server-rendered dashboard.
- **React (Vite):** A high-performance SPA connected to FastAPI WebSockets for real-time telemetry.

### Styling

- **Tailwind CSS:** For rapid, utility-first styling.
- **Framer Motion:** For handling complex animations and layout transitions.

## 4. Accessibility (A11y)

- **Contrast:** Ensure all text passes WCAG AA contrast ratios.
- **Keyboard Nav:** Full keyboard support for all interactive elements.
- **Screen Readers:** Semantic HTML structure (headers, landmarks).
