# RedAmon UI/UX Improvement Plan

> **Date:** 2026-06-18  
> **Scope:** Entire webapp frontend (`webapp/src/`)  
> **Framework:** Next.js 16 (App Router) · React 19 · TypeScript · CSS Modules + Design Tokens

---

## Table of Contents

1. [Recently Completed](#1-recently-completed)
2. [Visual & Design System](#2-visual--design-system)
3. [Navigation & Layout](#3-navigation--layout)
4. [Performance & Responsiveness](#4-performance--responsiveness)
5. [Data Presentation & Feedback](#5-data-presentation--feedback)
6. [Accessibility](#6-accessibility)
7. [Developer Experience & Maintainability](#7-developer-experience--maintainability)
8. [Roadmap & Prioritization](#8-roadmap--prioritization)

---

## 1. Recently Completed

| Improvement | Description | Sprint |
|---|---|---|
| **Tabbed Partial Recon Logs Drawer** | Replaced N individual `ReconLogsDrawer` instances with a unified `PartialReconLogsDrawer` featuring a tab bar with status dots, scrollable log area per run, and stop button from tab header | Sprint 4 |
| **SSE Log Deduplication** | Added `seq` field to `ReconLogEvent`; `useReconSSE` and `useMultiPartialReconSSE` reject events with already-seen `seq` values to prevent duplicate log entries from WebSocket reconnects | Sprint 4 |
| **Polling Jitter** | Added optional `jitter: true` to `usePolling`; introduces ±25% random jitter around the base interval with proper timer cleanup to prevent thundering herd | Sprint 4 |
| **Toast Feedback for Recon Actions** | Added `showToasts` option to `useReconStatus` — fires success/error/info toasts from `startRecon`, `stopRecon`, `pauseRecon`, `resumeRecon`. Wired with `showToasts: true` in graph/page.tsx | Sprint 4 |
| **Focus Management (Drawer)** | Spring 1: Added focus trap + `aria-*` attributes to `Drawer.tsx` | Sprint 1 |
| **Shared Hooks Extraction** | Sprint 2: Extracted `useClickOutside`, `usePolling`, `useDrawerPosition` from duplicated inline patterns | Sprint 2 |
| **CSS Modules Conversion** | Sprint 2.5: Converted inline styles to CSS modules in `error.tsx` and `graph/error.tsx` | Sprint 2.5 |
| **Error Boundary** | Sprint 3.1: Added reusable `ErrorBoundary.tsx` UI component | Sprint 3.1 |
| **Focus Trap (Modal)** | Sprint 3.2: Proper Tab trapping + first-focusable focus in `Modal.tsx` | Sprint 3.2 |
| **Responsive Spacing Aliases** | Sprint 3.3: Added `--space-sm/md/lg` with 767px mobile breakpoint in `tokens/spacing.css` | Sprint 3.3 |

---

## 2. Visual & Design System

### 2.1. Dark/Light Mode Polish

**Current state:** Fully functional dark-first theme with CSS custom properties. Light theme exists but lacks design review.

**Recommendations:**

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P0** | Audit light theme contrast — verify all `--text-*` on `--bg-*` combos meet WCAG AA (4.5:1 ratio) | 2d | High |
| **P0** | Ensure graph canvas (2D/3D) has light-appropriate `GRAPH_BACKGROUND`, node colors, and link colors in `colors.ts` | 1d | High |
| **P1** | Add smooth transition animations for theme switching (`transition: background-color 0.3s, color 0.3s, border-color 0.3s` on `:root`) | 0.5d | Medium |
| **P2** | Add a system-preference follower: if user selects "System", listen for `prefers-color-scheme` changes and swap live | 0.5d | Medium |

### 2.2. Animation & Micro-interactions

**Current state:** Minimal CSS transitions. No loading skeleton placeholders for page transitions. Graph animations exist via RAF loop.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add `skeleton.css` loading placeholders for panels that render async data (DataTable, insights charts, NodeDetailsTable) | 2d | High |
| **P1** | Add page-level route transition animation using `next/navigation` events (fade/slide for app router transitions) | 1d | Medium |
| **P2** | Add subtle hover/active states on all interactive elements in the graph toolbar and bottom bar | 1d | Medium |
| **P2** | Toast enter/exit animations (slide-in + fade-out) in `Toast.tsx` | 0.5d | Medium |

### 2.3. Typography & Spacing Audit

**Current state:** Good foundation with `tokens/typography.css` and `tokens/spacing.css` (4px base). 767px responsive alias exists.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Standardize heading hierarchy (h1–h6) across all pages — currently inconsistent between `/graph`, `/insights`, `/settings` | 1d | Medium |
| **P1** | Ensure all text uses token-based `--font-size-*` and `--line-height-*` (remove hardcoded px values) | 2d | Medium |
| **P2** | Add `--space-2xs` (2px) and `--space-3xl` (64px) to spacing scale if needed | 0.5d | Low |

---

## 3. Navigation & Layout

### 3.1. Mobile Responsiveness

**Current state:** Mobile bottom nav exists (`MobileBottomNav.tsx`). 767px breakpoint token defined. Some pages not responsive.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P0** | Make `/graph` page fully functional below 767px — currently panel-overloaded for mobile (graph + toolbar + drawer + bottom bar) | 3d | High |
| **P0** | Make `/projects/new` form responsive — 44 section components stack poorly on small screens | 3d | High |
| **P1** | Collapse the GlobalHeader nav links into a hamburger menu below 767px | 1d | High |
| **P1** | Make `/insights` charts responsive — recharts containers should use `width="100%"` with aspect ratio | 2d | Medium |
| **P2** | Add swipe gesture to close drawers on mobile (use existing `useGraphTouchGestures` patterns) | 1d | Medium |

### 3.2. Information Architecture

**Current state:** All recon state is surfaced through modal confirmations and then individual drawers — decent but scattered.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add a unified **Recon Hub** overview panel: collapsed view of all active/pending/failed scan runs accessible from the toolbar | 2d | High |
| **P2** | Consolidate the 44 section components in ProjectForm into collapsible accordion groups with search/filter | 3d | High |
| **P2** | Add `/projects` list view showing last-active status, scan count, and quick-action buttons (resume, duplicate) | 1d | Medium |

### 3.3. Drawer System Consolidation

**Current state:** Multiple drawer components: `Drawer.tsx`, `NodeDrawer`, `AIAssistantDrawer`, `FileSystemDrawer`, `ReconLogsDrawer`, `PartialReconLogsDrawer`, `UserPresetDrawer`, `ReconLogsDrawer`, etc.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Standardize drawer API: consistent open/close animation, width presets (sm/md/lg/ xl), header slot, footer slot | 1d | Medium |
| **P2** | Make drawers stackable (multi-drawer with back-drop for inner drawers) | 1d | Low |

---

## 4. Performance & Responsiveness

### 4.1. Graph Performance

**Current state:** Performance tiers exist in `graph/config/graph.ts` (full/reduced/minimal/ultra-minimal based on node count). Force simulation runs in RAF.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Implement Web Worker for force simulation to keep UI responsive during large graph layouts | 3d | High |
| **P1** | Add virtual viewport culling: don't render nodes/links outside the visible viewport | 2d | High |
| **P2** | Add progressive loading (render low-detail first, then full detail) for >5000 node graphs | 2d | Medium |

### 4.2. Bundle & Load Performance

**Current state:** No bundle analysis in CI. Heavy dependencies: three.js, xterm, react-force-graph.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Dynamic import (`next/dynamic`) for heavy components: GraphCanvas3D, KaliTerminal, all insights chart components | 1d | High |
| **P2** | Add `@next/bundle-analyzer` to CI and set budget thresholds | 0.5d | Medium |
| **P2** | Lazy-load the 55+ insight chart components — they're all imported eagerly on `/insights` | 1d | Medium |

### 4.3. Rendering & State

**Current state:** React Query for server state. Context for auth/project. SSE hooks for log streaming.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Virtualize the DataTable using `@tanstack/react-virtual` — currently renders all rows in DOM | 1.5d | High |
| **P1** | Memoize expensive graph data transformations — `useStableGraphData` exists but `clusterGraphData` and `export*` re-run on every render | 1d | Medium |
| **P2** | Add React Query stale-while-revalidate to all project/insights queries for instant back navigation | 0.5d | Medium |

---

## 5. Data Presentation & Feedback

### 5.1. Empty & Error States

**Current state:** `EmptyState.tsx` exists for CypherFix. Error boundaries exist. Most pages show raw "No data" text.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add contextual empty states for every data panel (graph, insights, datatable, each RedZoneTable) with illustration + CTA | 2d | High |
| **P1** | Add retry button to error boundaries that re-fires the failed query | 0.5d | High |
| **P2** | Add "last refreshed" timestamps to data-heavy panels | 0.5d | Low |

### 5.2. User Feedback Patterns

**Current state:** Toast system exists. No `aria-live` regions for screen readers. Background tasks progress is unclear.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add a **global progress indicator** for background recon (small persistent bar or dot in the toolbar showing "Scanning… 3 active") | 1d | High |
| **P2** | Add `aria-live="polite"` regions for toast notifications | 0.5d | Medium |
| **P2** | Add undo action on destructive toasts (e.g., "Project deleted" → "Undo") | 1d | Medium |

### 5.3. Keyboard Shortcuts

**Current state:** No documented global keyboard shortcuts.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P2** | Add a command palette (`Cmd+K`) for power users: open graph, switch project, run recon, toggle theme | 2d | Medium |
| **P2** | Add keyboard navigation for graph canvas (arrow keys to pan, +/- to zoom) | 1d | Low |

---

## 6. Accessibility

### 6.1. Screen Reader Support

**Current state:** Focus trap on Drawer + Modal. No systematic `aria-*` audit.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add `aria-label` / `aria-labelledby` to all icon-only buttons (GraphToolbar, ViewTabs, PageBottomBar) | 1d | High |
| **P1** | Add `role="status"` and `aria-live="polite"` to status indicators (scan progress, connection status) | 0.5d | High |
| **P2** | Add skip-to-content link at top of every page | 0.5d | Medium |
| **P2** | Audit all form controls in ProjectForm sections for associated `<label>` elements | 2d | Medium |

### 6.2. Focus Management

**Current state:** Focus trap on Drawer and Modal. Graph canvas focus not managed.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Return focus to trigger element after modal/drawer close | 0.5d | High |
| **P2** | Add visible focus indicators to graph canvas (keyboard navigable nodes) | 2d | Low |

### 6.3. Color & Contrast

**Current state:** Severity colors (crimson, red, magenta) used throughout. Not all color pairs checked for color blindness.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Audit severity colors for deuteranopia/protanopia accessibility — add patterns/texture as secondary encoding | 1d | High |
| **P2** | Ensure all tooltip text meets 4.5:1 contrast ratio against its background | 0.5d | Medium |

---

## 7. Developer Experience & Maintainability

### 7.1. Component Architecture

**Current state:** Good patterns (UI primitives, hooks, CSS modules). `AttackPanel.tsx` noted at 780 lines.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Split `AttackPanel.tsx` (780 lines) into smaller focused components (AttackList, AttackDetail, AttackControls) | 2d | Medium |
| **P1** | Add Storybook stories for all 15+ UI primitives | 3d | Medium |
| **P2** | Create barrel exports for graph components, insights components, project form sections | 0.5d | Medium |

### 7.2. Test Coverage

**Current state:** Vitest + jsdom + @testing-library/react configured. Few frontend tests exist.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Add smoke tests for all page-level components (graph, insights, projects, settings, login) | 2d | High |
| **P1** | Add unit tests for all shared hooks (useClickOutside, usePolling, useDrawerPosition, useMediaQuery, useTheme) | 1d | High |
| **P2** | Add interaction tests for AIAssistantDrawer (send message, receive response, tool execution) | 2d | Medium |
| **P2** | Add visual regression testing (Playwright screenshot tests) for the 2D graph canvas | 3d | Low |

### 7.3. CSS Maintainability

**Current state:** Excellent — CSS custom properties + CSS Modules. Some inline `style={{}}` props remain.

| Priority | Improvement | Effort | Impact |
|---|---|---|---|
| **P1** | Audit and migrate remaining inline styles to CSS Modules (sweep all `style={{}}` props) | 2d | Medium |
| **P2** | Add CSS property sorting convention and linter (stylelint-config-standard) | 1d | Low |
| **P2** | Document design system tokens in a living style guide page (`/style-guide`) | 2d | Low |

---

## 8. Roadmap & Prioritization

### Sprint 5 (Next)
| Task | Effort |
|---|---|
| Global recon progress indicator in toolbar | 1d |
| Audit light theme contrast (WCAG AA) | 2d |
| Dynamic import heavy components (3D graph, xterm, charts) | 1d |
| Add contextual empty states for all data panels | 2d |
| Responsive `/graph` page below 767px | 3d |
| Add retry button to error boundary | 0.5d |

### Sprint 6
| Task | Effort |
|---|---|
| Responsive `/projects/new` form (collapsible accordion sections) | 3d |
| Virtualize DataTable (@tanstack/react-virtual) | 1.5d |
| Web Worker for force simulation | 3d |
| Screen reader audit (aria-labels, aria-live regions) | 1d |
| Color blindness audit for severity colors | 1d |
| Split AttackPanel.tsx | 2d |

### Sprint 7
| Task | Effort |
|---|---|
| Command palette (Cmd+K) | 2d |
| Page transition animations | 1d |
| System theme preference follower | 0.5d |
| Smoke tests for all pages | 2d |
| Hook unit tests | 1d |
| Skeleton loading placeholders | 2d |

### Sprint 8
| Task | Effort |
|---|---|
| Storybook for UI primitives | 3d |
| Migrate remaining inline styles | 2d |
| Progressive graph loading for >5000 nodes | 2d |
| `aria-live` regions for toast + status | 0.5d |
| Keyboard navigation for graph canvas | 1d |
| Style guide page | 2d |

---

## Appendix: Architecture Snapshot

```
Components:   100+ (15 UI primitives, 5 layout, 44 project form sections, 55+ insights charts)
Pages:        11 (login, graph, insights, projects/list, projects/new, projects/settings, 
                  reports, settings, settings/users, cypherfix, error)
Hooks:        35+ (shared, graph, AI assistant, insights)
CSS Modules:  100+  ·  CSS Custom Properties:  200+ semantic tokens
Dependencies: Next.js 16, React 19, React Query 5, React Table 8, React Flow 12,
              Recharts 2, react-force-graph, three.js, xterm, lucide-react, zod
```

For each improvement, the plan gives priority (P0=critical, P1=important, P2=enhancement), estimated effort, and expected impact to guide sprint planning.
