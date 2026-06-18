# Mobile Web UI Polish Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add responsive breakpoints to 5 pages + 1 shared component that currently lack mobile styling, making the entire RedAmon webapp usable on phones and tablets.

**Architecture:** Add `@media` breakpoints to CSS module files at standard widths: 900px (tablet hamburger threshold matching GlobalHeader), 767px (stack layouts), and 480px (small phones). Follow the existing pattern from AttackPanel/PageBottomBar/Insights — use the project's CSS custom property tokens (`var(--space-*)`, `var(--text-*)`, `var(--bg-*)`), and prefer stacking vertically, hiding secondary text, and reducing padding on smaller viewports.

**Tech Stack:** CSS Modules, React/Next.js, existing useMediaQuery hooks available if needed (webapp/src/hooks/useMediaQuery.ts)

---

## Current state audit

**Already responsive (no changes needed):**
- Login page — 480px breakpoint: card becomes full-height, removes borders
- Graph page — 768px: body stacks vertically
- Insights page — 1199px + 767px: grids collapse (4→2→1 column)
- Reports page — 767px: header stacks, generate section goes full-width
- GlobalHeader — 900px: shows hamburger, hides desktop nav
- AttackPanel — 768px + 480px: comprehensive coverage
- PageBottomBar — 768px + 480px: hides section titles, compacts
- ReconLogsDrawer, AIAssistantDrawer, ViewTabs, GraphToolbar, RoeViewer, RedZoneTables — all have breakpoints
- Shared UI: Drawer (768px), Modal (640px), DisclaimerGate (640px), OtherScansModal (768px)

**Missing responsive (targets for this plan):**

| # | Page/Component | CSS file | Lines | Complexity |
|---|---|---|---|---|
| 1 | Projects page | `webapp/src/app/projects/page.module.css` | 143 | Medium |
| 2 | Users page | `webapp/src/app/settings/users/page.module.css` | 210 | Low |
| 3 | Settings page | `webapp/src/components/settings/Settings.module.css` | 461 | High |
| 4 | ProjectForm | `webapp/src/components/projects/ProjectForm/ProjectForm.module.css` | 1255 | High |
| 5 | Footer | `webapp/src/components/layout/Footer/Footer.module.css` | 85 | Low |
| 6 | CypherFixTab sub-components | 3 files (Dashboard, Detail, DiffViewer) | varies | Medium |

---

## Task 1: Projects page — responsive header and grid

**Objective:** Make /projects page usable on mobile by stacking the header and collapsing the project grid.

**Files:**
- Modify: `webapp/src/app/projects/page.module.css`

**Step 1: Add 767px breakpoint to stack header vertically**

Add after `.modalActions` block (before the closing brace):
```css
/* ─── Responsive ─── */

@media (max-width: 767px) {
  .header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
  }

  .headerActions {
    width: 100%;
    flex-wrap: wrap;
  }
}
```

**Step 2: Add 480px breakpoint for userSelector**

```css
@media (max-width: 480px) {
  .container {
    padding: var(--space-2);
  }

  .userSelector {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-2);
  }

  .userSelector .select {
    min-width: 100%;
    width: 100%;
  }

  .userSelector select {
    width: 100%;
  }
}
```

**Step 3: Collapse grid to 1 column on small phones**

Add to the 480px block:
```css
  .grid {
    grid-template-columns: 1fr;
    gap: var(--space-3);
  }
```

**Step 4: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds with no CSS errors.

---

## Task 2: Users page — responsive table and header

**Objective:** Make /settings/users table scroll horizontally and stack the header on mobile.

**Files:**
- Modify: `webapp/src/app/settings/users/page.module.css`

**Step 1: Add 767px breakpoint**

Add at end of file:
```css
/* ─── Responsive ─── */

@media (max-width: 767px) {
  .page {
    padding: var(--space-3);
  }

  .header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
  }

  .title {
    font-size: var(--text-lg);
  }

  /* Wrap the table in an overflow container via the page element */
  .page {
    overflow-x: auto;
  }

  .table {
    min-width: 600px;
  }
}
```

**Step 2: Add 480px breakpoint**

```css
@media (max-width: 480px) {
  .page {
    padding: var(--space-2);
  }

  .actions {
    gap: var(--space-1);
  }
}
```

**Step 3: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds.

---

## Task 3: Settings page — responsive tab bar, forms, and sections

**Objective:** Make /settings page usable on mobile — tabs scroll horizontally, form fields stack, ApiKeys sections collapse.

**Files:**
- Modify: `webapp/src/components/settings/Settings.module.css`

**Step 1: Add 767px breakpoint at end of file**

```css
/* ─── Responsive ─── */

@media (max-width: 767px) {
  .page {
    padding: var(--space-3);
  }

  .pageTitle {
    font-size: var(--text-lg);
  }

  /* Tab bar already has overflow-x: auto — ensure it scrolls well */
  .tabBar {
    gap: 0;
    -webkit-overflow-scrolling: touch;
  }

  .tab {
    padding: var(--space-2) var(--space-3);
    font-size: var(--text-xs);
  }

  /* Settings cards / sections — reduce gap */
  .settingsGrid {
    gap: var(--space-2);
  }
}
```

**Step 2: Add 480px breakpoint**

```css
@media (max-width: 480px) {
  .page {
    padding: var(--space-2);
    padding-bottom: var(--space-6);
  }

  .pageTitle {
    font-size: var(--text-base);
  }
}
```

**Step 3: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds.

---

## Task 4: ProjectForm — responsive header and body sections

**Objective:** Make the ProjectForm (used by /projects/new and /projects/[id]/settings) usable on mobile. Stack header, collapse sidebar panels, reduce padding on all sections.

**Files:**
- Modify: `webapp/src/components/projects/ProjectForm/ProjectForm.module.css`

**Step 1: Inspect key selectors used in the form layout**

The key structural classes in ProjectForm are:
- `.form` — flex column, full height
- `.header` — flex row, space-between, padding
- `.bodyWrapper` — flex column, overflow hidden
- `.actions` — flex row (header buttons)

The form body contains left sidebar (tabs/sections nav) and right content area. These use complex nested layouts.

**Step 2: Add 900px breakpoint — stack header, reduce padding in body**

```css
/* ─── Responsive ─── */

@media (max-width: 900px) {
  .header {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3);
  }

  .title {
    font-size: var(--text-base);
  }

  .actions {
    width: 100%;
    flex-wrap: wrap;
  }
}
```

**Step 3: Add 767px breakpoint — ensure main content scrolls**

```css
@media (max-width: 767px) {
  .bodyWrapper {
    overflow-y: auto;
  }
}
```

**Step 4: Add 480px breakpoint — compact header**

```css
@media (max-width: 480px) {
  .header {
    padding: var(--space-2);
    gap: var(--space-2);
  }

  .title {
    font-size: var(--text-sm);
  }

  .actions {
    gap: var(--space-1);
  }
}
```

**Step 5: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds with no CSS errors.

---

## Task 5: Footer — responsive stacking

**Objective:** Stack footer content vertically on small screens.

**Files:**
- Modify: `webapp/src/components/layout/Footer/Footer.module.css`

**Step 1: Add 480px breakpoint**

Add at end of file:
```css
/* ─── Responsive ─── */

@media (max-width: 480px) {
  .content {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-1);
  }

  .left {
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-1);
  }

  .versionWrapper {
    width: 100%;
    justify-content: space-between;
  }
}
```

**Step 2: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds.

---

## Task 6: CypherFixTab sub-components — responsive remediation list

**Objective:** Make the CypherFix remediation dashboard, detail view, and diff viewer usable on mobile.

**Files:**
- Modify: `webapp/src/app/graph/components/CypherFixTab/RemediationDashboard/RemediationDashboard.module.css`
- Modify: `webapp/src/app/graph/components/CypherFixTab/RemediationDetail/RemediationDetail.module.css`
- Modify: `webapp/src/app/graph/components/CypherFixTab/DiffViewer/DiffViewer.module.css`
- Modify: `webapp/src/app/graph/components/CypherFixTab/TriageProgress/TriageProgress.module.css`

**Step 1: Read the existing CSS for each sub-component**

Use `read_file` to inspect each CSS file before writing breakpoints.

**Step 2: Add breakpoints to RemediationalDashboard.css**

Typical pattern: stack filters, reduce card padding on mobile.

Add at end of file:
```css
@media (max-width: 767px) {
  /* Stack filter bar vertically */
  /* Reduce card padding */
  /* Make cards full-width if grid */
}

@media (max-width: 480px) {
  /* Further compaction for small phones */
}
```

**Step 3: Add breakpoints to RemediationalDetail.css**

Stack sections vertically, reduce padding.

**Step 4: Add breakpoints to DiffViewer.css**

Ensure diff blocks scroll horizontally, reduce side-by-side to stacked on mobile.

**Step 5: Add breakpoints to TriageProgress.css**

Reduce padding, stack progress indicators.

**Step 6: Verification**

Run: `cd webapp && npx next build 2>&1 | tail -5`
Expected: Build succeeds.

---

## Risk Assessment

- **Settings page** (Task 3): The main Settings.module.css handles layout for tabs/sections. Sub-component CSS files (LlmProviderForm, McpServersTab, TradecraftResourceList, TradecraftResourceForm) may also need individual breakpoints. If UI still breaks at 320px after adding Settings.module.css breakpoints, revisit sub-components individually.
- **ProjectForm** (Task 4): At 1255 lines, this is the most complex CSS file. The body uses a sidebar+content layout that may need JavaScript-level responsive logic (collapsing the sidebar on mobile). If CSS-only breakpoints are insufficient, we may need to modify the TSX to add a mobile toggle — flag this rather than silently failing.
- **CypherFixTab** (Task 6): The sub-components have unknown CSS structures — we must inspect each before writing breakpoints. This task is exploratory.

## Execution Order

Tasks are independent and can run in parallel except:
- Tasks 1-6 are all CSS-only changes to different files with no overlap
- Any task can be done first; suggested order is by complexity (lowest first):

1. Task 5 (Footer) — simplest, quick win
2. Task 2 (Users) — simple table page
3. Task 1 (Projects) — medium complexity
4. Task 3 (Settings) — complex, tests tab layout
5. Task 4 (ProjectForm) — most complex, needs care
6. Task 6 (CypherFix) — exploratory, last

## Validation

After all tasks complete, verify:
1. `cd webapp && npx next build` succeeds
2. All existing tests pass: `cd webapp && npm test -- --passWithNoTests 2>&1 | tail -20`
3. Manual visual check: open each page at 375px, 768px, 1024px widths in Chrome DevTools
4. No horizontal overflow on any page at 320px width
5. All interactive elements have ≥44px touch targets on mobile
