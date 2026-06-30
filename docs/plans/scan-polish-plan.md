# Recon, GVM, and Attack Polish Plan

## Overview
Polish the three core scanning/attack workflows to improve UX, reliability,
and result visibility. Each section has concrete, bite-sized tasks.

---

## Phase 1 — Recon Scan Polish

### 1.1 Scan Phase Descriptions
**File:** `webapp/src/lib/recon-types.ts` (or wherever RECON_PHASES is defined)
- Add human-friendly descriptions to each phase so the UI can show what's happening
- Current: `['Domain Discovery', 'Port Scanning', ...]`
- Add: tooltip descriptions explaining what each phase does

### 1.2 Scan Completion Summary
**File:** `webapp/src/app/graph/components/ScanProgressMonitor/ScanProgressMonitor.tsx`
- When a scan completes, show a brief summary card: ports found, domains discovered, vulns detected
- Auto-dismiss after 5 seconds or on click

### 1.3 Recon Log Viewer — Phase Grouping
**File:** `webapp/src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.tsx`
- Group log lines by phase with collapsible headers
- Color-code phases (discovery=blue, scanning=green, vuln=red)
- Show per-phase timing

### 1.4 Pause/Resume UX
**File:** `webapp/src/hooks/useReconStatus.ts`
- Add confirmation dialog before pausing (with estimated resume time)
- Show paused duration in the UI

---

## Phase 2 — GVM Scan Polish

### 2.1 GVM Result Summary
**File:** `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx`
- After GVM scan completes, show a badge with vulnerability counts by severity
- Parse the GVM output to extract: critical, high, medium, low counts
- API: Add `/api/gvm/[projectId]/summary` returning counts

### 2.2 GVM Readiness Check on Projects Page
**File:** `webapp/src/app/projects/page.tsx` + `useGvmStatus.ts`
- Show a small indicator on project cards if GVM has been run
- Show "GVM Syncing..." badge if feed sync is in progress

### 2.3 GVM Scan Confirmation Modal
**File:** New component `GvmConfirmModal.tsx`
- Before starting GVM, show: estimated time (~30-60 min), scan scope, warning about active probes
- Option to limit scan to specific IPs/ports

---

## Phase 3 — Attack Panel Polish

### 3.1 Attack Execution Feedback
**File:** `webapp/src/app/graph/components/AttackPanel/AttackPanel.tsx`
- When an attack is executed, show a progress indicator (not just "started")
- Show real-time SSE logs inline (not just in a separate drawer)
- Animate the attack result card when it completes

### 3.2 Attack Success/Failure Indicators
**File:** `webapp/src/app/graph/components/AttackPanel/ components/`
- Green checkmark + "Exploited" badge for successful attacks
- Red X + "Failed" badge with error summary for failed attacks
- Store attack results in localStorage for cross-session reference

### 3.3 Attack History Timeline
**File:** `webapp/src/app/graph/components/AttackPanel/AttackPanel.tsx`
- Show a chronological timeline of all executed attacks
- Each entry shows: timestamp, target, tool, result (success/fail), evidence snippet
- Filter by category and result

### 3.4 Attack Pre-flight Checks
**File:** `webapp/src/app/api/recon/[projectId]/attacks/suggestions/route.ts`
- Before suggesting an attack, verify the prerequisite tools are available
- If a tool is missing, show "Install X to enable this attack" instead of a dead button
- Check that the target is in scope (respects RoE)

---

## Phase 4 — Cross-cutting

### 4.1 Unified Scan Status Badge
**File:** New component `ScanStatusBadge.tsx`
- Replace inline status text with consistent colored badges
- States: idle (gray), starting (blue), running (green with spinner), paused (yellow), error (red)
- Use everywhere: GraphToolbar, ProjectCard, ReconLogsDrawer

### 4.2 Scan Queue Visualization
**File:** `webapp/src/app/graph/components/ScanProgressMonitor/ScanProgressMonitor.tsx`
- Show queued scans below active ones
- Drag to reorder (nice-to-have)
- Cancel queued scans

---

## Implementation Order
1. Phase 1.1-1.2 (quick wins — phase descriptions + completion summary)
2. Phase 2.1 (GVM result summary — high user value)
3. Phase 3.1-3.2 (attack feedback — critical for usability)
4. Phase 3.3 (attack history)
5. Remainder

---

## Notes
- All changes are additive — no breaking changes to existing APIs
- Maintain existing mobile-first responsive patterns
- All toasts follow existing `useToast` conventions
- SSE logs follow existing `useReconSSE` / `useGvmSSE` patterns
