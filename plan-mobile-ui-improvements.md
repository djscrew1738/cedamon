# Mobile UI Quick Wins — Implementation Plan

## 1. Goal & Scope

**Objective:** Fix the most critical mobile UX gaps in the RedAmon webapp, focusing on the global responsive shell and making the graph dashboard usable with touch gestures on phones.

**IN scope:**
- Add the missing viewport meta tag so the app renders at the correct scale on phones.
- Remove dead navigation code (`NavigationBar`) and tighten the mobile hamburger menu (`GlobalHeader`).
- Improve shared mobile primitives (`Drawer`, `Modal`) for safe areas and touch friendliness.
- Add touch-first controls to the graph canvas: prevent page scroll capture, support pinch-to-zoom / pan, and make the on-screen nav buttons usable on small screens.
- Add unit tests for the new gesture helper and updated header behavior.

**OUT of scope:**
- A full responsive redesign of every page (e.g., `/settings`, `/projects/new`).
- PWA / manifest / offline / installability work.
- Native mobile app (React Native, Capacitor, Expo).
- Changing the desktop layout or visual theme.

## 2. Files to Create / Modify

### New files
- `webapp/src/app/graph/hooks/useGraphTouchGestures.ts`  
  Custom hook that interprets `PointerEvent`/`TouchEvent` on the graph wrapper and drives `react-force-graph` pan/zoom APIs.
- `webapp/src/app/graph/hooks/useGraphTouchGestures.test.ts`  
  Unit tests for the gesture hook using synthetic touch events.
- `webapp/src/app/graph/components/GraphCanvas/GraphTouchLayer.tsx`  
  Thin wrapper around the graph canvas that installs the touch layer and prevents browser gesture conflicts.

### Modified files
- `webapp/src/app/layout.tsx` (MODIFY)  
  Add `viewport` metadata so mobile browsers use `width=device-width, initial-scale=1` and disable user scaling where appropriate.
- `webapp/src/components/layout/GlobalHeader/GlobalHeader.tsx` (MODIFY)  
  Increase mobile menu touch targets, add safe-area padding, close menu on overlay swipe, and keep the existing desktop nav intact.
- `webapp/src/components/layout/GlobalHeader/GlobalHeader.module.css` (MODIFY)  
  Mobile menu safe-area insets, larger nav item hit areas, and small screen header spacing.
- `webapp/src/components/layout/GlobalHeader/GlobalHeader.test.tsx` (MODIFY)  
  Add tests for the hamburger button and mobile menu open/close behavior.
- `webapp/src/components/layout/index.ts` (MODIFY)  
  Stop exporting the unused `NavigationBar`.
- `webapp/src/components/layout/NavigationBar/` (DELETE)  
  Remove the unused component directory (`NavigationBar.tsx`, `NavigationBar.module.css`, and any tests).
- `webapp/src/components/ui/Drawer/Drawer.tsx` (MODIFY)  
  Add touch drag-to-dismiss on overlay drawers and respect safe-area insets on mobile.
- `webapp/src/components/ui/Drawer/Drawer.module.css` (MODIFY)  
  Mobile drawer width/safe-area adjustments.
- `webapp/src/components/ui/Modal/Modal.module.css` (MODIFY)  
  Use `dvh` units and `env(safe-area-inset-bottom)` so bottom-sheet modals clear device notches/home indicators.
- `webapp/src/app/graph/components/GraphCanvas/GraphCanvas.module.css` (MODIFY)  
  Add `touch-action: none` to the wrapper so the browser does not scroll/page-zoom while interacting with the graph.
- `webapp/src/app/graph/components/GraphCanvas/GraphCanvas.tsx` (MODIFY)  
  Wrap the 2D/3D canvas in `GraphTouchLayer`; pass the graph ref to the touch layer.
- `webapp/src/app/graph/components/GraphCanvas/GraphCanvas2D.tsx` (MODIFY)  
  Ensure the d3-zoom `touchable` filter is enabled and expose any helper methods the touch layer needs.
- `webapp/src/app/graph/components/GraphCanvas/GraphNavControls.module.css` (MODIFY)  
  Larger buttons and repositioned padding on narrow screens.
- `webapp/src/app/graph/components/GraphCanvas/GraphNavControls.tsx` (MODIFY)  
  Use `touch-action: manipulation` and slightly larger icon sizes when the viewport is narrow.

## 3. Architecture / Key Decisions

### Approach
Implement a thin, non-invasive touch layer rather than replacing the graph renderer or adding a heavy gesture library.

1. **Viewport fix first** — Without the viewport meta tag, every other responsive fix is invisible to real phones. This is the highest-impact one-liner.
2. **Dead-code cleanup** — `NavigationBar` is exported but never used. Removing it reduces confusion and shrinks the bundle.
3. **Touch layer abstraction** — A new `GraphTouchLayer` sits between the canvas wrapper and `ForceGraph2D`/`ForceGraph3D`. It captures pointer/touch events, distinguishes 1-finger pan from 2-finger pinch, and calls the imperative `react-force-graph` APIs (`centerAt`, `zoom` for 2D; `cameraPosition` / `controls` for 3D). This keeps gesture logic out of the already-large 2D/3D canvas components.
4. **No new runtime dependencies** — We will use native `PointerEvent` / `TouchEvent` and small helpers instead of adding `@use-gesture` or `hammerjs`, keeping the bundle small and avoiding SSR issues with dynamically imported `react-force-graph`.
5. **Progressive enhancement** — On desktop, the touch layer does nothing; mouse wheel and d3-zoom/orbit controls continue to work exactly as before.

### Trade-offs considered

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Add `@use-gesture/react` | Rich gesture semantics, less code | Extra dependency, SSR/dynamic import edge cases, overkill for quick wins | Reject |
| Implement raw touch handlers in `GraphCanvas2D`/`3D` | Direct control | Bloats already-large files, duplicated for 2D/3D | Reject |
| Thin `GraphTouchLayer` wrapper + hook (chosen) | Reusable, testable, no new deps, minimal intrusion | Need to carefully avoid conflicting with node clicks | Adopt |
| Full PWA / native route | Best long-term mobile UX | Far beyond quick-win scope | Reject |

## 4. Step-by-Step Implementation

Each step is small, independent, and ordered so earlier changes do not depend on later ones.

### Step 1 — Fix the viewport meta tag
1. In `webapp/src/app/layout.tsx`, add the `viewport` export to the existing `metadata` object:
   ```ts
   export const viewport: Viewport = {
     width: 'device-width',
     initialScale: 1,
     maximumScale: 1,
     userScalable: false,
     viewportFit: 'cover',
   }
   ```
2. Import `Viewport` from `next`.
3. Verify dev server renders `<meta name="viewport">` in the HTML `<head>`.

### Step 2 — Remove unused `NavigationBar`
1. Delete `webapp/src/components/layout/NavigationBar/` (component, styles, tests).
2. Remove the `NavigationBar` export from `webapp/src/components/layout/index.ts`.
3. Run `npm run type-check` to confirm nothing imports it.

### Step 3 — Improve `GlobalHeader` mobile menu
1. Increase mobile nav item padding to at least `var(--space-3)` vertical to meet 44×44 pt touch target guidelines.
2. Add `padding-bottom: env(safe-area-inset-bottom)` to the slide-out menu.
3. Add a subtle swipe-to-close behavior on the overlay (touch start → move past threshold → close).
4. Keep existing desktop styles and close-on-route-change behavior.

### Step 4 — Update mobile menu tests
1. Add tests in `GlobalHeader.test.tsx`:
   - Hamburger button toggles the mobile menu.
   - Mobile menu contains the expected Core/Utilities links when open.
   - Clicking the overlay closes the menu.

### Step 5 — Improve `Drawer` and `Modal` mobile ergonomics
1. `Drawer`: add `touch-action: pan-y`/`none` as appropriate, drag-to-dismiss on overlay mode, and safe-area insets.
2. `Modal`: switch `max-height` to `90dvh` and add `padding-bottom: env(safe-area-inset-bottom)` for bottom-sheet behavior.

### Step 6 — Add graph touch layer CSS
1. In `GraphCanvas.module.css`, add `touch-action: none` to `.wrapper` so the browser does not scroll or zoom the page while the user interacts with the graph.

### Step 7 — Implement `useGraphTouchGestures`
1. Create `webapp/src/app/graph/hooks/useGraphTouchGestures.ts`.
2. Track active pointer/touch ids.
3. On one-pointer drag: compute delta and call `graphRef.current.centerAt(x + dx, y + dy)` (2D) or translate camera/controls target (3D).
4. On two-pointer pinch: compute distance ratio and call `graphRef.current.zoom(currentZoom * ratio)` (2D) or dolly camera along view vector (3D).
5. On tap/click with minimal movement: do nothing so `onNodeClick` still fires.
6. Return event handlers to attach to a container.

### Step 8 — Implement `GraphTouchLayer`
1. Create `webapp/src/app/graph/components/GraphCanvas/GraphTouchLayer.tsx`.
2. Accept `children`, `graphRef`, and `is3D` props.
3. Use the hook from Step 7 and render an absolutely positioned `<div>` over the canvas that captures pointer events.
4. Use `pointer-events: none` on the layer when no gesture is active? No — keep it capturing and let tap-through logic preserve node clicks. Actually, pass through quick taps by checking movement distance; attach `onPointerDown`/`Move`/`Up`/`Cancel`.

### Step 9 — Wire `GraphTouchLayer` into `GraphCanvas`
1. In `GraphCanvas.tsx`, wrap both the 2D and 3D graph renders with `<GraphTouchLayer graphRef={sharedGraphRef} is3D={effective3D}>`.
2. Ensure the layer has the same bounding box as the canvas via CSS.

### Step 10 — Verify 2D zoom integration
1. In `GraphCanvas2D.tsx`, make sure d3-zoom does not fight the custom touch layer. Use `fg.zoom().filter(event => !event.touches || event.touches.length < 2)` or disable d3 touch handling when our layer is active.
2. Confirm single-finger pan and two-finger pinch both work.

### Step 11 — Make `GraphNavControls` mobile-friendly
1. In `GraphNavControls.module.css`, add a media query for `max-width: 640px`:
   - `.btn` width/height → `40px`.
   - Move controls to `bottom: 12px; left: 12px` to avoid notches.
   - Increase opacity for visibility.
2. In `GraphNavControls.tsx`, bump `ICON_SIZE` to `16` on mobile via a window-width hook or CSS-only scaling.

### Step 12 — Add unit tests for gesture hook
1. Create `useGraphTouchGestures.test.ts`.
2. Test:
   - Pan gesture produces correct `centerAt` calls.
   - Pinch gesture produces correct `zoom` calls.
   - Small tap movements do not trigger pan/zoom.

### Step 13 — Manual verification
1. Run `npm run dev` and use browser DevTools device emulation (iPhone SE, Pixel 7).
2. Verify:
   - Viewport meta is present.
   - Header hamburger opens/closes.
   - Graph pan/zoom/pinch works.
   - Nav controls are tappable.
   - Drawers and modals render correctly without being clipped by safe areas.

### Step 14 — Lint and type check
1. Run `npm run lint` and `npm run type-check`.
2. Fix any errors.

## 5. Testing Strategy

### Unit tests
- `GlobalHeader.test.tsx`: mobile menu toggling, link presence in mobile view, close-on-overlay behavior.
- `useGraphTouchGestures.test.ts`: pan, pinch, tap-versus-drag thresholds, pointer cancellation.

### Integration / smoke tests
- Start the dev server and use Playwright or manual DevTools device emulation to confirm:
  - The graph page loads without horizontal overflow on 375 px width.
  - Pinch and pan gestures update the graph view.
  - Node tap still opens the node drawer.

### Edge cases
- Graph switches to 2D automatically above `AUTO_2D_THRESHOLD` nodes; verify touch layer still works.
- 3D mode orbit controls may already consume touch; ensure the touch layer does not double-handle rotation.
- iOS Safari: `100vh` vs. `100dvh` and safe-area insets must not clip the graph or menu.
- Desktop: verify mouse wheel zoom and node clicks are unchanged.

## 6. Risks & Rollback

| Risk | Likelihood | Mitigation |
|---|---|---|
| Custom touch layer conflicts with `react-force-graph` built-in touch handling, breaking node clicks. | Medium | Keep tap threshold small, only intercept move events with meaningful deltas, and test node drawer opening thoroughly. |
| Viewport meta with `userScalable=false` hurts accessibility. | Low | Keep `initialScale=1`; if complaints arise, remove `maximumScale`/`userScalable` constraints. |
| Removing `NavigationBar` breaks an import somewhere not caught by type check. | Low | Search the whole repo for `NavigationBar` before deleting; run build after deletion. |
| 3D orbit controls + touch layer cause double zoom/rotate. | Medium | Enable the touch layer only for 2D in the first iteration, or gate 3D touch handling behind a feature check. |
| Safe-area CSS not applied because `viewportFit=cover` is missing. | Low | Include `viewportFit: 'cover'` in the viewport metadata. |

### Rollback
All changes are additive or contained to a few files. If anything fails:
1. Revert `webapp/src/app/layout.tsx` to the previous metadata object.
2. Revert `GraphCanvas.tsx` to remove `GraphTouchLayer`.
3. Restore `NavigationBar` from git if deletion causes issues.
4. Revert CSS changes individually.

The only destructive step is deleting `NavigationBar`; this will be done only after confirming zero imports.
