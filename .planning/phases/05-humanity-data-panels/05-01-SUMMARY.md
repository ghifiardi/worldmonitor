---
phase: 05-humanity-data-panels
plan: 01
subsystem: ui
tags: [animation, requestAnimationFrame, counters, Intl.NumberFormat, panel]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: Panel base class, happy theme CSS, variant detection
provides:
  - CounterMetric interface and COUNTER_METRICS array (6 positive global metrics)
  - getCounterValue() absolute-time calculation function
  - formatCounterValue() locale-aware number formatter
  - CountersPanel component with 60fps animated ticking counters
affects: [05-02, 05-03, app-wiring]

# Tech tracking
tech-stack:
  added: []
  patterns: [requestAnimationFrame animation loop, absolute-time counter calculation, textContent-only DOM updates]

key-files:
  created:
    - src/services/humanity-counters.ts
    - src/components/CountersPanel.ts
  modified: []

key-decisions:
  - "Emoji icons encoded as Unicode escapes in TS source for cross-platform safety"
  - "Counter values calculated from absolute time (seconds since midnight UTC * rate) not delta accumulation, preventing drift across tabs/throttling"
  - "startTicking() called in constructor for immediate animation start"

patterns-established:
  - "Absolute-time counter pattern: derive display value from wall clock, never accumulate deltas"
  - "60fps DOM update pattern: textContent only, Map<id, HTMLElement> for O(1) element lookup"

requirements-completed: [COUNT-01, COUNT-02, COUNT-03]

# Metrics
duration: 2min
completed: 2026-02-23
---

# Phase 5 Plan 01: Ticking Counters Summary

**Worldometer-style ticking counters service with 6 positive metrics (births, trees, vaccines, graduates, books, renewable MW) animated at 60fps via requestAnimationFrame using absolute-time calculation**

## Performance

- **Duration:** 2 min
- **Started:** 2026-02-23T08:35:25Z
- **Completed:** 2026-02-23T08:37:49Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Created humanity-counters service with 6 metric definitions sourced from UN/WHO/World Bank/UNESCO annual totals
- Per-second rates pre-calculated from annual totals / 31,536,000 seconds per year
- Absolute-time getCounterValue() prevents drift across tabs, throttling, or background suspension
- CountersPanel extends Panel with counters-grid layout, 60fps requestAnimationFrame animation loop
- All DOM updates use textContent (not innerHTML) for zero layout thrashing at 60fps

## Task Commits

Each task was committed atomically:

1. **Task 1: Create humanity counters service** - `608c9ba` (feat)
2. **Task 2: Create CountersPanel component** - `6ed8b47` (feat)

## Files Created/Modified
- `src/services/humanity-counters.ts` - Counter metric definitions (6 metrics), getCounterValue(), formatCounterValue(), CounterMetric interface
- `src/components/CountersPanel.ts` - Panel subclass with 6 animated counter cards, requestAnimationFrame loop, startTicking()/destroy() lifecycle

## Decisions Made
- Emoji icons stored as Unicode escape sequences in TypeScript source for cross-platform compatibility
- Counter values use absolute-time calculation (seconds since midnight UTC * per-second rate) rather than delta accumulation, preventing drift when tabs are backgrounded or throttled
- startTicking() is called in constructor so counters begin animating immediately on creation
- No API calls needed -- all rates are hardcoded constants from published annual totals

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- CountersPanel ready for App.ts wiring (plan 05-03 or similar)
- CSS styles for `.counters-grid`, `.counter-card`, `.counter-value`, `.counter-icon`, `.counter-label`, `.counter-source` needed in happy-theme.css
- `font-variant-numeric: tabular-nums` should be applied to `.counter-value` to prevent layout shift as digits change

## Self-Check: PASSED

- FOUND: src/services/humanity-counters.ts
- FOUND: src/components/CountersPanel.ts
- FOUND: 05-01-SUMMARY.md
- FOUND: commit 608c9ba
- FOUND: commit 6ed8b47

---
*Phase: 05-humanity-data-panels*
*Completed: 2026-02-23*
