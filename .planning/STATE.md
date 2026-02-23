# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-22)

**Core value:** Every piece of content on the dashboard makes the viewer feel genuinely better about humanity
**Current focus:** Phase 5 - Humanity Data Panels (1/3 plans done)

## Current Position

Phase: 5 of 9 (Humanity Data Panels)
Plan: 1 of 3 in current phase (05-01 complete)
Status: In Progress
Last activity: 2026-02-23 -- Completed 05-01-PLAN.md (Ticking Counters Service & Panel)

Progress: [###-------] 33%

## Performance Metrics

**Velocity:**
- Total plans completed: 13
- Average duration: 12 min
- Total execution time: 2.7 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01 | 3 | 120 min | 40 min |
| 02 | 3 | 7 min | 2 min |
| 03 | 3 | 9 min | 3 min |
| 04 | 3 | 19 min | 6 min |
| 05 | 1 | 2 min | 2 min |

**Recent Trend:**
- Last 5 plans: 3m, 4m, 9m, 6m, 2m
- Trend: Phase 5 started -- plan 01 done in 2m

*Updated after each plan completion*
| Phase 04 P01 | 4 | 2 tasks | 9 files |
| Phase 04 P02 | 9 | 2 tasks | 14 files |
| Phase 04 P03 | 6 | 2 tasks | 4 files |
| Phase 05 P01 | 2 | 2 tasks | 2 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: Curated feeds before ML filtering -- research confirms sentiment false positives (sarcasm, ironic headlines) make ML-only gating unreliable. Curated sources are primary, ML is supplement.
- [Roadmap]: Only 2 new npm deps needed (papaparse, canvas-confetti) -- everything else uses existing infrastructure.
- [Roadmap]: WHO GHO API may be deprecated -- use World Bank as primary for health indicators to de-risk.
- [01-01]: Favicon paths handled via regex replacement in htmlVariantPlugin -- single index.html source of truth.
- [01-01]: Google Fonts loaded unconditionally (minimal overhead, CSS scoping prevents visual impact on non-happy variants).
- [01-01]: Hostname-based variant detection extended to all variants (tech, finance, happy) in inline script.
- [01-02]: Semantic colors use celebration/nature metaphors: gold=critical, sage=growth, blue=hope, pink=kindness.
- [01-02]: Dark mode uses deep navy (#1A2332) base, never pure black.
- [01-02]: --panel-radius introduced as CSS variable (14px) for downstream panel rounding in Plan 03.
- [01-03]: CSS @layer base introduced to control cascade -- happy-theme overrides sit outside @layer so they always win over :root defaults.
- [01-03]: data-variant attribute set on <html> from SITE_VARIANT enables pure-CSS variant scoping without runtime JS.
- [01-03]: Self-hosted MapLibre style JSONs with CARTO CDN tile sources -- pattern for per-variant basemaps.
- [02-01]: 8 feeds from 4 verified positive sources (GNN, Positive.News, Reasons to be Cheerful, Optimist Daily) -- unverified sources excluded.
- [02-01]: GDELT tone_filter appended server-side to query string, sort param replaces hardcoded 'date' -- backward compatible with empty defaults.
- [02-01]: Existing fetchGdeltArticles() passes empty toneFilter/sort to satisfy generated type requirements without changing behavior.
- [02-02]: Priority-ordered keyword tuples (Array<[string, category]>) guarantee evaluation order -- specific keywords checked before generic.
- [02-02]: Default category is 'humanity-kindness' for curated positive sources that don't match any keyword.
- [02-02]: Source-based pre-mapping for GNN category feeds (fast path) before keyword scan (slow path).
- [02-03]: In-place for..of mutation in loadNewsCategory() since items array already referenced by closures.
- [02-03]: Classification after fetchCategoryFeeds completes (not in onBatch callback) -- final render uses complete set.
- [03-01]: Additive-only guards -- all changes use SITE_VARIANT !== 'happy' to avoid touching full/tech/finance paths.
- [03-01]: Natural map layer kept for happy variant (earthquakes informational, not geopolitical).
- [03-01]: InsightsPanel available for all variants since it adapts to available data.
- [03-01]: Defense-in-depth for LiveNewsPanel: both panel creation gating AND empty channels array.
- [03-02]: CSS variable names in plan were hypothetical -- mapped to actual happy theme vars (--yellow for gold, --green for sage, --semantic-info for hope-blue, --red for kindness-pink).
- [03-02]: Category badge colors: science=blue, nature=green, kindness=pink, innovation=gold, climate=#2d9a4e, culture=#8b5cf6.
- [03-02]: extractImageUrl uses 4-strategy fallback with try/catch per strategy -- never throws, always returns undefined on failure.
- [03-03]: GdeltArticle field mapping: article.date (not seenDate), article.image (not socialImage) -- adapted to actual API shape.
- [03-03]: Two-phase render: curated RSS renders immediately, GDELT+ML supplements async -- never blocks UX on ML.
- [03-03]: happyAllItems accumulator: reset at loadNews() start, concat in loadNewsCategory(), consumed in pipeline.
- [04-01]: Happy variant layer toggles use hardcoded English labels (no i18n keys yet, consistent with Phase 3 pattern).
- [04-01]: Legend colors: green for positive, gold for breakthrough, light green for kindness, orange for natural (matches happy theme warm palette).
- [04-02]: INT64_ENCODING_NUMBER on PositiveGeoEvent.timestamp ensures number type in generated TypeScript (project convention).
- [04-02]: Server-side GDELT GEO uses 2 compound queries with 500ms delay, count>=3 noise filter (balances API calls vs coverage).
- [04-02]: Pulse animation at 500ms period (slower than hotspots' 400ms) for calmer positive feel.
- [04-02]: MapContainer.setPositiveEvents delegates to DeckGLMap only (SVG map does not support positive events layer).
- [04-03]: Baseline kindness points use Math.random() jitter (not seeded) -- regenerates every refresh cycle for "alive" feeling.
- [04-03]: Real kindness events pulse at 600ms period (slower than positive events' 500ms) for gentler, calming feel.
- [04-03]: MapContainer.setKindnessData delegates to DeckGLMap only (SVG map does not support kindness layer).
- [05-01]: Counter values use absolute-time calculation (seconds since midnight UTC * rate) not delta accumulation, preventing drift across tabs/throttling.
- [05-01]: startTicking() called in constructor for immediate animation start; no separate init step needed.
- [05-01]: Emoji icons encoded as Unicode escapes in TS source for cross-platform safety.

### Pending Todos

None yet.

### Blockers/Concerns

- MEDIUM risk: Sentiment threshold (0.85) now implemented with localStorage override ('positive-threshold') -- still needs experimentation.
- LOW risk: Positive.News RSS added in 02-01 (URL verified). Future Crunch excluded (unverified RSS URL).
- LOW risk: @huggingface/transformers v4 preview dropped Feb 2026 -- do NOT use, stick with existing v2/v3 stable.

## Session Continuity

Last session: 2026-02-23
Stopped at: Completed 05-01-PLAN.md (Ticking Counters Service & Panel)
Resume file: .planning/phases/05-humanity-data-panels/05-01-SUMMARY.md
