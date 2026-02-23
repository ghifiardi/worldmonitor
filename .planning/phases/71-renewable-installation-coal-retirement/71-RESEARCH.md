# Phase 7.1: Renewable Energy Installation & Coal Retirement Data - Research

**Researched:** 2026-02-23
**Domain:** EIA electricity capacity data integration + D3 visualization for solar/wind growth and coal decline
**Confidence:** HIGH (existing codebase patterns are proven; EIA API v2 is already integrated; D3 already in project)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ENERGY-01 | Renewable energy capacity visualization showing solar/wind installations growing, coal plants closing | EIA API v2 `state-electricity-profiles/capability` endpoint provides pre-aggregated annual capacity (MW) by energy source since 1990. Solar = `SUN`, Wind = `WND`, Coal = `COL`. This is the recommended endpoint over `operating-generator-capacity` because it returns aggregated state-level totals (not individual generators), requiring only client-side state summation for national totals. The existing `get-energy-prices.ts` handler pattern can be directly replicated for a new RPC. |
| ENERGY-03 | Data from IEA Renewable Energy Progress Tracker and existing EIA API integration | Phase 7 already satisfied the IEA portion via World Bank `EG.ELC.RNEW.ZS` (IEA SE4ALL-sourced). This phase adds the EIA API integration component. The project already has `EIA_API_KEY` configured and an existing EIA handler at `server/worldmonitor/economic/v1/get-energy-prices.ts`. Extending the EconomicService with a new `GetEnergyCapacity` RPC is the standard approach. |
</phase_requirements>

---

## Summary

Phase 7.1 closes the verification gap identified in 07-VERIFICATION.md: the existing RenewableEnergyPanel shows a World Bank percentage gauge but lacks solar/wind installation growth and coal retirement visualizations. The fix requires two additions: (1) a new server-side RPC that fetches EIA capacity data, and (2) new D3 visualizations in the existing panel.

The EIA API v2 provides two possible endpoints for capacity data. The **recommended endpoint** is `/v2/electricity/state-electricity-profiles/capability/` which returns pre-aggregated annual summer capacity (MW) by state and energy source (since 1990, sourced from Form EIA-860). The alternative `operating-generator-capacity` endpoint returns plant-level monthly data (thousands of records) requiring heavy server-side aggregation. The `state-electricity-profiles/capability` approach needs only ~50-100 records per energy source per year and simple summation across states for a national total.

The implementation follows existing patterns exactly: a new proto message and RPC in the economic service, a new server handler mirroring `get-energy-prices.ts`, a client-side service function in `src/services/renewable-energy-data.ts`, and new D3 chart sections appended below the existing gauge in `RenewableEnergyPanel.ts`. No new npm packages are needed. The panel already uses D3 for the gauge and sparkline; the new charts extend this with stacked area/bar charts for capacity growth and a declining trend line for coal.

**Primary recommendation:** Add a `GetEnergyCapacity` RPC to the existing EconomicService that fetches from EIA `state-electricity-profiles/capability`. Render the data as a D3 stacked area chart (solar + wind growth over time) and a separate declining trend for coal capacity, placed below the existing gauge and sparkline in the RenewableEnergyPanel.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Vanilla TypeScript | Project standard | Service + panel code | No framework (project decision) |
| D3.js | Already in project (`d3` package) | Stacked area chart, bar chart, trend lines | Already used by this panel for gauge + sparkline |
| `Panel` base class | `src/components/Panel.ts` | RenewableEnergyPanel extends this | Mandatory for all happy variant panels |
| sebuf proto/RPC | Already in project | New `GetEnergyCapacity` RPC | All server-side data fetching uses sebuf RPCs |
| EIA API v2 | `https://api.eia.gov/v2/` | Capacity data source | Already integrated for energy prices |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `getCSSColor()` | `src/utils/index.ts` | Theme-aware colors for new D3 charts | Must use for all chart colors (dark mode) |
| `replaceChildren()` | `src/utils/dom-utils.ts` | Safe DOM clearing on re-render | Used by all Panel subclasses |
| `createCircuitBreaker()` | `src/utils/index.ts` | Resilient EIA API calls | Wrap new capacity fetch in circuit breaker |
| `dataFreshness` | `src/services/data-freshness.ts` | Track update timestamps | Record when capacity data updates |
| `getCachedJson/setCachedJson` | `server/_shared/redis.ts` | Redis caching for EIA responses | Cache capacity data (annual data, 24h TTL appropriate) |
| `isFeatureAvailable('energyEia')` | `src/services/runtime-config.ts` | Feature gating for EIA dependency | Graceful degradation when EIA_API_KEY missing |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `state-electricity-profiles/capability` | `operating-generator-capacity` | Plant-level data (thousands of records), requires server-side aggregation, monthly frequency but annual totals still need grouping. Capability endpoint is pre-aggregated. |
| New `GetEnergyCapacity` RPC | Extend `GetEnergyPrices` response | Cleaner separation of concerns; capacity data is structurally different from price data |
| Stacked area chart | Grouped bar chart | Area chart better shows cumulative growth over time; bar chart better for year-over-year comparison. Both valid. |
| Sum all states for US total | Filter by "US" stateid | It is unclear if the capability endpoint supports "US" as a stateid for national aggregate. Summing all 50 states + DC is the safe approach and guarantees correct totals. |

**Installation:** No new npm packages required.

---

## Architecture Patterns

### Recommended Data Flow

```
EIA API v2 (/electricity/state-electricity-profiles/capability/data/)
    |
    v
Server Handler (server/worldmonitor/economic/v1/get-energy-capacity.ts)
    |-- Fetches SUN, WND, COL capacity by year
    |-- Sums across all states for US national total per year
    |-- Redis cache (24h TTL — annual data)
    v
Sebuf RPC (GetEnergyCapacity → GetEnergyCapacityResponse)
    |
    v
Client Service (src/services/renewable-energy-data.ts)
    |-- Circuit breaker wrapper
    |-- Feature gating (energyEia)
    v
RenewableEnergyPanel.ts
    |-- Existing: gauge + sparkline + regions (World Bank data)
    |-- NEW: capacity growth chart (solar + wind stacked area)
    |-- NEW: coal decline chart (declining trend line)
```

### Pattern 1: New RPC in Existing Service

**What:** Add `GetEnergyCapacity` RPC to the existing EconomicService proto, following the exact same pattern as `GetEnergyPrices`.

**When to use:** When adding a new data source from the same provider (EIA) within the same domain (economic/energy).

**Example proto:**
```protobuf
// get_energy_capacity.proto
message GetEnergyCapacityRequest {
  // Energy source codes to query (e.g., "SUN", "WND", "COL").
  // Empty returns all tracked sources.
  repeated string energy_sources = 1;
  // Number of years of historical data. Default 20.
  int32 years = 2;
}

message EnergyCapacityYear {
  // Year (e.g., 2024).
  int32 year = 1;
  // Total US summer capacity in MW for this energy source and year.
  double capacity_mw = 2;
}

message EnergyCapacitySeries {
  // Energy source code (e.g., "SUN", "WND", "COL").
  string energy_source = 1;
  // Human-readable name (e.g., "Solar", "Wind", "Coal").
  string name = 2;
  // Annual capacity data points, sorted oldest first.
  repeated EnergyCapacityYear data = 3;
}

message GetEnergyCapacityResponse {
  repeated EnergyCapacitySeries series = 1;
}
```

### Pattern 2: Server Handler Aggregation

**What:** The handler fetches per-state data from EIA and aggregates to national totals. This keeps the client thin and avoids exposing state-level complexity.

**When to use:** When the upstream API does not provide the exact aggregation level needed (state-level vs. national).

**Example handler approach:**
```typescript
// server/worldmonitor/economic/v1/get-energy-capacity.ts
// For each energy source (SUN, WND, COL):
//   1. Fetch all states' annual capacity from EIA
//   2. Group by year
//   3. Sum capacity across all states for each year
//   4. Return sorted time-series

const EIA_CAPACITY_SOURCES = [
  { code: 'SUN', name: 'Solar' },
  { code: 'WND', name: 'Wind' },
  { code: 'COL', name: 'Coal' },
];

// API URL pattern:
// /v2/electricity/state-electricity-profiles/capability/data/
//   ?api_key=XXX
//   &data[]=capability
//   &frequency=annual
//   &facets[energysourceid][]=SUN
//   &sort[0][column]=period&sort[0][direction]=desc
//   &length=5000
```

### Pattern 3: Extend Existing Panel with New Sections

**What:** Add new visualization sections to `RenewableEnergyPanel.setData()` below the existing gauge + sparkline + regions. The new data type is passed via a separate method or an extended data interface.

**When to use:** When extending an existing panel with additional data sources that arrive from different RPCs (World Bank vs. EIA).

**Example:**
```typescript
// In RenewableEnergyPanel.ts — new method alongside setData()
public setCapacityData(series: EnergyCapacitySeries[]): void {
  // Find or create the capacity section container
  // Render stacked area chart for solar + wind
  // Render declining trend for coal
}
```

### Anti-Patterns to Avoid

- **Fetching `operating-generator-capacity` and aggregating thousands of plant records on each request:** This endpoint returns individual generators. For 2024, there are ~23,000 operating generators in the US. Summing them per request is wasteful when `state-electricity-profiles/capability` provides pre-aggregated state totals (only ~50 records per energy source per year).
- **Mixing EIA capacity data into the existing `fetchRenewableEnergyData()` call:** The existing function fetches World Bank data. EIA capacity data should arrive through a separate RPC and be set on the panel via a separate method. This keeps the World Bank gauge working independently of EIA availability.
- **Hardcoding capacity numbers:** Do not use static data for capacity charts. The whole point of this phase is to use the EIA API for live data. The existing renewable-installations.json (92 curated installations for map markers) is separate from the aggregate capacity time-series.
- **Blocking panel render on EIA failure:** If EIA is down or EIA_API_KEY is missing, the existing gauge + sparkline + regions should still render from World Bank data. The capacity chart section should show a graceful "Data unavailable" state.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| EIA data fetching | Direct `fetch()` in client | New sebuf RPC via server handler | API key protection, Redis caching, circuit breaker |
| State → national aggregation | Client-side aggregation | Server-side aggregation in handler | Cleaner client code, caching of aggregated result |
| Stacked area chart | Custom SVG path math | D3 `d3.stack()` + `d3.area()` | D3 stack layout handles baseline calculation, missing data |
| Theme-aware chart colors | Hardcoded hex colors | `getCSSColor('--green')`, `getCSSColor('--red')` etc. | Dark mode support is mandatory |
| Annual date parsing | Manual string parsing | `parseInt(period, 10)` (YYYY format) | EIA annual data uses simple YYYY strings |

**Key insight:** This phase adds NO new libraries. Every building block exists: D3 for charts, sebuf for RPCs, Redis for caching, EIA API patterns in `get-energy-prices.ts`. The work is wiring existing patterns to a new data source and rendering.

---

## Common Pitfalls

### Pitfall 1: EIA `state-electricity-profiles/capability` May Not Support "US" as a stateid

**What goes wrong:** Assuming there is a "US" national aggregate row and filtering for it, getting zero results.
**Why it happens:** The endpoint is documented as "by state" — it may only have 50 states + DC + territories, not a pre-computed national total.
**How to avoid:** Query without stateid filter, fetch all states for the desired energy source and year range, then sum `capability` values grouped by year on the server side. This guarantees correct national totals.
**Warning signs:** Empty response when filtering for stateid "US"; discrepancy between state sum and expected national total.

### Pitfall 2: Coal Energy Source Code Ambiguity (COL vs. BIT/SUB/LIG/RC)

**What goes wrong:** Using only "COL" as the energy source code and getting no results, or using BIT/SUB/LIG/RC and missing some coal capacity.
**Why it happens:** Different EIA endpoints use different coal codes. The `operating-generator-capacity` endpoint uses specific codes (BIT, SUB, LIG, RC) while `state-electricity-profiles/capability` may use an aggregate "COL" code, or it may use the specific sub-types.
**How to avoid:** At implementation time, first query the facet values endpoint (`/v2/electricity/state-electricity-profiles/capability/facet/energysourceid`) with the real API key to discover exact available codes. Fall back to querying all coal sub-types (BIT, SUB, LIG, RC) and summing if "COL" is not available.
**Warning signs:** Coal capacity numbers seem too low or zero.

### Pitfall 3: EIA Data Only Covers the US

**What goes wrong:** Presenting EIA capacity data as if it represents global solar/wind/coal trends.
**Why it happens:** EIA is the US Energy Information Administration — it only covers US generators.
**How to avoid:** Label all capacity charts explicitly as "US Installed Capacity" or "US Solar/Wind Growth." The existing gauge (World Bank data) is global; the new capacity chart is US-specific. Make this distinction clear in the UI with section headers or labels.
**Warning signs:** Users question why the "renewable %" (global) and capacity numbers (US) don't align.

### Pitfall 4: Stale Annual Data

**What goes wrong:** The capacity chart shows data only through 2023 or 2024, looking outdated.
**Why it happens:** EIA Form 860 annual data has a ~6 month publication lag. The "capability" endpoint covers 1990-2024 (as of 2025 publication). Monthly data from `operating-generator-capacity` is more current but plant-level.
**How to avoid:** Display the data year range in the chart (e.g., "1990-2024"). Accept that annual capacity data will always lag 6-12 months. Consider displaying the latest year's data as a highlighted endpoint on the chart.
**Warning signs:** Chart appears to stop at a year that's "old" from the user's perspective.

### Pitfall 5: Panel Height Overflow

**What goes wrong:** Adding two more chart sections (capacity growth + coal decline) below the existing gauge + sparkline + regions makes the panel too tall, requiring excessive scrolling.
**Why it happens:** The existing panel already has 3 visual sections. Adding 2 more = 5 sections in one panel.
**How to avoid:** Design the capacity visualizations to be compact. Options: (a) single chart with solar, wind, and coal as three series in one stacked/grouped view; (b) tabbed view between "Renewable %" and "Installation Growth"; (c) keep each chart small (~80-100px height). Recommendation: single compact chart (Option a) with a section header separator.
**Warning signs:** Panel becomes taller than 2 grid spans; users don't scroll down to see the new data.

### Pitfall 6: Proto Codegen Forgetting

**What goes wrong:** Adding the new proto file and RPC but forgetting to run `cd proto && buf generate`, resulting in missing generated client/server types.
**Why it happens:** Proto codegen is a manual step in this project.
**How to avoid:** Run `cd proto && buf generate` immediately after editing any `.proto` files. Verify the generated files exist before writing handler/service code.
**Warning signs:** TypeScript errors about missing types from `@/generated/...`.

---

## Code Examples

Verified patterns from the existing codebase:

### EIA API Fetch Pattern (from get-energy-prices.ts)

```typescript
// Source: server/worldmonitor/economic/v1/get-energy-prices.ts lines 46-94
// This is the exact pattern to replicate for capacity data.
async function fetchEiaSeries(config, apiKey) {
  const params = new URLSearchParams({
    api_key: apiKey,
    'data[]': 'value',             // For capacity: 'data[]': 'capability'
    frequency: 'weekly',            // For capacity: frequency: 'annual'
    'facets[series][]': config.seriesFacet,  // For capacity: 'facets[energysourceid][]': 'SUN'
    'sort[0][column]': 'period',
    'sort[0][direction]': 'desc',
    length: '2',                    // For capacity: '5000' (all states * 30 years)
  });

  const response = await fetch(`https://api.eia.gov${config.apiPath}?${params}`, {
    headers: { Accept: 'application/json', 'User-Agent': CHROME_UA },
    signal: AbortSignal.timeout(10000),
  });
  // ... parse response.response.data array
}
```

### Capacity API URL Construction

```typescript
// New handler: get-energy-capacity.ts
// EIA state-electricity-profiles/capability endpoint
const apiPath = '/v2/electricity/state-electricity-profiles/capability/data/';

const params = new URLSearchParams({
  api_key: apiKey,
  'data[]': 'capability',           // Summer capacity in MW
  frequency: 'annual',              // YYYY format
  'facets[energysourceid][]': energySource,  // 'SUN', 'WND', or 'COL'
  'sort[0][column]': 'period',
  'sort[0][direction]': 'desc',
  length: '5000',                   // Up to 50 states * 35 years
});
// Optional: add start year to reduce response size
// params.set('start', '2000');
```

### Server-Side State Aggregation

```typescript
// Aggregate per-state records to national totals by year
interface EiaCapabilityRow {
  period: string;       // "2024"
  stateid: string;      // "CA", "TX", etc.
  capability: number;   // MW for this state/source/year
  // ... other fields
}

function aggregateToNational(rows: EiaCapabilityRow[]): Map<number, number> {
  const byYear = new Map<number, number>();
  for (const row of rows) {
    const year = parseInt(row.period, 10);
    if (isNaN(year) || row.capability == null) continue;
    byYear.set(year, (byYear.get(year) ?? 0) + row.capability);
  }
  return byYear; // year -> total US capacity MW
}
```

### D3 Stacked Area Chart Pattern

```typescript
// D3 stacked area chart for solar + wind capacity growth
// Based on the existing sparkline pattern in RenewableEnergyPanel.ts

const stack = d3.stack<{ year: number; solar: number; wind: number }>()
  .keys(['solar', 'wind'])
  .order(d3.stackOrderNone)
  .offset(d3.stackOffsetNone);

const series = stack(data);

const area = d3.area<d3.SeriesPoint<{ year: number; solar: number; wind: number }>>()
  .x(d => x(d.data.year))
  .y0(d => y(d[0]))
  .y1(d => y(d[1]))
  .curve(d3.curveMonotoneX);

// Render each series
for (const s of series) {
  g.append('path')
    .datum(s)
    .attr('d', area)
    .attr('fill', s.key === 'solar' ? getCSSColor('--yellow') : getCSSColor('--blue'))
    .attr('opacity', 0.7);
}
```

### Extending RenewableEnergyPanel with Capacity Data

```typescript
// Source pattern: RenewableEnergyPanel.ts setData() + new setCapacityData()
// The existing setData() handles World Bank gauge. The new method handles EIA capacity.

// In App.ts loadRenewableData():
private async loadRenewableData(): Promise<void> {
  // Existing World Bank data (unchanged)
  const data = await fetchRenewableEnergyData();
  this.renewablePanel?.setData(data);

  // NEW: EIA capacity data (independent, gracefully degradable)
  try {
    const capacity = await fetchEnergyCapacity();
    this.renewablePanel?.setCapacityData(capacity);
  } catch {
    // EIA failure doesn't break the existing gauge
  }
}
```

### Handler Registration Pattern

```typescript
// Source: server/worldmonitor/economic/v1/handler.ts
// Add new import and handler method:
import { getEnergyCapacity } from './get-energy-capacity';

export const economicHandler: EconomicServiceHandler = {
  getFredSeries,
  listWorldBankIndicators,
  getEnergyPrices,
  getMacroSignals,
  getEnergyCapacity,  // NEW
};
```

---

## EIA API Endpoints Comparison

| Endpoint | Path | Data Level | Frequency | Records per Query | Aggregation Needed |
|----------|------|------------|-----------|-------------------|-------------------|
| **state-electricity-profiles/capability** (RECOMMENDED) | `/v2/electricity/state-electricity-profiles/capability/data/` | State-level | Annual (1990-2024) | ~50 states * 35 years = ~1,750 per source | Sum states for national total |
| operating-generator-capacity | `/v2/electricity/operating-generator-capacity/data/` | Plant-level | Monthly (2008-2025) | ~23,000 generators per year | Sum all generators per year and source |

**Decision: Use `state-electricity-profiles/capability`** because:
1. Pre-aggregated to state level (far fewer records)
2. Annual frequency aligns with the visualization need (year-over-year growth)
3. Covers 1990-2024 (vs. 2008-2025 for operating-generator-capacity)
4. Same data source (EIA-860 form) backs both endpoints
5. Simpler server-side aggregation (50 rows per year vs. thousands)

### Known EIA Energy Source Codes

| Code | Description | Category | Use In Phase 7.1 |
|------|-------------|----------|-------------------|
| SUN | Solar (all types) | Renewable | Solar capacity growth chart |
| WND | Wind | Renewable | Wind capacity growth chart |
| COL | Coal (aggregate) | Fossil | Coal decline chart |
| BIT | Bituminous Coal | Fossil | Fallback if COL not available |
| SUB | Subbituminous Coal | Fossil | Fallback if COL not available |
| LIG | Lignite | Fossil | Fallback if COL not available |
| RC | Refined Coal | Fossil | Fallback if COL not available |

**Important note (MEDIUM confidence):** The exact `energysourceid` values in the `capability` endpoint may differ from the `energy_source_code` values in `operating-generator-capacity`. The codes listed above are from the operating-generator-capacity endpoint documentation. The capability endpoint's facet values must be verified at implementation time by querying `/v2/electricity/state-electricity-profiles/capability/facet/energysourceid`.

---

## Visualization Design Recommendations

### Option A: Single Combined Chart (Recommended)

A single compact chart with three series:
- **Solar (gold/yellow):** Stacked area showing MW growth since ~2010
- **Wind (blue):** Stacked area showing MW growth since ~2000
- **Coal (red/gray, inverted):** Declining trend line showing MW decrease since ~2010

This fits in ~100-120px height with a section header "US Installed Capacity (EIA)".

### Option B: Dual Charts

Two separate mini-charts:
1. **Renewables Growth:** Stacked area (solar + wind) ~80px
2. **Coal Decline:** Single declining area ~60px

More space required but clearer separation.

### Option C: Tabbed Sections

Tab buttons: "Global %" | "US Capacity"
- "Global %" shows existing gauge + sparkline + regions
- "US Capacity" shows the new capacity charts

Saves vertical space but hides data behind a click.

**Recommendation:** Option A for compactness. The phase success criteria say "both EIA and World Bank data are used together" which implies they should be visible simultaneously, ruling out Option C. Option A is more compact than B.

### Color Scheme (Theme-Aware)

| Series | CSS Variable | Meaning |
|--------|-------------|---------|
| Solar | `--yellow` or custom amber | Warm energy from sun |
| Wind | `--blue` or `--info` | Cool, airy |
| Coal | `--red` or `--semantic-critical` | Declining fossil fuel |
| Background | `--border` | Chart grid background |

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| EIA API v1 series IDs | EIA API v2 faceted queries | 2023 | v2 uses RESTful routes with facet filtering; no more series ID lookups |
| Individual generator queries | State-profiles aggregate endpoint | Available since v2 | Pre-aggregated data reduces client/server work |
| Hardcoded renewable capacity figures | Live API annual data | This phase | Dynamic data that updates with each EIA publication |

**Deprecated/outdated:**
- EIA API v1: Fully retired. Project already uses v2 in `get-energy-prices.ts`.
- Manual EIA data downloads: The API provides all the same data programmatically.

---

## Open Questions

1. **Exact `energysourceid` facet values in `capability` endpoint**
   - What we know: The `operating-generator-capacity` endpoint uses SUN, WND, BIT, SUB, LIG, RC. The `capability` endpoint may use different codes (e.g., "Coal" vs "COL", "Solar" vs "SUN").
   - What's unclear: Whether the capability endpoint uses the same 3-letter codes or different identifiers.
   - Recommendation: At implementation time, query the facet endpoint first: `/v2/electricity/state-electricity-profiles/capability/facet/energysourceid?api_key=XXX`. Build the handler to be resilient to code variations.
   - **Confidence:** MEDIUM — the exact codes need live API validation.

2. **National aggregate availability via "US" stateid**
   - What we know: The endpoint has a `stateid` facet. It is documented as "State / Census Region."
   - What's unclear: Whether "US" is a valid stateid that returns a pre-computed national total.
   - Recommendation: Don't depend on "US" stateid. Always fetch all states and aggregate server-side. If "US" happens to work, it's a bonus optimization.
   - **Confidence:** LOW — could not verify without live API call.

3. **Response size and pagination**
   - What we know: EIA API v2 has a 5,000 row JSON limit per request.
   - What's unclear: Whether fetching all states for one energy source and 35 years exceeds this limit (50 states * 35 years = 1,750 rows per source, well within limit).
   - Recommendation: Use `length=5000` to be safe. Should comfortably fit in one request per energy source.
   - **Confidence:** HIGH — 1,750 records is well within the 5,000 limit.

4. **Chart section height budget**
   - What we know: The existing RenewableEnergyPanel has gauge (140px) + sparkline (40px) + regions (~120px) = ~300px. Panel default span is 1 (~200px viewport units).
   - What's unclear: Whether adding ~120px of capacity charts will require the panel to use span-2 by default.
   - Recommendation: Design capacity section to fit in 100-120px. If the total panel height exceeds one span, set the panel to `priority: 1` and `span-2` in the config or let the user resize.
   - **Confidence:** HIGH — manageable with compact chart design.

---

## Sources

### Primary (HIGH confidence)
- Existing codebase: `server/worldmonitor/economic/v1/get-energy-prices.ts` — verified EIA API v2 handler pattern (URL construction, response parsing, Redis caching, error handling)
- Existing codebase: `src/components/RenewableEnergyPanel.ts` — verified panel structure, D3 gauge/sparkline patterns
- Existing codebase: `src/services/renewable-energy-data.ts` — verified World Bank data fetching and data types
- Existing codebase: `proto/worldmonitor/economic/v1/service.proto` — verified proto service structure and RPC pattern
- EIA API v2 metadata: `https://api.eia.gov/v2/electricity/state-electricity-profiles/capability?api_key=DEMO_KEY` — confirmed endpoint exists with annual frequency, `capability` data column (MW), facets for stateid, energysourceid, producertypeid
- EIA API v2 metadata: `https://api.eia.gov/v2/electricity?api_key=DEMO_KEY` — confirmed all 6 electricity child routes
- Phase 7 verification: `.planning/phases/07-conservation-energy-trackers/07-VERIFICATION.md` — verified exact gap: no EIA capacity data, no solar/wind/coal visualization
- Phase 7 research: `.planning/phases/07-conservation-energy-trackers/07-RESEARCH.md` — verified EIA endpoint identification, energy source codes, World Bank indicator approach

### Secondary (MEDIUM confidence)
- EIA API v2 documentation: https://www.eia.gov/opendata/documentation.php — API query parameters (data[], facets[], frequency, sort[], length, offset, start, end)
- EIA operating-generator-capacity metadata: `https://api.eia.gov/v2/electricity/operating-generator-capacity?api_key=DEMO_KEY` — confirmed plant-level monthly data, facets for energy_source_code
- EIA energy source codes: SUN (solar), WND (wind), COL (coal aggregate), BIT/SUB/LIG/RC (coal sub-types) — from EIA form documentation and previous research

### Tertiary (LOW confidence)
- `energysourceid` exact facet values in `capability` endpoint — not verified with live API call; inferred from `operating-generator-capacity` codes and general EIA naming conventions
- "US" national aggregate in `stateid` facet — could not verify; recommended to aggregate all states server-side instead

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — Zero new libraries; all patterns proven in codebase
- Architecture: HIGH — Exact replication of get-energy-prices.ts handler + economic service RPC pattern
- Data source (EIA capability endpoint): MEDIUM — Endpoint confirmed to exist with correct data columns; exact facet values need live validation
- Visualization: HIGH — D3 stacked area and trend line are well-documented D3 patterns already used in the project
- Pitfalls: MEDIUM — Coal code ambiguity and US aggregate availability need runtime verification

**Research date:** 2026-02-23
**Valid until:** 2026-03-23 (30 days -- stable domain, no fast-moving dependencies)
