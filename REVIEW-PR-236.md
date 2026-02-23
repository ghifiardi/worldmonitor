# PR Review: fix: use deterministic hash-based jitter for country centroid fallback (#236)

## Summary

This PR has two commits:
1. Reduce dedup coordinate rounding from 0.5° to 0.1° in the unrest module
2. Replace `Math.random()` jitter with deterministic djb2 hash-based jitter for country centroid fallback in the cyber module

The core idea — making centroid jitter deterministic so threat markers don't jump on each request — is sound and solves a real UX problem.

## Issues Found

### Bug: JSDoc comment documents wrong output range

The `hashJitter` comment says it "returns a float in [-0.5, 0.5)" but the function actually returns values in **[-1.0, 1.0]**:

```typescript
return ((hash & 0x7fffffff) / 0x7fffffff - 0.5) * 2;
//       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//       [0, 1.0]            → [-0.5, 0.5]       → [-1.0, 1.0]
```

The `* 2` at the end doubles the range. This matches the original `(Math.random() - 0.5) * 2` behavior (±1°), so the **code is correct** — only the documentation is wrong. Should read "returns a float in [-1.0, 1.0]".

### Redundant commit: unrest deduplication change already merged

Commit 1 (`83dab23`) changes `Math.round(lat * 2) / 2` → `Math.round(lat * 10) / 10` in `unrest/v1/_shared.ts`. However, this exact change was **already merged** to `main` via PR #235 (commit `6f68bb1`). The current `main` already has the `* 10 / 10` rounding. This commit is redundant and will cause a merge conflict or be a no-op. The PR should be rebased on current `main` and this commit dropped.

## Code Quality Notes

**Positive:**
- djb2 is a well-known hash with decent distribution — appropriate for this use case
- Using `index` parameter (0 for lat, 1 for lon) ensures different jitter per axis
- Fallback of `seed` to `countryCode` is a sensible default
- Passing `threat.id` at the call site ensures unique, stable positions per threat

**Minor observations:**
- `hashJitter` output range is [-1.0, 1.0] (inclusive on both ends since `hash & 0x7fffffff` can be exactly `0x7fffffff`), while the original `Math.random()` version was [-1.0, 1.0). This is negligible for ±1° jitter.
- The hash quality of djb2 is sufficient for visual marker scatter; no cryptographic strength needed here.

## Verdict

**Request changes.** The deterministic jitter approach (commit 2) is good to merge after fixing the JSDoc range comment. However, the PR needs to be **rebased onto current `main`** to drop the now-redundant unrest dedup commit (commit 1), which is already in `main` via #235.
