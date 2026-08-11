# Issue: jobs-guest tests fail under Node 26 (TS-aware eval)

Two integration tests in `src/control/jobs-guest.test.ts` fail on Node 26:

- "runs literal structured argv with an allowlisted environment…"
- "enforces active-job limits, timeouts, process-group cancellation…"

## Evidence
- The first test runs a job via `node -e <script>` where the script string
  contains a literal newline inside a single-quoted JS string (`s.split('\n')`
  in the test source produces an actual newline in the script). Node 26's
  `evalTypeScript` rejects it (`SyntaxError: Invalid or unexpected token`).
  Older Node tolerated it.
- These tests also require the Rust binary at
  `ops/guest-control/target/debug/bloom-guest-control` (so they're local
  integration tests, not CI-portable without the Rust build).
- Inline-script escaping in the tests is tangled (e.g. `/\s+/` in the test
  source resolves to `/s+/` in the script) — likely more than one latent issue.

## Impact
Developers on Node 24/26 see red; the inline-`node -e` pattern is fragile
across Node versions.

## Direction
1. Stop constructing scripts as `node -e` strings with host-side escapes. Write the test script to a temp file and run `node <file>`, or factor it into a fixture. This removes the eval/escape fragility entirely.
2. Reconcile any other latent escaping bugs uncovered by (1).
3. Consider whether these tests should be CI-gated on the Rust build being present.
