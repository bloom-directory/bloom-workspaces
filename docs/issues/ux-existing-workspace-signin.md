# Issue: existing workspace not surfaced after sign-in (create-errors-then-refresh)

UX bug reported live: after signing in, the page does not show the existing
workspace; clicking "create workspace" errors ("already has an active
workspace"); refreshing then shows it.

## Evidence
- `web/main.ts:430`: `inactive = !workspace || workspace.state === "stopped" || workspace.state === "failed"`. Failed/stopped workspaces render as the "create" view, not as an existing workspace.
- Sign-in calls `renderWorkspace(session.workspace)` (`main.ts:187`) using the
  workspace from the auth response; refresh fetches `/api/workspaces/current`
  fresh (`main.ts:482`). A stale or failed-state workspace at sign-in time shows
  the create view; a refresh showing the running workspace "fixes" it.
- One-active-workspace-per-wallet then makes the create click 409.

## Impact
Confusing first-load experience; users think they have no workspace and hit an
error trying to make one.

## Direction
1. Reproduce (sign in with a workspace in each state: running, provisioning, failed, none) and confirm which path mismatches.
2. Likely fix: on sign-in, fetch `/api/workspaces/current` fresh (don't rely on the auth-response workspace), and render failed/stopped workspaces as "your workspace (stopped/failed)" with a restart action instead of as the empty create view.
3. Make provisioning state clearly read as "your workspace is starting," not as absence.
