# Fork patch queue

This directory defines the canonical fork-owned changes replayed on top of
upstream `main`. The seven patches in `patches/` are persisted, ordered, and
covered by `SHA256SUMS`; they replace the historical 33-commit fork stack with
feature-level patches.

Local use requires Git, `jq` 1.6 or newer, and the Go toolchain declared in
`backend/go.mod`. GitHub-hosted Ubuntu runners already provide `jq`.

Automated synchronization requires a repository Actions secret named
`SYNC_TOKEN`. Prefer a short-lived GitHub App installation token with contents,
pull-request, actions, and workflow write access. A scoped PAT is a fallback for
organizations that disable pull-request creation by the default `GITHUB_TOKEN`.

`patch-series.json` is the ownership contract. Every changed path must match
exactly one series. A missing owner, overlap, empty series, duplicate ID/order,
or checksum mismatch fails validation before any patch is applied. Generator
outputs are omitted from patches and regenerated after replay; currently this
applies to Wire's `backend/cmd/server/wire_gen.go`.

The synchronization flow is fail-closed:

1. Fetch the recorded base, the fork source ref, and the new upstream tip.
2. Verify the committed queue checksums and create a clean upstream worktree.
3. Apply every canonical patch with `git am --3way`.
4. Regenerate declared outputs and refresh the queue against the new base.
5. Run fork validation and tests.
6. Push `sync/upstream-<sha>` and open a pull request to `main`.

Conflicts are never auto-resolved and no side-preference merge strategy is
used. Resolve a conflict by rebuilding the affected fork feature against the
new upstream tree, then update the manifest path ownership if files moved
between series.

The source branch does not need to contain the recorded upstream commit in its
history. Exact clean-tree replay is the integrity check, so GitHub merge,
squash, and rebase strategies remain compatible. Upstream-owned workflows stay
untouched; only the fork workflow and script paths named in the manifest are
part of the overlay.

After a sync pull request is merged, `base_upstream_sha` points at the upstream
tip used by that pull request. Do not advance it independently of a successful
replay.

Local validation:

```bash
bash .github/scripts/validate-patch-queue.sh HEAD upstream/main
bash .github/scripts/verify-fork-hotpath.sh
```

After committing an intentional fork change, refresh the canonical queue and
commit the resulting patch metadata before opening a pull request:

```bash
bash .github/scripts/generate-patch-queue.sh \
  fork-meta/patch-series.json HEAD fork-meta/patches
```
