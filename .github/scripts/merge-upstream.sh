#!/usr/bin/env bash
set -euo pipefail

upstream_ref="${1:-upstream/main}"

set_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  fi
}

if git merge-base --is-ancestor "$upstream_ref" HEAD; then
  echo "$upstream_ref is already contained in HEAD."
  set_output changed false
  exit 0
fi

# Preserve non-conflicting fork code while preferring upstream for overlapping
# hunks. The patch contract and tests below the merge step reject lost behavior.
set +e
git merge --no-commit --no-ff -X theirs "$upstream_ref"
merge_status=$?
set -e

if ! git rev-parse --verify -q MERGE_HEAD >/dev/null; then
  echo "::error::Unable to start merge with $upstream_ref (status=$merge_status)"
  exit 1
fi

# Workflows are owned by this fork. Upstream workflow files must not be restored.
find .github/workflows -type f \
  ! -name "build.yml" \
  ! -name "sync-upstream.yml" \
  -delete
git add -A .github/workflows

# -X theirs resolves content conflicts. Remaining conflicts are normally
# modify/delete or rename/delete cases; mirror the upstream tree for those.
mapfile -d '' -t conflicts < <(git diff --name-only --diff-filter=U -z)
for path in "${conflicts[@]}"; do
  if [[ "$path" == .github/workflows/* ]]; then
    git rm --ignore-unmatch -- "$path"
  elif git cat-file -e "$upstream_ref:$path" 2>/dev/null; then
    echo "Resolving structural conflict from upstream: $path"
    git checkout "$upstream_ref" -- "$path"
    git add -- "$path"
  else
    echo "Accepting upstream deletion: $path"
    git rm --ignore-unmatch -- "$path"
  fi
done

remaining="$(git diff --name-only --diff-filter=U)"
if [ -n "$remaining" ]; then
  echo "::error::Unresolved paths remain after merging $upstream_ref"
  printf '%s\n' "$remaining"
  exit 1
fi

git diff --check
git diff --cached --check
set_output changed true
