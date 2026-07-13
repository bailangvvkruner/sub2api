#!/usr/bin/env bash
set -euo pipefail

source_ref="${1:-HEAD}"
upstream_ref="${2:-upstream/main}"
manifest="${3:-fork-meta/patch-series.json}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel)"
if [ "$(git rev-parse "$source_ref")" = "$(git rev-parse HEAD)" ] && [ -n "$(git status --porcelain)" ]; then
  die "source worktree is dirty; commit the candidate before validating it"
fi

queue_root="$(mktemp -d)"
source_manifest="$queue_root/patch-series.json"
git show "$source_ref:$manifest" >"$source_manifest" || die "manifest is unavailable at $source_ref:$manifest"
base_ref="$(jq -er '.base_upstream_sha' "$source_manifest" | tr -d '\r')"
patch_directory="$(jq -er '.patch_directory' "$source_manifest" | tr -d '\r')"
case "$patch_directory" in
  fork-meta/patches) ;;
  *) die "unsafe patch_directory: $patch_directory" ;;
esac
queue_dir="$queue_root/$patch_directory"
mkdir -p "$queue_dir"
for metadata in series SHA256SUMS; do
  git show "$source_ref:$patch_directory/$metadata" >"$queue_dir/$metadata" \
    || die "canonical patch metadata is missing: $patch_directory/$metadata"
done
while IFS= read -r patch_name; do
  [[ "$patch_name" =~ ^[0-9]{4}-[a-z0-9-]+\.patch$ ]] || die "unsafe patch filename: $patch_name"
  git show "$source_ref:$patch_directory/$patch_name" >"$queue_dir/$patch_name" \
    || die "canonical patch is missing: $patch_name"
done <"$queue_dir/series"
(cd "$queue_dir" && sha256sum -c SHA256SUMS)

worktree_root="$(mktemp -d)"
base_worktree="$worktree_root/base"
upstream_worktree="$worktree_root/upstream"

cleanup() {
  git worktree remove --force "$base_worktree" >/dev/null 2>&1 || true
  git worktree remove --force "$upstream_worktree" >/dev/null 2>&1 || true
  rm -rf "$queue_root" "$worktree_root"
}
trap cleanup EXIT

apply_queue() {
  local worktree="$1" patch_name
  while IFS= read -r patch_name; do
    [ -n "$patch_name" ] || continue
    if ! git -C "$worktree" am --3way --keep-cr "$queue_dir/$patch_name"; then
      git -C "$worktree" am --abort >/dev/null 2>&1 || true
      die "patch replay failed in clean worktree: $patch_name"
    fi
  done <"$queue_dir/series"
}

run_generators() {
  local worktree="$1" encoded working_directory
  local -a command
  while IFS= read -r encoded; do
    working_directory="$(jq -r '.working_directory' <<<"$encoded" | tr -d '\r')"
    mapfile -t command < <(jq -r '.command[]' <<<"$encoded" | tr -d '\r')
    (cd "$worktree/$working_directory" && "${command[@]}")
  done < <(jq -c '.generators[]' "$source_manifest")
}

assert_only_generated_changes() {
  local worktree="$1" path
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    jq -e --arg path "$path" '[.generators[].outputs[]] | index($path) != null' "$source_manifest" >/dev/null \
      || die "generator changed undeclared path: $path"
  done < <(
    {
      git -C "$worktree" diff --name-only
      git -C "$worktree" ls-files --others --exclude-standard
    } | sort -u
  )
}

git worktree add --detach "$base_worktree" "$base_ref"
apply_queue "$base_worktree"
run_generators "$base_worktree"
assert_only_generated_changes "$base_worktree"
mkdir -p "$base_worktree/$patch_directory"
cp -R "$queue_dir/." "$base_worktree/$patch_directory/"
git -C "$base_worktree" add -A
git -C "$base_worktree" diff --cached --check -- . ":(exclude)$patch_directory/*.patch"
source_tree="$(git rev-parse "${source_ref}^{tree}")"
rebuilt_tree="$(git -C "$base_worktree" write-tree)"
[ "$source_tree" = "$rebuilt_tree" ] || die "canonical patch queue does not reproduce the fork source tree"

target_sha="$(git rev-parse "$upstream_ref")"
git merge-base --is-ancestor "$base_ref" "$target_sha" \
  || die "upstream target does not descend from recorded base"
if [ "$target_sha" != "$base_ref" ]; then
  git worktree add --detach "$upstream_worktree" "$target_sha"
  apply_queue "$upstream_worktree"
  run_generators "$upstream_worktree"
  assert_only_generated_changes "$upstream_worktree"
  git -C "$upstream_worktree" diff --check -- . ":(exclude)$patch_directory/*.patch"
fi

printf 'canonical patch queue validated: source=%s upstream=%s\n' "$source_ref" "$target_sha"
