#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-fork-meta/patch-series.json}"
source_ref="${2:-origin/main}"
upstream_ref="${3:-upstream/main}"
branch_name="${4:-}"
worktree_dir="${5:-}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[ -n "$branch_name" ] || die "sync branch name is required"
[ -n "$worktree_dir" ] || die "worktree directory is required"
case "$branch_name" in
  sync/upstream-*) ;;
  *) die "refusing unexpected sync branch name: $branch_name" ;;
esac

repo_root="$(git rev-parse --show-toplevel)"
git cat-file -e "${source_ref}^{commit}" 2>/dev/null || die "source commit is unavailable: $source_ref"

queue_root="$(mktemp -d)"
source_manifest="$queue_root/patch-series.json"
git show "$source_ref:$manifest" >"$source_manifest" || die "manifest is unavailable at $source_ref:$manifest"
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

base_ref="$(jq -er '.base_upstream_sha' "$source_manifest" | tr -d '\r')"
target_sha="$(git rev-parse "$upstream_ref")"
git merge-base --is-ancestor "$base_ref" "$target_sha" \
  || die "upstream history was rewritten or the manifest base is invalid"
[ "$base_ref" != "$target_sha" ] || die "upstream is already synchronized at $target_sha"

[ ! -e "$worktree_dir" ] || die "worktree destination already exists: $worktree_dir"
git show-ref --verify --quiet "refs/heads/$branch_name" \
  && die "local sync branch already exists: $branch_name"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ -d "$worktree_dir" ]; then
    git -C "$worktree_dir" am --abort >/dev/null 2>&1 || true
    git worktree remove --force "$worktree_dir" >/dev/null 2>&1 || true
    git branch -D "$branch_name" >/dev/null 2>&1 || true
  fi
  rm -rf "$queue_root"
  exit "$status"
}
trap cleanup EXIT

git worktree add -b "$branch_name" "$worktree_dir" "$target_sha"
while IFS= read -r patch_name; do
  [ -n "$patch_name" ] || continue
  printf 'applying %s\n' "$patch_name"
  if ! git -C "$worktree_dir" am --3way --keep-cr "$queue_dir/$patch_name"; then
    printf 'error: patch conflict; no automatic resolution was attempted\n' >&2
    git -C "$worktree_dir" status --short >&2 || true
    exit 1
  fi
done <"$queue_dir/series"

run_generators() {
  local encoded working_directory
  local -a command
  while IFS= read -r encoded; do
    working_directory="$(jq -r '.working_directory' <<<"$encoded" | tr -d '\r')"
    mapfile -t command < <(jq -r '.command[]' <<<"$encoded" | tr -d '\r')
    (cd "$worktree_dir/$working_directory" && "${command[@]}")
  done < <(jq -c '.generators[]' "$source_manifest")
}

assert_only_generated_changes() {
  local path
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    jq -e --arg path "$path" '[.generators[].outputs[]] | index($path) != null' "$source_manifest" >/dev/null \
      || die "generator changed undeclared path: $path"
  done < <(
    {
      git -C "$worktree_dir" diff --name-only
      git -C "$worktree_dir" ls-files --others --exclude-standard
    } | sort -u
  )
}

run_generators
assert_only_generated_changes

tmp_manifest="$(mktemp)"
jq --arg sha "$target_sha" '.base_upstream_sha = $sha' \
  "$worktree_dir/$manifest" >"$tmp_manifest"
mv "$tmp_manifest" "$worktree_dir/$manifest"

patch_output="$worktree_dir/$patch_directory"
mkdir -p "$patch_output"
find "$patch_output" -mindepth 1 -maxdepth 1 -type f -delete
git -C "$worktree_dir" add -A
source_tree="$(git -C "$worktree_dir" write-tree)"
source_commit="$({
  printf 'canonical patch refresh for %s\n' "$target_sha"
} | GIT_AUTHOR_NAME='sub2api fork automation' GIT_AUTHOR_EMAIL='41898282+github-actions[bot]@users.noreply.github.com' \
    GIT_COMMITTER_NAME='sub2api fork automation' GIT_COMMITTER_EMAIL='41898282+github-actions[bot]@users.noreply.github.com' \
    git -C "$worktree_dir" commit-tree "$source_tree" -p "$target_sha")"
bash "$worktree_dir/.github/scripts/generate-patch-queue.sh" \
  "$worktree_dir/$manifest" "$source_commit" "$patch_output"

git -C "$worktree_dir" diff --check -- . ":(exclude)$patch_directory/*.patch"
git -C "$worktree_dir" diff --cached --check -- . ":(exclude)$patch_directory/*.patch"
if [ -n "$(git -C "$worktree_dir" diff --name-only --diff-filter=U)" ]; then
  die "unmerged paths remain after patch replay"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'changed=true\n'
    printf 'branch=%s\n' "$branch_name"
    printf 'target_sha=%s\n' "$target_sha"
    printf 'worktree=%s\n' "$worktree_dir"
  } >>"$GITHUB_OUTPUT"
fi

trap - EXIT
rm -rf "$queue_root"
printf 'fork rebuilt at %s on %s\n' "$worktree_dir" "$branch_name"
