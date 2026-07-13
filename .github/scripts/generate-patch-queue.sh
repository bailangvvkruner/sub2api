#!/usr/bin/env bash
set -euo pipefail

manifest="${1:-fork-meta/patch-series.json}"
source_ref="${2:-HEAD}"
output_dir="${3:-}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || die "jq is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "run inside a git worktree"
[ -f "$manifest" ] || die "manifest not found: $manifest"

jq -e '
  .schema_version == 2
  and (.patch_directory | type == "string" and length > 0)
  and (.series | type == "array" and length >= 5 and length <= 8)
  and (all(.series[]; (.id | test("^[a-z0-9][a-z0-9-]*$")) and (.order | type == "number") and (.subject | type == "string" and length > 0) and (.include_regex | type == "array" and length > 0)))
  and ([.series[].id] | length == (unique | length))
  and ([.series[].order] | length == (unique | length))
  and (all(.series[].include_regex[]; . as $re | try ("" | test($re) | true) catch false))
  and (.generators | type == "array" and length > 0)
  and (all(.generators[]; (.working_directory | type == "string") and (.command | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)) and (.outputs | type == "array" and length > 0 and all(.[]; type == "string" and length > 0))))
  and ([.generators[].outputs[]] | length == (unique | length))
' "$manifest" >/dev/null || die "manifest schema is invalid"

patch_directory="$(jq -er '.patch_directory' "$manifest" | tr -d '\r')"
case "$patch_directory" in
  fork-meta/patches) ;;
  *) die "unsafe patch_directory: $patch_directory" ;;
esac

base_ref="$(jq -er '.base_upstream_sha' "$manifest" | tr -d '\r')"
git cat-file -e "${base_ref}^{commit}" 2>/dev/null || die "base commit is unavailable: $base_ref"
git cat-file -e "${source_ref}^{commit}" 2>/dev/null || die "source commit is unavailable: $source_ref"

if [ -z "$output_dir" ]; then
  output_dir="$(mktemp -d)"
else
  mkdir -p "$output_dir"
  find "$output_dir" -mindepth 1 -maxdepth 1 -type f -delete
fi

mapfile -d '' -t changed_paths < <(git diff --name-only --no-renames -z "$base_ref" "$source_ref")
[ "${#changed_paths[@]}" -gt 0 ] || die "fork source has no changes relative to recorded upstream base"

declare -A series_files=()
declare -A generated_paths=()
while IFS= read -r generated_path; do
  [ -n "$generated_path" ] || continue
  generated_paths["$generated_path"]=1
done < <(jq -r '[.generators[].outputs[]] | unique[]' "$manifest" | tr -d '\r')

for path in "${changed_paths[@]}"; do
  if [[ "$path" == "$patch_directory/"* ]]; then
    printf 'skip canonical patch metadata: %s\n' "$path"
    continue
  fi
  if [ "${generated_paths[$path]:-}" = 1 ]; then
    printf 'skip generated path: %s\n' "$path"
    continue
  fi
  mapfile -t owners < <(
    jq -r --arg path "$path" '
      .series[]
      | select(any(.include_regex[]; . as $re | $path | test($re)))
      | .id
    ' "$manifest" | tr -d '\r'
  )
  if [ "${#owners[@]}" -eq 0 ]; then
    die "changed path has no patch-series owner: $path"
  fi
  if [ "${#owners[@]}" -ne 1 ]; then
    die "changed path matches multiple patch series (${owners[*]}): $path"
  fi
  series_files["${owners[0]}"]+="$path"$'\n'
done

source_sha="$(git rev-parse "$source_ref")"
source_date="$(git show -s --format=%aD "$source_ref")"
series_total="$(jq '.series | length' "$manifest" | tr -d '\r')"
index_file="$output_dir/series"
: >"$index_file"
patch_index=0

while IFS=$'\t' read -r order id subject; do
  files_blob="${series_files[$id]:-}"
  [ -n "$files_blob" ] || die "patch series is empty: $id"
  mapfile -t files < <(printf '%s' "$files_blob" | sed '/^$/d')
  patch_index=$((patch_index + 1))
  patch_name="$(printf '%04d' "$order")-$id.patch"
  patch_file="$output_dir/$patch_name"
  {
    printf 'From %s Mon Sep 17 00:00:00 2001\n' "$source_sha"
    printf 'From: sub2api fork automation <41898282+github-actions[bot]@users.noreply.github.com>\n'
    printf 'Date: %s\n' "$source_date"
    printf 'Subject: [PATCH %s/%s] %s\n' "$patch_index" "$series_total" "$subject"
    printf '\n---\n'
    git diff --binary --full-index --no-renames "$base_ref" "$source_ref" -- "${files[@]}"
    printf '\n'
  } >"$patch_file"
  git mailinfo /dev/null /dev/null <"$patch_file" >/dev/null \
    || die "generated mail patch is invalid: $patch_file"
  printf '%s\n' "$patch_name" >>"$index_file"
done < <(jq -r '.series | sort_by(.order)[] | [.order, .id, .subject] | @tsv' "$manifest" | tr -d '\r')

[ "$patch_index" -eq "$series_total" ] || die "generated patch count does not match manifest"
: >"$output_dir/SHA256SUMS"
while IFS= read -r patch_name; do
  (cd "$output_dir" && sha256sum "$patch_name") >>"$output_dir/SHA256SUMS"
done <"$index_file"
printf 'generated %s canonical patches in %s\n' "$patch_index" "$output_dir"
