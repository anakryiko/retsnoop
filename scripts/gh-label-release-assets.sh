#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

set -o errexit
set -o nounset
set -o pipefail

# Use this script to add labels to GitHub release assets for a given release.
#
# Based on the following console workflow:
#
# gh api \
#     '/repos/anakryiko/retsnoop/releases/tags/<some_tag>' \
#     --jq '.id'
# gh api \
#     '/repos/anakryiko/retsnoop/releases/<release_id>/assets' \
#     --jq '.[] | select(.name == "<file_name>").id'
# gh api \
#     --method PATCH \
#     -H "Accept: application/vnd.github+json" \
#     -H "X-GitHub-Api-Version: 2022-11-28" \
#     '/repos/anakryiko/retsnoop/releases/assets/<asset_id>' \
#     -f name='<new_file_name>' \
#     -f label='<new_name_in_asset_list>'

REPO="anakryiko/retsnoop"

usage() {
    echo "Update asset labels for retsnoop releases"
    echo "Usage:"
    echo "  $0 [options] <release_tag>"
    echo ""
    echo "OPTIONS"
    echo " -h       display this help"
    exit "$1"
}

OPTIND=1
while getopts "h" opt; do
    case "$opt" in
    h)
        usage 0
        ;;
    *)
        usage 1
        ;;
    esac
done
shift $((OPTIND-1))
[[ "${1:-}" = "--" ]] && shift

# Get release tag from command line
if [[ "$#" -lt 1 ]]; then
    echo "error: missing release tag"
    usage 1
fi
release_tag="$1"
echo "repo: ${REPO}, release tag: ${release_tag}"

# Add labels to set for given asset names here:
declare -A assets_labels=(
    ["srcs-full-${release_tag}.tar.gz"]="Full source code with submodules (tar.gz)"
    ["srcs-full-${release_tag}.zip"]="Full source code with submodules (zip)"
)

# Get release ID
release_id="$(gh api "/repos/${REPO}/releases/tags/${release_tag}" --jq '.id')"
echo "  found release ID ${release_id}"

# For each label to set, get asset ID, prompt user for confirmation, set label
for asset_name in "${!assets_labels[@]}"; do
    asset_id="$(gh api "/repos/${REPO}/releases/${release_id}/assets" \
        --jq ".[] | select(.name == \"${asset_name}\").id")"
    echo "  found asset ID ${asset_id}"

    echo "asset '${asset_name}': add label '${assets_labels[${asset_name}]}'"
    answer=""
    read -rp 'proceed? [y/N]: ' answer

    case "${answer}" in
        y|yes|Y|Yes|YES)
            # Note: A 404 error at this stage may be synonymous with
            # insufficient permissions for the token in use for gh.
            gh api \
                --method PATCH \
                -H 'Accept: application/vnd.github+json' \
                -H 'X-GitHub-Api-Version: 2022-11-28' \
                "/repos/${REPO}/releases/assets/${asset_id}" \
                -f label="${assets_labels[${asset_name}]}"
            ;;
        *)
            echo "cancelled"
            ;;
    esac
done
