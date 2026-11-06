#!/usr/bin/env bash
#
# Fetch the latest codeql-bundle-vX.Y.Z tag from github/codeql-action, download the
# matching codeql-cli-binaries release, and install it to /opt/codeql.
#
# Usage: ./update-codeql.sh

set -euo pipefail

ACTION_REPO="github/codeql-action"
CLI_REPO="github/codeql-cli-binaries"
INSTALL_DIR="/opt/codeql"

for bin in curl jq wget unzip sudo; do
    command -v "$bin" >/dev/null 2>&1 || {
        echo "error: '$bin' is required but not found in PATH" >&2
        exit 1
    }
done

echo "Requesting sudo access for ${INSTALL_DIR}..." >&2
sudo -v

curl_gh() {
    local auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    curl -fsSL "${auth[@]}" -H "Accept: application/vnd.github+json" "$@"
}

echo "Fetching releases for ${ACTION_REPO}..." >&2
release_json=$(curl_gh "https://api.github.com/repos/${ACTION_REPO}/releases?per_page=100" |
    jq -c '[.[] | select(.tag_name | test("^codeql-bundle-v[0-9]+\\.[0-9]+\\.[0-9]+$"))] | sort_by(.published_at) | last')

if [ "$release_json" = "null" ] || [ -z "$release_json" ]; then
    echo "error: no codeql-bundle-vX.Y.Z tag found in ${ACTION_REPO} releases" >&2
    exit 1
fi

tag_name=$(jq -r '.tag_name' <<<"$release_json")
published_at=$(jq -r '.published_at' <<<"$release_json")
version="${tag_name#codeql-bundle-v}"
pretty_date=$(LC_TIME=C date -u -d "$published_at" +"%-d %B %Y")

echo "Latest bundle: ${tag_name} (${pretty_date}), CLI version v${version}" >&2

zip_name="codeql-linux64.zip"
download_url="https://github.com/${CLI_REPO}/releases/download/v${version}/${zip_name}"

work_dir="codeql-download-$(date +%Y%m%d%H%M%S)"
mkdir -p "$work_dir"

echo "Downloading ${download_url}..." >&2
wget -q --show-progress -P "$work_dir" "$download_url"

echo "Unzipping..." >&2
unzip -q "${work_dir}/${zip_name}" -d "$work_dir"

if [ ! -d "${work_dir}/codeql" ]; then
    echo "error: expected '${work_dir}/codeql' directory not found after unzip" >&2
    exit 1
fi

if [ -e "$INSTALL_DIR" ]; then
    backup_dir="${INSTALL_DIR}.bak-$(date +%Y%m%d%H%M%S)"
    echo "Existing ${INSTALL_DIR} found, moving it to ${backup_dir}" >&2
    sudo mv "$INSTALL_DIR" "$backup_dir"
fi

echo "Installing to ${INSTALL_DIR}..." >&2
sudo mv "${work_dir}/codeql" "$INSTALL_DIR"
sudo chown -R "$(id -u):$(id -g)" "$INSTALL_DIR"
rm -rf "$work_dir"

echo "" >&2
echo "Done. Installed ${tag_name} to ${INSTALL_DIR}" >&2
echo ""
echo "[\`v${version}\` (${pretty_date})](https://github.com/${ACTION_REPO}/releases/tag/${tag_name})"
