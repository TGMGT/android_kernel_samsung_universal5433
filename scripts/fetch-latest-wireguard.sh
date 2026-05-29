#!/bin/bash
set -e

USER_AGENT="WireGuard-AndroidROMBuild/0.3 ($(uname -a))"

exec 9>.wireguard-fetch-lock
flock -n 9 || exit 0

# Use a fixed recent version or pin it (recommended)
VERSION="1.0.20220627"   # Last available release

# Optional: Check every 30 days instead of 1 day
if [[ $(( $(date +%s) - $(stat -c %Y "net/wireguard/.check" 2>/dev/null || echo 0) )) -lt 2592000 ]]; then
    exit 0
fi

if [[ -f net/wireguard/version.h && $(< net/wireguard/version.h) == *"$VERSION"* ]]; then
    touch net/wireguard/.check
    exit 0
fi

rm -rf net/wireguard
mkdir -p net/wireguard

echo "Downloading wireguard-linux-compat $VERSION ..."

curl -A "$USER_AGENT" -LsS --connect-timeout 30 \
    "https://codeload.github.com/WireGuard/wireguard-linux-compat/tar.gz/v$VERSION" \
    | tar -C "net/wireguard" -xJf - --strip-components=2 \
      "wireguard-linux-compat-v$VERSION/src"

sed -i 's/tristate/bool/;s/default m/default y/;' net/wireguard/Kconfig

touch net/wireguard/.check
echo "WireGuard compat module fetched successfully."
