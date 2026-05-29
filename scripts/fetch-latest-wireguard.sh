#!/bin/bash
set -e
USER_AGENT="WireGuard-AndroidROMBuild/0.3 ($(uname -a))"

exec 9>.wireguard-fetch-lock
flock -n 9 || exit 0

[[ $(( $(date +%s) - $(stat -c %Y "net/wireguard/.check" 2>/dev/null || echo 0) )) -gt 86400 ]] || exit 0

while read -r distro package version _; do
	if [[ $distro == upstream && $package == linuxcompat ]]; then
		VERSION="$version"
		break
	fi
done < <(curl -A "$USER_AGENT" -LSs --connect-timeout 30 https://build.wireguard.com/distros.txt)

[[ -n $VERSION ]]

if [[ -f net/wireguard/version.h && $(< net/wireguard/version.h) == *$VERSION* ]]; then
	touch net/wireguard/.check
	exit 0
fi

rm -rf net/wireguard
mkdir -p net/wireguard

echo "Downloading wireguard-linux-compat $VERSION..."

if ! curl -A "$USER_AGENT" -LsS --connect-timeout 20 -f \
  "https://git.zx2c4.com/wireguard-linux-compat/snapshot/wireguard-linux-compat-$VERSION.tar.xz" \
  | tar -C "net/wireguard" -xJf - --strip-components=2 "wireguard-linux-compat-$VERSION/src"; then

    echo "zx2c4 mirror failed, falling back to Codeload GitHub..."
    if ! curl -A "$USER_AGENT" -LsS --connect-timeout 30 -f \
      "https://codeload.github.com/WireGuard/wireguard-linux-compat/tar.gz/refs/tags/v${VERSION}" \
      | tar -C "net/wireguard" -xzf - --strip-components=2 "wireguard-linux-compat-v${VERSION}/src"; then
        echo "Error: Both mirrors failed to download WireGuard compat source."
        exit 1
    fi
fi

sed -i 's/tristate/bool/;s/default m/default y/;' net/wireguard/Kconfig
sed -i '1i #ifndef fallthrough\n#define fallthrough do {} while (0)\n#endif' net/wireguard/compat/siphash/siphash.c
touch net/wireguard/.check
echo "WireGuard compat $VERSION downloaded successfully."
