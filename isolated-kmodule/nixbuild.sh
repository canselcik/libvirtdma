#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
KROOT=$(nix-build -E '(import <nixpkgs> {}).linuxPackages_latest.kernel.dev' --no-out-link)
KDIR="$KROOT/lib/modules/*/build"

if [ ! -d $KDIR ]; then
	echo "Kernel Build Directory is invalid: $KDIR"
	exit 1
fi

KDIR=${KDIR} make build-module
