#!/bin/bash

nix-shell '<nixpkgs>' -A linuxPackages_latest.kernel.dev \
	--command "make -C $(nix-build -E '(import <nixpkgs> {}).linuxPackages_latest.kernel.dev' --no-out-link)/lib/modules/*/build M=$(pwd) modules"
