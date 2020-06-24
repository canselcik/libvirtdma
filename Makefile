all: build

build:
	INCLUDE_DIR=/nix/store/796fpc57zsb4x57krgcdspxk0vp2rykq-glibc-2.30-dev/include/ \
	LIBCLANG_PATH=/nix/store/043gdd2fxp4pxnxwid66ihmi1652vy4y-clang-7.1.0-lib/lib/ \
	  cargo build --all

example:
	INCLUDE_DIR=/nix/store/796fpc57zsb4x57krgcdspxk0vp2rykq-glibc-2.30-dev/include/ \
	LIBCLANG_PATH=/nix/store/043gdd2fxp4pxnxwid66ihmi1652vy4y-clang-7.1.0-lib/lib/ \
	  cargo build --examples

c:
	cd hypervisor-cheat; \
	  INCLUDE_DIR=/nix/store/796fpc57zsb4x57krgcdspxk0vp2rykq-glibc-2.30-dev/include/ \
	  LIBCLANG_PATH=/nix/store/043gdd2fxp4pxnxwid66ihmi1652vy4y-clang-7.1.0-lib/lib/ \
	    cargo build --bin hypervisor-cheat

runc: c
	sudo ./target/debug/hypervisor-cheat
