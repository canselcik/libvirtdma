all: build

build:
	cd hypervisor-cli; cargo build

cli: build
	sudo -E hypervisor-cli/target/debug/hypervisor-cli
