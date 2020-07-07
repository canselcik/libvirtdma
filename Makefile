all: build

build:
	cd hypervisor-cli; cargo build

runc: build
	sudo -E hypervisor-cli/target/debug/hypervisor-cli