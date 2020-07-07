all: build kbuild

# Builds the library and the demo cli
build:
	cd hypervisor-cli; cargo build

# Builds the kernel module
kbuild:
	cd isolated-kmodule; make

# Loads the kernel module if not loaded already
kload: kbuild
	@(lsmod | grep vmread &> /dev/null && \
		echo "Kernel Module seems to be already loaded. Unload it with 'rmmod' if you would like to load it again") || \
		sudo insmod isolated-kmodule/build/vmread.ko

# Runs the cli
cli: build
	sudo -E hypervisor-cli/target/debug/hypervisor-cli
