obj-m += kmem.o
MCFLAGS += -O3
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}

KDIR ?= /lib/modules/$(shell uname -r)/build

ifndef OUT_DIR
	KOUTPUT := $(PWD)/build/vmread_kmod
else
	KOUTPUT := $(OUT_DIR)/vmread_kmod
endif

KOUTPUT_MAKEFILE := $(KOUTPUT)/Makefile

all:
	@(command -v nix-shell &> /dev/null && \
		nix-shell '<nixpkgs>' -A linuxPackages_latest.kernel.dev --command "./nixbuild.sh") || \
		make build-module

build-module: $(KOUTPUT_MAKEFILE)
	make -C $(KDIR) M=$(KOUTPUT) src=$(PWD) modules
	cp $(KOUTPUT)/kmem.ko $(KOUTPUT)/../vmread.ko

$(KOUTPUT):
	mkdir -p "$@"

$(KOUTPUT_MAKEFILE): $(KOUTPUT)
	touch "$@"

clean:
	make -C $(KDIR) M=$(KOUTPUT) src=$(PWD) clean
	$(shell rm $(KOUTPUT_MAKEFILE))
	rmdir $(KOUTPUT)
