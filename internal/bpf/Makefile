KERNELDIR ?= /lib/modules/$(shell uname -r)/build

define BASEFLAGS
          -I$(KERNELDIR)/arch/x86/include                \
		  -I$(KERNELDIR)/arch/x86/include/generated      \
		  -I$(KERNELDIR)/include                         \
		  -I$(KERNELDIR)/include/uapi                    \
		  -include $(KERNELDIR)/include/linux/kconfig.h  \
		  -include asm_goto_workaround.h                 \
		  -D__KERNEL__                                   \
		  -D__BPF_TRACING__                              \
		  -Wno-gnu-variable-sized-type-not-at-end        \
		  -Wno-address-of-packed-member                  \
		  -fno-jump-tables                               \
		  -Wno-pointer-sign                              \
	      -Wno-tautological-compare
endef

all: probe.o 

clean:
	rm -f *~
	rm -f .built-in.a.cmd
	rm -f built-in.a
	rm -f probe*.o
	rm -f probe*.ll
	rm -f Modules.symvers
	rm -f modules.order
	rm -f Module.symvers 
	rm -f .cache.mk

probe.o: probe.c
	@echo "Building Probe..."
	clang ${BASEFLAGS} -O2 -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	llc -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

NAME=probe
IMAGE=probe-builder:latest
TMP_DIR ?= $(shell pwd)/probe_tmp

build: ## Build kernel probe /w temp container
	rm -rf $(TMP_DIR)
	mkdir -p $(TMP_DIR)
	cp -Lr $(KERNELDIR)/* $(TMP_DIR)
	docker build . -t probe-builder
	-docker rm -f -v $(NAME)
	docker run --name=$(NAME) \
		-v $$(pwd):/bpf \
		-v $(TMP_DIR):/kernel \
		$(IMAGE)
	docker rm -f -v $(NAME)
	rm -rf $(TMP_DIR)
