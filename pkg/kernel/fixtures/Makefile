KERNELDIR ?= /lib/modules/$(shell uname -r)/build

always += dummy_probe.o

all: dummy_probe

dummy_probe:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

$(obj)/dummy_probe.o: $(src)/dummy_probe.c
	clang $(LINUXINCLUDE) $(KBUILD_CPPFLAGS) $(DEBUG) -D__KERNEL__ -D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -fno-jump-tables \
		-Wno-tautological-compare -O3 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	llc -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	rm -f *~
	rm -f dummy_probe.ll
	rm -f Modules.symvers
	rm -f modules.order
	rm -f Module.symvers
	rm -f .cache.mk

clean_all: clean
	rm -rf dummy_probe.o

