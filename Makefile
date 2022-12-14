APPS = dropwatch
bpftool = $(shell which bpftool || echo ./tools/bpftool)
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath ./out/libbpf/libbpf.a)
INCLUDES := -I./out/libbpf/usr/include -I./libbpf/include/uapi -I/usr/include/x86_64-linux-gnu -I.

.PHONY: all
all: $(APPS)

$(APPS): %: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES) -c $@.bpf.c -o $@.bpf.o
	$(bpftool) gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall $(INCLUDES) -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o -static $(LIBBPF_OBJ) -lelf -lz -o out/$@

install:
	install -D out/dropwatch $(DESTDIR)/usr/bin/dropwatch

vmlinux:
	$(bpftool) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

libbpf: $(LIBBPF_OBJ)

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 OBJDIR=$(dir $@) DESTDIR=$(dir $@) install

format:
	VERSION_CONTROL=none indent -linux *.h *.c

clean:
	rm -rf $(APPS) *.o out
