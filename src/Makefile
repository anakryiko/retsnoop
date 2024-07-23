# SPDX-License-Identifier: BSD-2-Clause
OUTPUT ?= .output
OUTPUT_ABS := $(abspath $(OUTPUT))
CLANG ?= clang
LD ?= ld
LLVM_STRIP ?= llvm-strip
CARGO ?= cargo
DEBUG ?=

BPFTOOL_SRC := $(abspath ../bpftool/src)
BPFTOOL_OUTPUT ?= $(OUTPUT)/bpftool
BPFTOOL_OUTPUT_ABS ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ ?= $(OUTPUT)/libbpf.a
DEFAULT_SIDECAR := ../sidecar/target/$(if $(DEBUG),debug,release)/addr2line
SIDECAR ?= $(DEFAULT_SIDECAR)
SIDECAR_EMBED_NAME ?= $(subst .,_,$(subst /,_,$(SIDECAR)))
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated (they will be installed into $(OUTPUT))
INCLUDES := -I$(OUTPUT) -I$(OUTPUT)/include
CFLAGS ?= -g -Wall -O$(if $(DEBUG),0,2)

ARCH ?= $(shell uname -m						\
		| sed 's/x86_64/x86/'					\
		| sed 's/i686/x86/'					\
		| sed 's/aarch64/arm64/'				\
		| sed 's/ppc64le/powerpc/'				\
		| sed 's/riscv64/riscv/'				\
		| sed 's/s390x/s390/'					\
	)

ifeq ($(wildcard $(ARCH)/),)
$(error Architecture $(ARCH) is not supported yet.)
endif

# for installation
INSTALL := install
prefix ?= /usr/local
bindir := $(prefix)/bin

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: retsnoop simfail

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) retsnoop simfail bpftool
	$(Q)$(CARGO) clean --manifest-path=../sidecar/Cargo.toml

.PHONY: cscope
cscope:
	$(Q)ls *.c *.h $(ARCH)/vmlinux.h > cscope.files
	$(Q)cscope -b -q $(INCLUDES) -f cscope.out

install: all
	mkdir -p $(DESTDIR)$(bindir)/
	$(INSTALL) -pt $(DESTDIR)$(bindir)/ retsnoop simfail

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(OUTPUT)/tests:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

.PHONY: libbpf-headers
libbpf-headers: | $(OUTPUT)/include

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q) [ -d ../libbpf/src ] || git submodule update --init
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    PREFIX=$(OUTPUT_ABS) DESTDIR=			      \
		    OBJDIR=$(OUTPUT_ABS)/libbpf LIBDIR=$(OUTPUT_ABS)/ 	      \
		    EXTRA_CFLAGS="-g -O$(if $(DEBUG),0,2)"                    \
		    install install_uapi_headers

# Build bpftool
$(BPFTOOL): $(LIBBPF_OBJ) | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q) [ -d ../bpftool/src ] || git submodule update --init
	$(Q)CFLAGS= EXTRA_CFLAGS="$(CFLAGS) -Wno-sign-compare"		      \
		$(MAKE) ARCH= CROSS_COMPILE=				      \
			BPF_DIR=$(LIBBPF_SRC) OUTPUT=$(BPFTOOL_OUTPUT_ABS)/      \
			-C $(BPFTOOL_SRC) bootstrap

.PHONY: bpftool
bpftool: $(BPFTOOL)
	$(Q)ln -s $(BPFTOOL) bpftool

# Build BPF object files
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard *.h) $(ARCH)/vmlinux.h    \
		 | $(OUTPUT) $(OUTPUT)/tests
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(ARCH)     \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@

# Link together BPF object files and generate BPF skeleton
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-LINK,$@)
	$(Q)$(BPFTOOL) gen object $(@:.skel.h=.bpfo) $^
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $(@:.skel.h=.bpfo) name $(notdir $*_bpf) > $@

# Build application object files
$(OUTPUT)/%.o: %.c $(wildcard *.h) $(LIBBPF_OBJ) | $(OUTPUT) $(OUTPUT)/tests
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/retsnoop.skel.h: $(OUTPUT)/mass_attach.bpf.o
$(OUTPUT)/retsnoop.o: $(OUTPUT)/retsnoop.skel.h $(OUTPUT)/calib_feat.skel.h
$(OUTPUT)/mass_attacher.o: $(OUTPUT)/retsnoop.skel.h $(OUTPUT)/calib_feat.skel.h

$(DEFAULT_SIDECAR)::
	$(call msg,CARGO,addr2line)
	$(Q)$(CARGO) build --manifest-path=../sidecar/Cargo.toml $(if $(DEBUG),,--release)

$(OUTPUT)/addr2line.embed.o: $(SIDECAR)
	$(call msg,LLVM_STRIP,$<)
	$(Q)$(LLVM_STRIP) -g $<
	$(call msg,LD,$@)
	$(Q)$(LD) -r -b binary -z noexecstack \
		--defsym __binary_sidecar_start=_binary_$(SIDECAR_EMBED_NAME)_start \
		--defsym __binary_sidecar_end=_binary_$(SIDECAR_EMBED_NAME)_end \
		--defsym __binary_sidecar_size=_binary_$(SIDECAR_EMBED_NAME)_size \
		-o $@ $<

$(OUTPUT)/addr2line.o: $(OUTPUT)/addr2line.embed.o

# Build application binary
retsnoop: override CFLAGS += -DSKEL_NAME=retsnoop_bpf			\
		    	     -DSKEL_HEADER=retsnoop.skel.h		\
		    	     -DSKEL_EXTRA_HEADER=retsnoop.h

retsnoop: $(addprefix $(OUTPUT)/,					\
		      retsnoop.o					\
		      logic.o 						\
		      fnargs.o 						\
		      env.o						\
		      ksyms.o						\
		      utils.o						\
		      hashmap.o						\
		      addr2line.o					\
		      addr2line.embed.o					\
		      mass_attacher.o)					\
	  $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ -lelf -lz -o $@

$(OUTPUT)/tests/simfail.o: $(OUTPUT)/tests/kprobe_bad_kfunc.skel.h	\
			   $(OUTPUT)/tests/fentry_unsupp_func.skel.h	\
			   $(OUTPUT)/tests/simple_obj.skel.h		\
			   | $(OUTPUT)/tests

simfail: $(addprefix $(OUTPUT)/tests/,					\
		     simfail.o)						\
	 $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) $^ -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

