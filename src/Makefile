# SPDX-License-Identifier: BSD-2-Clause
OUTPUT := .output
CLANG ?= clang
LD ?= ld
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../tools/bpftool)
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
LIBSIDECAR_OBJ := ../sidecar/target/release/libsidecar.a
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi
CFLAGS := -g -Wall -O2
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

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
	$(Q)rm -rf $(OUTPUT) retsnoop simfail
	$(Q)cargo clean --manifest-path=../sidecar/Cargo.toml

$(OUTPUT) $(OUTPUT)/libbpf $(OUTPUT)/tests:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q) [ -d ../libbpf/src ] || git submodule update --init --recursive
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    EXTRA_CFLAGS="-g -O2" \
		    install

# Build BPF object files
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard *.h) vmlinux.h | $(OUTPUT) $(OUTPUT)/tests
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@

# Link together BPF object files and generate BPF skeleton
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(call msg,GEN-LINK,$@)
	$(Q)$(BPFTOOL) gen object $(@:.skel.h=.bpfo) $^
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $(@:.skel.h=.bpfo) name $(notdir $*_bpf) > $@

# Build application object files
$(OUTPUT)/%.o: %.c $(wildcard *.h) | $(OUTPUT) $(OUTPUT)/tests
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/retsnoop.skel.h: $(OUTPUT)/mass_attach.bpf.o
$(OUTPUT)/retsnoop.o: $(OUTPUT)/retsnoop.skel.h $(OUTPUT)/calib_feat.skel.h
$(OUTPUT)/mass_attacher.o: $(OUTPUT)/retsnoop.skel.h $(OUTPUT)/calib_feat.skel.h

$(LIBSIDECAR_OBJ): force
	$(call msg,CARGO,$@)
	$(Q)RUSTFLAGS='-C target-feature=+crt-static' \
	    cargo build --manifest-path=../sidecar/Cargo.toml --release --lib

../sidecar/target/release/addr2line::
	$(call msg,CARGO,addr2line)
	$(Q)cargo build --manifest-path=../sidecar/Cargo.toml --release --bin addr2line

$(OUTPUT)/addr2line.embed.o: ../sidecar/target/release/addr2line
	$(call msg,LLVM_STRIP,$<)
	$(Q)$(LLVM_STRIP) -g $<
	$(call msg,LD,$@)
	$(Q)$(LD) -r -b binary \
		--defsym __binary_sidecar_start=_binary____sidecar_target_release_addr2line_start \
		--defsym __binary_sidecar_end=_binary____sidecar_target_release_addr2line_end \
		--defsym __binary_sidecar_size=_binary____sidecar_target_release_addr2line_size \
		-o $@ $<

$(OUTPUT)/addr2line.o: $(OUTPUT)/addr2line.embed.o

# Build application binary
retsnoop: override CFLAGS += -DSKEL_NAME=retsnoop_bpf			\
		    	     -DSKEL_HEADER=retsnoop.skel.h		\
		    	     -DSKEL_EXTRA_HEADER=retsnoop.h

retsnoop: $(addprefix $(OUTPUT)/,					\
		      retsnoop.o					\
		      ksyms.o						\
		      addr2line.o					\
		      addr2line.embed.o					\
		      mass_attacher.o)					\
	  $(LIBSIDECAR_OBJ)						\
	  $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -lpthread -ldl -lm -o $@

$(OUTPUT)/tests/simfail.o: $(OUTPUT)/tests/kprobe_bad_kfunc.skel.h	\
			   $(OUTPUT)/tests/fentry_unsupp_func.skel.h	\
			   | $(OUTPUT)/tests

simfail: $(addprefix $(OUTPUT)/tests/,					\
		     simfail.o)						\
	  $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

.PHONY: force
force:

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

