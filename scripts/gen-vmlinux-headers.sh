#!/bin/bash

usage () {
	echo "USAGE: ./gen-vmlinux-headers.sh <linux-repo-path>"
	exit 1
}

set -eu

LINUX_REPO=${1-""}
RETSNOOP_REPO=$(cd $(dirname "$0")/.. && pwd)
BUILD_DIR="$RETSNOOP_REPO/scripts/.linux_builds"

if [ -z "${LINUX_REPO}" ]; then
	echo "Error: Linux repo path is not specified"
	usage
fi

# you'd need cross-compilers installed for each supported architecture, e.g.:
# sudo dnf install gcc-x86_64-linux-gnu \
#                  gcc-aarch64-linux-gnu \
#                  gcc-s390x-linux-gnu \
#                  gcc-ppc64le-linux-gnu \
#                  binutils-ppc64le-linux-gnu \
#                  gcc-riscv64-linux-gnu

build_arch(){
	local arch="$1"
	local build_dir="$BUILD_DIR/$arch"
	local build_dir_abs="$(mkdir -p $build_dir && cd $build_dir && pwd)"
	local kernel_log="$build_dir_abs/../linux_build_$arch.txt"
	local retsnoop_log="$build_dir_abs/../retsnoop_build_$arch.txt"
	local arch_slug=$(						\
		printf "$arch"						\
			| sed 's/x86_64/x86/'				\
			| sed 's/i686/x86/'				\
			| sed 's/aarch64/arm64/'			\
			| sed 's/ppc64le/powerpc/'			\
			| sed 's/riscv64/riscv/'			\
			| sed 's/s390x/s390/'				\
	)

	echo "Building $arch ($arch_slug) into $build_dir..."
	(
		cd "$LINUX_REPO"
		make O="$build_dir_abs"					\
		     ARCH=$arch_slug CROSS_COMPILE=$arch-linux-gnu-	\
		     tinyconfig &> "$kernel_log"
		cat >> "$build_dir_abs/.config" <<- EOF
			CONFIG_64BIT=y
			CONFIG_DEBUG_INFO=y
			CONFIG_DEBUG_INFO_DWARF4=y
			CONFIG_DEBUG_INFO_BTF=y
			CONFIG_BPF=y
			CONFIG_BPF_SYSCALL=y
			CONFIG_BPF_EVENTS=y
			CONFIG_MODULES=y
			CONFIG_TRACING=y
			CONFIG_KPROBES=y
			CONFIG_FTRACE=y
			CONFIG_FUNCTION_TRACER=y
			CONFIG_FPROBE=y
			CONFIG_KPROBE_EVENTS=y
			CONFIG_UPROBE_EVENTS=y
			CONFIG_PERF_EVENTS=y
		EOF
		make O="$build_dir_abs"					\
		     ARCH=$arch_slug CROSS_COMPILE=$arch-linux-gnu-	\
		     olddefconfig &>> "$kernel_log"
		make O="$build_dir_abs"					\
		     ARCH=$arch_slug CROSS_COMPILE=$arch-linux-gnu-	\
		     -j$(nproc) all &>> "$kernel_log"

		"$RETSNOOP_REPO/src/bpftool" btf dump			\
			file "$build_dir_abs/vmlinux" format c		\
			> "$RETSNOOP_REPO/src/$arch_slug/vmlinux.h"
	)

	echo "Validating vmlinux.h for $arch ($arch_slug)..."
	(
		cd "$RETSNOOP_REPO/src"
		rm -rf .output retsnoop simfail
		make ARCH=$arch_slug -j$(nproc) &> "$retsnoop_log"
	)
}

(
	echo "Building bpftool..."
	cd "$RETSNOOP_REPO/src"
	make bpftool &> "$BUILD_DIR/bpftool_build.txt"
)

for arch in x86_64 aarch64 s390x ppc64le riscv64; do
	build_arch $arch
done
