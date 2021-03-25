# retsnoop

`retsnoop` is BPF-based tool that is meant to help debugging kernel issues. It
allows to capture call stacks of kernel functions that return errors (NULL or
-Exxx) and emits every such detected call stack, along with the captured
results.

It's output in a default brief form looks like this:
```shell
$ sudo retsnoop -p bpf -ss
Receiving data...
                             entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                             do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
           24us [-EINVAL]    __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                             . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)
                             __do_sys_bpf+0x5ca                        (kernel/bpf/syscall.c:4438:9)
                             . bpf_btf_load                            (kernel/bpf/syscall.c:3818:9)
           21us [-EINVAL]    btf_new_fd+0x213                          (kernel/bpf/btf.c:5639:8)
                             . btf_parse                               (kernel/bpf/btf.c:4246:8)
                             . btf_parse_type_sec                      (kernel/bpf/btf.c:4009:5)
            0us [-EINVAL]    btf_check_all_metas+0x5                   (kernel/bpf/btf.c:3856:1)


                             entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                             do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
            2us [-EINVAL]    __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                             . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)


                             entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                             do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
           46us [-ENOMEM]    __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                             . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)
                             __do_sys_bpf+0x359                        (kernel/bpf/syscall.c:4375:9)
                             . map_create                              (kernel/bpf/syscall.c:828:8)
                             . find_and_alloc_map                      (kernel/bpf/syscall.c:122:8)
           41us [-ENOMEM]    array_map_alloc+0x1eb                     (kernel/bpf/arraymap.c:150:16)
                             . bpf_array_alloc_percpu                  (kernel/bpf/arraymap.c:39:6)
           16us [NULL]       bpf_map_alloc_percpu+0x3f                 (kernel/bpf/syscall.c:436:2)
                             . set_active_memcg                        (include/linux/sched/mm.h:315:6)
                             . preempt_count                           (arch/x86/include/asm/preempt.h:27:9)
           14us [NULL]       __alloc_percpu_gfp+0x5                    (mm/percpu.c:1894:9)
            0us [NULL]       pcpu_alloc+0x5                            (mm/percpu.c:1679:1)
```

Here three different error call stacks were captured and inline symbolization
was performed. Functions with '. ' prefix are inlined functions, detected by
`addr2line` (see below).

The same set of errors in verbose mode looks like this:

```shell
$ sudo retsnoop -p bpf -ss -v
Using vmlinux image at /lib/modules/5.12.0-rc2-00442-g87d77e59d1eb/build/vmlinux.
Discovered 46315 available kprobes!
Found 1016 attachable functions in total.
Skipped 44660 functions in total.
Function '__ia32_sys_bpf' is marked as an entry point.
Function '__x64_sys_bpf' is marked as an entry point.
Total 2032 BPF programs attached successfully!
Receiving data...
                              ffffffff81c0007c entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                              ffffffff81bee6dd do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
           63us [-EINVAL]     ffffffff8116de95 __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                                               . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)
                             ~ffffffffa1ac4057 bpf_trampoline_6442464085_1+0x57
                              ffffffff8116c6ca __do_sys_bpf+0x5ca                        (kernel/bpf/syscall.c:4438:9)
                                               . bpf_btf_load                            (kernel/bpf/syscall.c:3818:9)
                             ~ffffffff81195c45 btf_new_fd+0x5
                             ~ffffffffa2ce2057 bpf_trampoline_6442474345_1+0x57
           48us [-EINVAL]     ffffffff81195e53 btf_new_fd+0x213                          (kernel/bpf/btf.c:5639:8)
                                               . btf_parse                               (kernel/bpf/btf.c:4246:8)
                                               . btf_parse_type_sec                      (kernel/bpf/btf.c:4009:5)
            6us [-EINVAL]     ffffffff8118ede5 btf_check_all_metas+0x5                   (kernel/bpf/btf.c:3856:1)
                             ~ffffffffa2cfe080 bpf_trampoline_6442474383_1+0x80
                             ~ffffffffa0966e53 bpf_prog_814c04020ce2e2d5_fexit1+0x463
                             ~ffffffff81155491 bpf_get_stack_raw_tp+0x51
                             ~ffffffffa0966e53 bpf_prog_814c04020ce2e2d5_fexit1+0x463


                              ffffffff81c0007c entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                              ffffffff81bee6dd do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
            7us [-EINVAL]     ffffffff8116de95 __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                                               . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)
                             ~ffffffffa1ac4080 bpf_trampoline_6442464085_1+0x80
                             ~ffffffffa03cc5fb bpf_prog_814c04020ce2e2d5_fexit1+0x463
                             ~ffffffff81155491 bpf_get_stack_raw_tp+0x51
                             ~ffffffffa03cc5fb bpf_prog_814c04020ce2e2d5_fexit1+0x463


                              ffffffff81c0007c entry_SYSCALL_64_after_hwframe+0x44       (arch/x86/entry/entry_64.S:112:0)
                              ffffffff81bee6dd do_syscall_64+0x2d                        (arch/x86/entry/common.c:46:12)
           83us [-ENOMEM]     ffffffff8116de95 __x64_sys_bpf+0x5                         (kernel/bpf/syscall.c:4351:1)
                                               . __se_sys_bpf                            (kernel/bpf/syscall.c:4351:1)
                             ~ffffffffa1ac4057 bpf_trampoline_6442464085_1+0x57
                              ffffffff8116c459 __do_sys_bpf+0x359                        (kernel/bpf/syscall.c:4375:9)
                                               . map_create                              (kernel/bpf/syscall.c:828:8)
                                               . find_and_alloc_map                      (kernel/bpf/syscall.c:122:8)
                             ~ffffffff81188145 array_map_alloc+0x5
                             ~ffffffffa2928057 bpf_trampoline_6442473861_1+0x57
           67us [-ENOMEM]     ffffffff8118832b array_map_alloc+0x1eb                     (kernel/bpf/arraymap.c:150:16)
                                               . bpf_array_alloc_percpu                  (kernel/bpf/arraymap.c:39:6)
                             ~ffffffff8116a3d5 bpf_map_alloc_percpu+0x5
                             ~ffffffffa26a406d bpf_trampoline_6442473048_1+0x6d
           26us [NULL]        ffffffff8116a40f bpf_map_alloc_percpu+0x3f                 (kernel/bpf/syscall.c:436:2)
                                               . set_active_memcg                        (include/linux/sched/mm.h:315:6)
                                               . preempt_count                           (arch/x86/include/asm/preempt.h:27:9)
           22us [NULL]        ffffffff811e4815 __alloc_percpu_gfp+0x5                    (mm/percpu.c:1894:9)
                             ~ffffffffa1ca4065 bpf_trampoline_6442477050_1+0x65
            3us [NULL]        ffffffff811e4035 pcpu_alloc+0x5                            (mm/percpu.c:1679:1)
                             ~ffffffffa1ea6096 bpf_trampoline_6442477052_1+0x96
                             ~ffffffffa0ba2513 bpf_prog_22cf752688d52e2b_fexit4+0x463
                             ~ffffffff81155491 bpf_get_stack_raw_tp+0x51
                             ~ffffffffa0ba2513 bpf_prog_22cf752688d52e2b_fexit4+0x463
```

Those function calls with `~` in front are filtered out, as they correspond to
BPF trampoline and BPF programs, which most probably are coming from
retsnoop's own instrumentation. You should be able to ignore them most of the
time.

## Entry, allow, and deny globs

Retsnoop allows to specify functions of interest with glob expressions:
  - entry globs, for functions that would trigger tracking of call stacks
    (e.g., `*_sys_bpf` to trace bpf() syscall); any other function will be
    ignored, unless it is called, directly or indirectly, from one of the
    entry functions;
  - allow globs, for functions that will be traced and whose return results
    would be captured on errors; allowed functions don't trigger the tracing
    itself, but they are tracked as part of entry function's call stacks;
  - deny globs, for functions that should never be traced (e.g., if they are
    too low-level to trace safely).

To specify entry/allow/deny globs, use `-e`/`-a`/`-d` options, like so:

```shell
$ sudo retsnoop -e '*_sys_bpf' -a '*bpf*' -d 'migrate*' -d 'rcu*'
```

## Use cases

Additionally, retsnoop comes with so-called use cases, which are predefined
sets of entry, allow, and deny globs. One or more of those use cases can be
specified:

```shell
$ sudo retsnoop -c bpf
```

Either use case or at least one entry glob that matches at least one function
has to be specified. Entry functions (those that match entry globs) are
automatically enlisted as allowed functions.

Currently only `bpf` use case is defined.

## Filtering by process ID (PID)

It is possible to only trace kernel stacks within the context of specified
PID:

```shell
$ sudo retsnoop -c bpf -p 123
```

In the future, retsnoop might support auto-spawning of the process in perf
fashion like this:

```shell
$ sudo retsnoop -c bpf -- ./my_app arg1 arg2
```

## Call stack symbolization
Retsnoop is "hosting" fast Rust-based
[addr2line](https://github.com/gimli-rs/addr2line) utility internally, which it
can use to perform more extensive stack trace symbolizations, including source
code level information (file path and line number and position) and inline
function calls. To use them, specify either `-s` for line number info only or
`-ss` for both line info and inline fuctions. With high rate of errors, extra
symbolization might be too prohibitive, so please try with and without extra
symbolization. Retsnoop performs a simple function name + offset resolution
using /proc/kallsyms-based unconditionally.

When extended symbolization is requested, resnoop is expected to find kernel
image (`vmlinux`) in one of standard locations (e.g., `/boot/vmlinux-$(uname
-r)`). It is possible to specify kernel image location explicitly with `-k`
option.

### addr2line

retsnoop embeds addr2line inside to perform additional stack symbolization,
including file/line information and inline function calls. retsnoop runs
addr2line in a separate process with two pipes for stdin/stdout communication.
To allow this mode of operation without additional complexities of setting up
pseudo-terminals, addr2line is modified to forcefully flush its stdout output
after each symbolized address. Until [PR]
(https://github.com/gimli-rs/addr2line/pull/210) is applied upstream,
[patch](https://github.com/anakryiko/retsnoop/blob/master/tools/0001-examples-addr2line-flush-stdout-after-each-response.patch)
can be applied on top of the latest [master
branch](https://github.com/anakryiko/retsnoop/releases). But for convenience,
custom-built and stripped addr2line (x86-64 architecture only) is already
checked in in this repository under `tools/`.

## Kernel and environment dependencies

Retsnoop is using some of the more recent BPF features (BTF, fentry/fexit BPF
program types, etc), so will require sufficiently recent kernel version. It's
on our TODO list to determine minimum upstream kernel version that retsnoop
supports.

## Building retsnoop from source 

See pre-built versions of retsnoop for x86-64 (amd64) architecture in
[Releases](https://github.com/anakryiko/retsnoop/releases) section.

It's also straightforward to build retsnoop from sources. Most of retsnoop's
dependencies are already included:
  - libbpf is checkout as a submodule, build and statically linked
    automatically by retsnoop's Makefile;
  - the only runtime libraries (beyond libc) is libelf and zlib, you'll also
    need develop versions of them to compile libbpf;
  - retsnoop pre-packages x86-64 versions of necessary tooling (addr2line and
    bpftool) required during the build;
  - the largest external depenency is Clang compiler with support for `bpf`
    target. Try to use at least Clang 11+, but Clang 10 might be able to work.

Once dependencies are satisfied, the rest is simple:
```shell
$ make -C src
```

You'll get `retsnoop` binary under `src/` folder. You can copy it to
a production server and run it. There are no extra files that need to be
distributed.

