# What is retsnoop?

Retsnoop is a BPF-based tool for non-intrusive mass-tracing of Linux
kernel[^uprobe-support] internals.

Retsnoop's main goal is to provide a flexible and ergonomic way to extract the
exact information from the kernel that is useful to the user. At any given
moment, a running kernel is doing many different things, across many different
subsystems, and on many different cores. Extracting and reviewing all of the
various logs, callstacks, tracepoints, etc across the whole kernel can be a
very time consuming and burdensome task. Similarly, iteratively adding printk()
statements requires long iteration cycles of recompiling, rebooting, and
rerunning testcases. Retsnoop, on the other hand, allows users to achieve a
much higher signal-to-noise ratio by allowing them to specify both the specific
subset of kernel functions that they would like to monitor, as well as the
types of information to be collected from those functions, all without
requiring any kernel changes.

Retsnoop achieves its goal by low-overhead non-intrusive tracing of a
collection of kernel functions, intercepting their entries and exits.
Retsnoop's central concept is a **user-specified** set of kernel functions of
interest. This allows retsnoop to capture high-relevance data by letting the
user flexibly control a relevant subset of kernel functions. All other kernel
functions are ignored and don't pollute captured data with irrelevant
information.
	  
Retsnoop also supports a set of additional filters for further restricting the
context and conditions under which tracing data is captured, allowing to filter
based on PID or process name, choose a subset of admissible errors returned
from functions, or gate on function latencies.
	  
Retsnoop supports **three different and complementary modes**.

The default **stack trace mode** succinctly points to the deepest function call
stack that satisfies user conditions (e.g., an error returned from the
syscall). It shows a sequence of function calls, the corresponding source code
locations at each level of the stack, and emits latencies and returned results:

```
$ sudo ./retsnoop -e '*sys_bpf' -a ':kernel/bpf/*.c'
Receiving data...
20:19:36.372607 -> 20:19:36.372682 TID/PID 8346/8346 (simfail/simfail):

                    entry_SYSCALL_64_after_hwframe+0x63  (arch/x86/entry/entry_64.S:120:0)
                    do_syscall_64+0x35                   (arch/x86/entry/common.c:80:7)
                    . do_syscall_x64                     (arch/x86/entry/common.c:50:12)
    73us [-ENOMEM]  __x64_sys_bpf+0x1a                   (kernel/bpf/syscall.c:5067:1)
    70us [-ENOMEM]  __sys_bpf+0x38b                      (kernel/bpf/syscall.c:4947:9)
                    . map_create                         (kernel/bpf/syscall.c:1106:8)
                    . find_and_alloc_map                 (kernel/bpf/syscall.c:132:5)
!   50us [-ENOMEM]  array_map_alloc
!*   2us [NULL]     bpf_map_alloc_percpu
^C
Detaching... DONE in 251 ms.
```

The **function call trace mode** (`-T`) additionally provides a detailed trace
of control flow across the given set of functions, allowing to understand the
kernel behavior more comprehensively:

```
FUNCTION CALL TRACE                               RESULT                 DURATION
-----------------------------------------------   --------------------  ---------
→ bpf_prog_load
    → bpf_prog_alloc
        ↔ bpf_prog_alloc_no_stats                 [0xffffc9000031e000]    5.539us
    ← bpf_prog_alloc                              [0xffffc9000031e000]   10.265us
    [...]
    → bpf_prog_kallsyms_add
        ↔ bpf_ksym_add                            [void]                  2.046us
    ← bpf_prog_kallsyms_add                       [void]                  6.104us
← bpf_prog_load                                   [5]                   374.697us
```

Last, but not least, **LBR mode**
([Last Branch Records](https://lwn.net/Articles/680985/)) allows the user to
"look back" and peek deeper into individual function's internals, trace
"invisible" inlined functions, and pinpoint the problem all the way down to the
individual C statements. This mode is especially great when tracing unfamiliar
parts of the kernel without having a good idea what to even look for. It
enables iterative discovery process without having much of an idea where to
look and what functions are relevant:

```
$ sudo ./retsnoop -e '*sys_bpf' -a 'array_map_alloc_check' --lbr=any
Receiving data...
20:29:17.844718 -> 20:29:17.844749 TID/PID 2385333/2385333 (simfail/simfail):
...
[#22] ftrace_trampoline+0x14c                                    ->  array_map_alloc_check+0x5   (kernel/bpf/arraymap.c:53:20)
[#21] array_map_alloc_check+0x13  (kernel/bpf/arraymap.c:54:18)  ->  array_map_alloc_check+0x75  (kernel/bpf/arraymap.c:54:18)
      . bpf_map_attr_numa_node    (include/linux/bpf.h:1735:19)      . bpf_map_attr_numa_node    (include/linux/bpf.h:1735:19)
[#20] array_map_alloc_check+0x7a  (kernel/bpf/arraymap.c:54:18)  ->  array_map_alloc_check+0x18  (kernel/bpf/arraymap.c:57:5)
      . bpf_map_attr_numa_node    (include/linux/bpf.h:1735:19)
[#19] array_map_alloc_check+0x1d  (kernel/bpf/arraymap.c:57:5)   ->  array_map_alloc_check+0x6f  (kernel/bpf/arraymap.c:62:10)
[#18] array_map_alloc_check+0x74  (kernel/bpf/arraymap.c:79:1)   ->  __kretprobe_trampoline+0x0
...
```

Please also check out **the companion blog post,
["Tracing Linux kernel with retsnoop"](https://nakryiko.com/posts/retsnoop-intro/),**
which goes into more details about each mode and demonstrates retsnoop usage
on a few examples inspired by the actual real-world problems.

> **_NOTE:_**
> Retsnoop is utilizing the power of [BPF technology](https://ebpf.io/what-is-ebpf)
> and so **requires root permissions**, or a sufficient level of capabilities
> (`CAP_BPF` and `CAP_PERFMON`). Also note that despite all the safety guarantees
> of BPF technology and careful implementation, kernel tracing is inherently
> tricky and potentially disruptive to production workloads, so it's always
> recommended to test whatever you are trying to do on a non-production system
> as much as possible. Typical user-context kernel code (which is a majority
> of Linux kernel code) won't cause any problems, but tracing very low-level
> internals running in special kernel context (e.g., hard IRQ, NMI, etc) might
> need some care. Linux kernel itself normally protects itself from tracing
> such dangerous and sensitive parts, but kernel bugs do slip in sometimes, so
> please use your best judgement (and test, if possible).

> **_NOTE:_**
> Retsnoop relies on [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
> technology, so please make sure your Linux kernel is built with
> `CONFIG_DEBUG_INFO_BTF=y` kernel config. Without this retsnoop will refuse
> to start.

[^uprobe-support]:
    User space tracing might be supported in the future, but for now retsnoop
    is specializing in tracing kernel internals only.

# Using retsnoop

This section provides a reference-style description of various `retsnoop`
concepts and features for those who want to use the full power of `retsnoop` to
their advantage. If you are new to `retsnoop`, consider checking
["Tracing Linux kernel with retsnoop"](https://nakryiko.com/posts/retsnoop-intro/)
blog post to familiarize yourself with the output format and see how the tool
can be utilized in practice.

## Specifying traced functions

Retsnoop's operation is centered around tracing multiple functions. Functions
are split into two categories: **entry** and **non-entry** (auxiliary)
functions. Entry functions define a set of functions that activate
`retsnoop`'s recording logic. When any entry function is called for the first
time, `retsnoop` starts tracking and recording all subsequent functions
calls, until the entry function that triggered recording returns. Once
recording is activated, both entry and non-entry functions are recorded in
exactly the same way and are not distinguished between each other. Function
calls within each thread are traced completely independently, so there could
be multiple recordings going on at the same time simultaneously on multi-CPU
systems.

So, in short, **entry functions** are recording triggers, while **non-entry**
functions are augmenting recorded data with additional internal function calls,
but only if those are called from an activated entry functions. If some
non-entry function is called before the entry function is called, such a call
is ignored by `retsnoop`. Such a split avoids low-signal spam such as
recordings of common helper functions that happen outside of an interesting
context of entry functions.

A set of functions is specified through:
  - `-e` (`--entry`) argument(s), to specify a set of entry functions.
  - `-a` (`--allow`) argument(s), to specify a set of non-entry functions. If
    any of the function in the non-entry set overlaps with the entry set, the
    entry set takes precedence.
  - `-d` (`--deny`) argument(s), to exclude specified functions from both
    entry and non-entry sets. Functions that are denied are filtered out from
    both entry and non-entry subsets. Denylist always take precedence.

Each of `-e`, `-a`, and `-d` expect a value which could be of two forms:
  - **function name glob**, similar to shell's file globs. E.g., `*bpf*` will
    match any function that has the "bpf" substring in its name. Only `*` and
    `?` wildcards are supported, and they can be specified multiple times. `*`
    wildcard matches any sequence of characters (or none), and `?` matches
    exactly one character. So `foo??` will match `foo10`, but not `foo1`. You
    can also optionally add **kernel module glob**, in the form of
    `<func-glob> [<module-glob>]`, to narrow down function search to only
    kernel modules matching specified glob pattern. E.g., `*_read_* [*kvm*]`
    would match `vmx_read_guest_seg_ar` from `kvm_intel` module, or
    `segmented_read_std` from `kvm` module. So, specifying `* [kvm]` is
    probably the easiest way to discover all the traceable functions in `kvm`
    module.
  - **source code path glob**, prefixed with ':' (e.g., `:kernel/bpf/*.c`).
    Any function that is defined in a source file that matches specified file
    path glob is added to the match. Source code location has to be relative
    to the kernel repo root. So, `:kernel/bpf/*.c` will match any function
    defined in `*.c` files under Linux's `kernel/bpf` directory. All this, of
    course, relies on the kernel image file (`vmlinux`) being available in one
    of the standard places and having DWARF debug information in it. Note that
    `retsnoop` doesn't analyze source code itself and doesn't expect it to be
    present anywhere. All this information is supposed to be recorded in DWARF
    debug information.

Any of `-e`, `-a`, and `-d` can be specified multiple times and matched
functions are concatenated within their category. This allows full flexibility
in matching disparate subsets of functions that can't be expressed through one
simple glob. Mixing function name globs and source code path globs are also
supported.

All matched functions are additionally checked against a list of traceable
functions, which the kernel reports in the
`/sys/kernel/debug/tracing/available_filter_functions` file. If you don't see
the expected function there, then most probably it's due to one of a few common
reasons:
  - function is inlined and as such isn't traceable directly; try to instead
    trace a non-inlined function that calls into the desired function or is
    called from it;
  - function is in some way special and is not allowed to be traceable by the
    kernel itself (usually some low-level functions executed in restricted
    kernel contexts);
  - function could be compiled out due to kernel config or is in a kernel
    module which isn't loaded at the time of tracing;
  - sometimes function got renamed due to some compiler optimization, getting
    additional suffix like `.isra.0` and similar; in such a case append '*' at
    the end to match such suffixes.

If in doubt whether you've specified the correct set of functions, use the
`--dry-run -v` argument to do a verbose dry-run, in which `retsnoop` will
report all the functions it discovered and will attempt to attach, but will
stop short of actually attaching them. This is the best way to validate
everything without any risk of interfering with the system's workload.

## Modes of operation

### Default stack trace mode

As mentioned above, by default `retsnoop` is capturing a stack trace, with the
deepest nested function calls that satisfy conditions. E.g., if no custom error
filters are specified, `retsnoop` will try to capture stack trace of a deepest
function call chain resulting in the error return. See
[the stack trace mode example](https://nakryiko.com/posts/retsnoop-intro/#failed-per-cpu-bpf-array-map-case)
in the companion blog post for more details.

Retsnoop always captures and emits stack trace. Other modes (function call
trace and LBR, described below) are complementary to the default stack trace
mode and each other.

### Function call trace mode

Providing `-T` (`--trace`) flag enables function call trace mode. In this
mode, `retsnoop` will keep track of a detailed sequence of calls between each
entry and non-entry function. Just like stack trace mode, this recording is
activated only upon hitting an entry function and also satisfying any of the
additional filtering conditions.

As mentioned above, this mode is complementing default stack trace mode, and,
if enabled, LBR mode. It provides a different view of a captured function call
sequence. Given it might be quite verbose and expensive to record, depending
on the specific workload and a set of functions of interest, it requires
explicit opt-in with a `-T` argument.

This mode is perfect for understanding kernel behavior in details, especially
unfamiliar parts of it. See
[the function call trace mode example](https://nakryiko.com/posts/retsnoop-intro/#tracing-bpf-verification-flow)
in the companion blog post for more details.

### LBR (Last Branch Records) mode

[LBR](https://lwn.net/Articles/680985/) (Last Branch Records) is an Intel CPU
feature that allows users to instruct the CPU to record the last
N calls/returns/jumps (what exactly is captured is configurable) constantly
with no overhead. The number of captured records depends on the generation of
CPU and is typically in 8 to 32 range. In recent enough Linux kernel (v5.16+)
it's possible to capture such LBRs from a BPF program in ad-hoc fashion, which
is utilized by `retsnoop` in the LBR mode. Some non-Intel CPUs have a similar
capabilities, which are abstracted away by the kernel's perf subsystem, so you
don't necessarily need Intel CPUs to take advantage of it with `retsnoop`.

So when is LBR mode useful? There are a few typical scenarios.

One of them is when you are investigating some generic error being returned
from the kernel. The kernel can return errors in various different cases and
it's not clear which one it is. This is often the case with `bpf()` syscall,
for example, where errors like `-EINVAL` can be returned due to dozens of
various error conditions, and a bunch of such conditions could be checked
within the same big function. Debugging exactly which error condition is hit
can be maddening at times. LBR mode allows users to get insight *into which
exact if condition within the function* returned an error.

Another common scenario is when you are trying to trace a completely
unfamiliar part of Linux kernel code. You might know the entry function, but
have no clue what other functions it calls and where in the source code they
are defined. E.g., a common case would be an entry function that calls into
generic callback and it's not clear where the callback function is actually
defined. In such cases it's very hard to know which function name globs or
source code path globs to specify, as there could be lots of possible
implementations of such callbacks. LBR mode can help here because it
doesn't require tracing relevant functions to discover them.

No matter what circumstances call for LBR mode, it can be activated by using
`-R` (`--lbr`) argument. Similar to the function call trace mode, LBR mode is
independent and complimentary to the default stack trace and function call
trace modes. When the right conditions happen, `retsnoop` captures LBR data,
in addition to stack trace and other information, and then outputs data in its
own format.

See [the LBR mode example](https://nakryiko.com/posts/retsnoop-intro/#peering-deep-into-functions-with-lbr)
in the companion blog post for more details.

Here we'll just note that LBR mode allows customizing what kind of records the
CPU is instructed to record. It can be one of the following values: `any`,
`any_call`, `any_return` (default), `cond`, `call`, `ind_call`, `ind_jump`,
`call_stack`, `abort_tx`, `in_tx`, `no_tx`. See Linux's
[perf_event.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h#L180-L208)
UAPI header and its `enum perf_branch_sample_type_shift`'s comments for brief
descriptions of each of those modes.

By default, `retsnoop` assumes `any_return` LBR configuration, which records
the last N returns from functions. This is very useful for the second type of
cases when we want to know which functions are being called without having to
study code thoroughly. The LBR stack will point to functions called before the
deepest explicitly traced by `retsnoop` function was called, even if they
weren't part of entry/non-entry set of functions. So you can keep iterating
with `retsnoop` and expanding entry/non-entry function sets this way.

For the first class of scenarios (complicated functions with multiple error
conditions), LBR config `any` might be more appropriate. It records any
function calls, returns, and jumps, both conditional and unconditional. It
might help pinpoint the exact statement *within a single big function* that is
returning an error, as it's not bound to function boundaries.

Note that LBR is a tricky business and it might not capture enough relevant
details or sometimes it capture irrelevant details. If the latter is the case,
you can trim it down with `--lbr-max-count` argument to emit specified number
of most relevant entries.

## Additional filters

By default, `retsnoop` records any function call traces (based on entry and
non-entry function sets) that result in a triggered entry function returning an
error. The "error return" is defined heuristically and is either `NULL` for
pointer-returning functions or `-Exxx` small negative error for integer
returning ones. This can be further adjusted, as you'll see below. But such
function traces are collected globally across any process, which might be
inconvenient and lead to irrelevant "spam" in output.

Fortunately, `retsnoop` allows the user to adjust conditions under which it
captures traces.

### Error filters

`-S` (`--success-stacks`) forces `retsnoop` to capture any function trace,
disabling the default logic of capturing only error-returning cases. If you
don't see `retsnoop` capturing stack traces or recording function call traces
that you are sure are happening inside the kernel, check if you need to enable
the successful stack traces capture with `-S`.

`retsnoop` also allows the user to fine-tune which return results are
considered to be erroneous with `-x` (`--allow-errors`) and `-X`
(`--deny-errors`) arguments. They expect either `Exxx`/`-Exxx` symbolic error
codes (you can find all errors recognized by `retsnoop`
[in this table](https://github.com/anakryiko/retsnoop/blob/master/src/utils.c#L10-L50))
or `NULL`.

These arguments can be specified multiple times and all errors are
concatenated into a single list. The error denylist (`-X`) takes precedence,
so if there is an overlap between `-x` and `-X`, `-X` wins and the specified
error will be ignored, even if it is allowed by `-x` argument.

If no `-x` is provided, all supported errors are assumed to be allowed, except
those denied by `-X`.

### Process filtering

`retsnoop` allows the user to narrow down a set of processes in the context of
which data will be captured. These filters are invaluable on busy production
hosts that have a lot of things going on at the same time, but you need to
investigate something happening only within a small subset of processes.

`-p` (`--pid`) and `-P` (`--no-pid`) allows filtering based on process ID
(PID). Just as with most other arguments like this, you can specify them
multiple times to combine multiple PID filters.

`-n` (`--comm`) and `-N` (`--no-comm`) allows the user to filter by
process/thread names, in addition to or instead of PID filtering. Can be
specified multiple times as well.

### Duration filter

`-L` (`--longer`) allows the user to specify the minimal duration of
a triggering entry function execution that will be captured and reported,
skipping everything that completed sooner. This argument should be a positive
number in units of milliseconds.

If you need to investigate latency issues, this filter allows the user to
ignore irrelevant fast-completing function calls and instead trace slow ones
in a more focused way.

## Other settings

### Verboseness, dry-run, version, and feature detection

`retsnoop` supports various levels of "verboseness". By default it doesn't
emit any extra information about what it's doing and which functions it's
going to trace. The default  verbose level (`-v`) provides a good list of
high-signal verbose output to understand what's going on under the cover. With
`-v` retsnoop will report a list of discovered functions, where the kernel
image is located, etc. `retsnoop` also has more verbose levels (`-vv` and
`-vvv`), but they most probably are only useful for developers of `retsnoop`
and for debugging.

The default verbose output is extremely useful in combination with dry-run mode,
activated with `--dry-run` argument. In this mode `retsnoop` will report all
the actions it's going to perform (including listing which functions it
discovered and is going to trace), but stops short of actually activating any
of that. This way there is not even a chance to disturb production workload and
it's a safe way to pre-check everything upfront.

`-V` (`--version`) will print `retsnoop`'s version. If combined with `-v`,
`retsnoop` will also output all the detected kernel features that it relies
on. You'll need to run `retsnoop` under root or with `CAP_BPF` and
`CAP_PERFMON` capabilities for feature detection to work. You should see
something like below:

```
$ sudo ./retsnoop -Vv
retsnoop v0.9.1
Feature detection:
        BPF ringbuf map supported: yes
        bpf_get_func_ip() supported: yes
        bpf_get_branch_snapshot() supported: yes
        BPF cookie supported: yes
        multi-attach kprobe supported: no
Feature calibration:
        kretprobe IP offset: 8
        fexit sleep fix: yes
        fentry re-entry protection: yes
```

### Symbolization settings

`retsnoop` tries to provide as accurate and full function and stack trace
information as possible. If Linux kernel image can be found in the system in
one of the standard locations and it contains DWARF type information, this
will be used to augment captured stack traces with information about source
code location and inline functions. Using DWARF information adds a bit of
extra CPU overhead, so this behavior and related parameters can be tuned.

If `retsnoop` fails to find the kernel image in the standard location, it can
be pointed to a custom location through the `-k` (`--kernel`) argument.

`-s` (`--symbolize`) allows the user to tune stack symbolization behavior.
Specify `-sn` to disable extra DWARF-based symbolization. In such case
`retsnoop` will stick to a basic symbolization based on `/proc/kallsyms` data.
`-s` alone will try to get source code location information, but won't attempt
to symbolize inline functions. `-ss` allows both inlined functions and source
code information. This is a default mode, if kernel with DWARF information is
found, due to its extreme usefulness in most of the cases.

Note, DWARF type information is also necessary for source code path globs to
work.

# Getting retsnoop

## Download pre-built x86-64 binary

**Each release has a pre-built retsnoop binary** for x86-64 (amd64) architecture
ready to be downloaded and used. Go to
["Releases"](https://github.com/anakryiko/retsnoop/releases) page to download
latest binary.

## Building retsnoop from source 

It's also pretty straightforward to build `retsnoop` from the sources. Most of `retsnoop`'s
dependencies are already included:
  - [libbpf](https://github.com/libbpf/libbpf/) is checked out as a submodule,
    built and statically linked automatically by `retsnoop`'s Makefile;
  - the only runtime libraries (beyond `libc`) is `libelf` and `zlib`, you'll
    also need development versions of them (for API headers) to compile
    `libbpf`;
  - `retsnoop` pre-packages x86-64 versions of necessary tooling
    ([bpftool](https://github.com/libbpf/bpftool/) required during the build,
    but this can be improved if there is an interest in `retsnoop` on non-x86
    architecture (please open an issue to request);
  - the largest external depenency is Clang compiler with support for `bpf`
    target. Try to use at least Clang 11+, but the latest Clang version you
    can get, the better.

Once dependencies are satisfied, the rest is simple:
```shell
$ make -C src
```

You'll get `retsnoop` binary under `src/` folder. You can copy it to
a production server and run it. There are no extra files that need to be
distributed besides the main `retsnoop` executable.

## Distro availability

Retsnoop started to be packaged by distros. Table below will point out which
distros package retsnoop and at which verison.

[![retsnoop distro status](https://repology.org/badge/vertical-allrepos/retsnoop.svg)](https://repology.org/project/retsnoop/versions)
