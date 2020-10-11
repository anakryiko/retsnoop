addr2line
=========

retsnoop embeds addr2line inside to perform additional stack symbolization,
including file/line information and inline function calls. retsnoop runs
addr2line in a separate process with two pipes for stdin/stdout communication.
To allow this mode of operation without additional complexities of setting up
pseudo-terminals, addr2line is modified to forcefully flush its stdout output
after each symbolized address. Until PR ([0]) is applied upstream, patch
(tools/0001-examples-addr2line-flush-stdout-after-each-response.patch) can be
applied on top of the latest master branch at [1]. But for convenience,
custom-built and stripped addr2line (amd64 architecture only) is already
checked in in this repository.

  [0] https://github.com/gimli-rs/addr2line/pull/210
  [1] https://github.com/gimli-rs/addr2line

