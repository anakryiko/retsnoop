# TODO

1. [DONE] Switch from per-CPU call_stack tracking to per-task.
2. [DONE] Fix stack stitching to support arbitrary number of stitched pieces.
3. See if we can optimize the size of struct call_stack, it's pretty gigantic right now.
4. Validate if recursive protection is still needed (at least on latest kernels).
5. Minimize/prune BPF preset, it takes multiple minutes on a slightly older kernel.
6. Add per-stack metadata:
    - [DONE] timestamp;
    - [DONE] PID/TID/UID.
7. Capture input arguments for each function. Pretty-print them (e.g., const char * and struct bpf_attr *).
8. [DONE] Add ability to provide lists of globs from file.

    
