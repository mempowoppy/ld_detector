# ld_detector
detect LD_PRELOAD hijacking, library injection attacks, and dynamic linker manipulation

it implements multiple detection mechanisms including environment variable enumeration for ld_preload, ld_library_path, ld_audit, and ld_debug manipulations, process memory mapping analysis through `/proc/self/maps` parsing for suspicious shared object locations and dynamic linker introspection using `dl_iterate_phdr()` to enumerate loaded objects via program header inspection

it also performs symbol resolution hooking detection using `dlsym()` and `dladdr()` to identify function pointer redirection, filesystem metadata validation through `stat()` analysis for setuid/setgid bits and world writable permissions, mount namespace inspection of `/proc/mounts` for overlay filesystems and command line forensics via `/proc/self/cmdline` analysis

compilation requires libdl for dynamic loading primitives and glibc for proc filesystem access. standard build process is `gcc -o ld_detector ld_detector.c -ldl`. basic usage involves executing `./ld_detector` for standard scanning, `sudo ./ld_detector` for elevated privileges and full system visibility or `LD_PRELOAD=/tmp/test.so ./ld_detector` to test detection capabilities against known injection vectors
