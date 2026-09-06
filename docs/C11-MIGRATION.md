# Pure C11 migration verification

Win-TraceGuard 1.0.1 replaces the initial implementation with a maintained **ISO C11 + WinAPI** codebase while preserving the defensive ETW telemetry and detection workflow.

## What changed

- implementation files are `.c` / `.h` only;
- CMake declares `LANGUAGES C` and requires C11;
- ETW callbacks use C function pointers;
- process/event/finding state uses plain C structures;
- JSONL serialization and replay parsing use bounded C buffers;
- capture timing uses Win32 synchronization/thread primitives;
- explicit init/dispose functions own allocations and Windows resources.

## What did not change

- realtime `Microsoft-Windows-Kernel-Process` collection;
- TDH provider/property discovery;
- process-start, process-stop and image-load normalization;
- parent/child correlation;
- the seven v1 detection IDs;
- console + JSONL output;
- deterministic replay workflow;
- read-only security boundary.

## Verification gates

The CI workflow fails if it finds `.cpp`, `.cc`, `.cxx`, `.hpp` or `.hh` files. It also fails if CMake enables CXX or does not explicitly configure C11.

A successful CI run therefore verifies all of the following on a Windows/MSVC runner:

```text
Pure-C source audit      PASS
CMake LANGUAGES C        PASS
MSVC C compiler          PASS
Release build            PASS
CTest                     PASS
Version reports C11      PASS
Provider CLI smoke       PASS
Detection replay         PASS
```

This check exists so the language claim is mechanically enforced rather than relying only on README text.
