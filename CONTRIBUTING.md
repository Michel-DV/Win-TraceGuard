# Contributing

Contributions are welcome when they preserve the project's defensive, read-only boundary and the native **C11 + WinAPI** implementation.

## Build

```powershell
cmake -S . -B build -A x64 -DTRACEGUARD_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Language boundary

The maintained codebase is pure C11. New implementation files should use `.c` / `.h` and must not introduce C++ source/header files, CXX language configuration or STL/runtime dependencies. CI enforces this rule automatically.

Prefer:

- plain structs with explicit initialization/cleanup;
- bounded buffers and checked conversions;
- visible ownership for allocations and Windows handles;
- narrow module interfaces;
- Win32 APIs where platform functionality is required.

## Rule contributions

A detection rule should have a stable ID, an explainable rationale, a bounded false-positive story and regression tests. Prefer correlations that improve analyst context over a large list of weak string matches.

Rules operate on normalized `TgEvent` fields rather than raw ETW/TDH structures. Keep Windows trace decoding inside the collection layer so replay and unit tests remain deterministic.

## Code quality

The MSVC build runs with `/W4 /utf-8`. New code should compile cleanly, preserve the pure-C source audit, pass CTest and keep replay smoke tests green.

Changes that affect memory ownership, ETW property decoding, JSON parsing, process-state cleanup or handle lifetime should include focused regression coverage whenever practical.
