# Contributing

Contributions are welcome when they preserve the project's defensive and read-only boundary.

## Build

```powershell
cmake -S . -B build -A x64 -DTRACEGUARD_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Rule contributions

A detection rule should have a stable ID, an explainable rationale, a bounded false-positive story and regression tests. Prefer correlations that improve analyst context over a large list of weak string matches.

## Code style

The project targets C++20 and MSVC with `/W4 /permissive- /utf-8`. Keep raw ETW decoding inside the collection layer and keep the rule engine independent of Windows ETW types.
