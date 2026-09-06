# Changelog

All notable changes to Win-TraceGuard are documented here.

## 1.0.1 - 2026-09-06

### Changed

- rewrote the maintained implementation in **ISO C11 + WinAPI**;
- replaced higher-level runtime abstractions with explicit C structures, function-pointer callbacks and lifecycle functions;
- replaced stream/container-based JSON handling with bounded C serialization and replay parsing;
- moved capture timing to Win32 synchronization/thread primitives;
- preserved realtime ETW collection, TDH property decoding, process ancestry correlation, all seven v1 detections, JSONL recording and deterministic replay;
- updated the entire test suite, build system and documentation for the C11 implementation.

### Hardened

- added CI enforcement that rejects C++ source/header files and CXX CMake configuration;
- added explicit bounds around TDH property allocation and normalized event fields;
- tightened ETW text-conversion ownership so temporary buffers have a single cleanup path;
- classified explicit process-stop/image-load opcodes before heuristic process-start inference;
- expanded regression coverage to all seven built-in detections, benign control behavior, JSON round-trip, PPID correlation and process-stop cleanup.

## 1.0.0 - 2026-09-06

### Added

- realtime ETW collection using `Microsoft-Windows-Kernel-Process`;
- provider discovery through TDH rather than a hard-coded GUID;
- process-start, process-stop and image-load normalization;
- transient parent/child process correlation;
- seven explainable v1 detection heuristics;
- human-readable console findings;
- JSONL event/finding recording;
- deterministic JSONL replay mode for detection regression testing;
- CMake build, Windows/MSVC CI and unit tests;
- architecture, detections, output and threat-model documentation;
- custom terminal-style README visuals.
