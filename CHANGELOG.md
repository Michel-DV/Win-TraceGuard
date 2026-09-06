# Changelog

All notable changes to Win-TraceGuard are documented here.

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
- C++20/CMake build;
- unit tests and Windows/MSVC CI;
- architecture, detections, output and threat-model documentation;
- custom terminal-style README visuals.
