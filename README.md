# Win-TraceGuard

<p align="center">
  <strong>Native Windows ETW telemetry & detection sensor for endpoint research, hunting and detection engineering.</strong>
</p>

<p align="center">
  <a href="../../actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Michel-DV/Win-TraceGuard/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="C++20" src="https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus">
  <img alt="Windows" src="https://img.shields.io/badge/platform-Windows-0078D4?logo=windows11">
  <img alt="ETW" src="https://img.shields.io/badge/telemetry-ETW-6f42c1">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-2ea44f">
</p>

Win-TraceGuard turns low-level Windows **Event Tracing for Windows (ETW)** process telemetry into a compact analyst workflow:

**collect → normalize → correlate → detect → record → replay**.

It is intentionally read-only. TraceGuard does **not** inject into processes, modify remote memory, install persistence, steal credentials, exploit hosts, terminate processes or attempt to evade security controls. Its job is to observe endpoint behavior and explain why a sequence is interesting.

![Win-TraceGuard architecture](docs/assets/overview.svg)

## Why this project exists

A lot of endpoint-security demos stop at one of two extremes: either they print raw ETW metadata that is difficult to reason about, or they jump straight to a large opaque detection framework. TraceGuard sits in the middle.

The v1 design demonstrates how a native Windows sensor can:

- create and consume a realtime ETW session;
- resolve a provider dynamically instead of hard-coding its GUID;
- decode selected ETW properties with **TDH**;
- normalize OS-specific records into a stable event model;
- correlate parent/child processes in memory;
- apply small, explainable detection rules;
- write a replayable JSONL evidence stream;
- regression-test detection logic without requiring privileged ETW access in CI.

That makes the repository useful both as a security tool and as a readable Windows-internals/detection-engineering project.

---

## Live capture preview

> The terminal graphics in this README are illustrative v1 output previews built from the documented output contract. They are not presented as malware-analysis evidence from a real host.

![Live TraceGuard capture](docs/assets/live-preview.svg)

```powershell
traceguard.exe capture --seconds 30 --jsonl trace.jsonl
```

TraceGuard subscribes to the `Microsoft-Windows-Kernel-Process` ETW provider, normalizes supported process/image events, evaluates the rule engine, prints findings and optionally records both events and findings to JSONL.

Depending on local Windows ETW policy, starting the realtime session can require an **elevated terminal** or equivalent trace-session permissions. TraceGuard reports the Windows error and exits; it does not attempt to bypass the policy.

---

## Detection replay

The replay workflow is one of the most important design choices in the project.

![TraceGuard replay](docs/assets/replay-preview.svg)

```powershell
traceguard.exe replay .\samples\demo-events.jsonl
```

A normalized event file can be replayed through the **current** rule engine. That means a detection can be added or tuned and then tested against the same telemetry without re-running a live capture.

For machine-readable findings:

```powershell
traceguard.exe replay .\samples\demo-events.jsonl --json
```

---

## What v1 collects

The ETW layer currently focuses on `Microsoft-Windows-Kernel-Process` and attempts to normalize:

| Field | Purpose |
|---|---|
| timestamp | UTC event time |
| kind | `process_start`, `process_stop`, `image_load`, `other` |
| PID / PPID | process correlation |
| image | process executable path/name when exposed by the provider schema |
| parent image | transient enrichment from the PPID map |
| command line | process command line when available |
| loaded image | DLL/image path for image-load style records |
| event ID / opcode | low-level ETW context |
| provider | source provider name |

Property decoding is deliberately tolerant. ETW schemas can vary by Windows build and event version, so a missing field yields a partial event rather than a crash.

---

## Built-in detections

The first release ships with a compact rule set chosen to demonstrate **correlation and explainability**, not to maximize alert count.

| Rule | Severity | What it detects |
|---|---:|---|
| `TG1001` | Medium | executable starts from AppData, Temp, Downloads or `Users\Public` |
| `TG1002` | High | Office application spawns a command/script interpreter |
| `TG1003` | High | PowerShell command line contains an encoded-command switch |
| `TG1004` | High | `mshta.exe` launched with HTTP/HTTPS content |
| `TG1005` | High | `rundll32.exe` contains remote or script-like content |
| `TG1006` | Medium | Windows dual-use utility references a user-writable location |
| `TG2001` | Medium | image/DLL is loaded from a user-writable path |

A finding is **not a malware verdict**. Each rule includes a rationale explaining why the event deserves attention and where legitimate false positives are plausible.

Detailed rule notes live in [`docs/DETECTIONS.md`](docs/DETECTIONS.md).

---

## JSONL evidence stream

![TraceGuard JSONL](docs/assets/json-preview.svg)

Example event:

```json
{"type":"event","timestamp_utc":"2026-09-06T12:00:01.000Z","kind":"process_start","pid":4112,"ppid":4100,"event_id":1,"opcode":1,"provider":"Microsoft-Windows-Kernel-Process","image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent_image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","command_line":"powershell.exe -EncodedCommand SQBFAFgA","loaded_image":""}
```

Example finding:

```json
{"type":"finding","timestamp_utc":"2026-09-06T12:00:01.000Z","rule_id":"TG1003","severity":"high","title":"PowerShell command line contains an encoded-command switch","rationale":"Encoded PowerShell is not inherently malicious, but it reduces command-line transparency and is a strong triage signal when correlated with process ancestry.","pid":4112,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
```

The schema is intentionally flat and easy to feed into PowerShell, Python, notebooks, jq-compatible tooling or a future SIEM adapter.

See [`docs/OUTPUT.md`](docs/OUTPUT.md) for the output contract.

---

## Native Windows implementation

The realtime collector is implemented directly with Windows tracing APIs:

```text
TdhEnumerateProviders
        |
        v
resolve Microsoft-Windows-Kernel-Process GUID
        |
        v
StartTraceW
        |
        v
EnableTraceEx2
        |
        v
OpenTraceW + ProcessTrace
        |
        v
EVENT_RECORD callback
        |
        v
TdhGetPropertySize / TdhGetProperty
```

There is no Python runtime, service dependency, packet driver or external JSON library in the v1 executable.

The provider GUID is resolved by name at runtime through TDH. This keeps the source readable and makes the provider dependency explicit.

---

## Process ancestry correlation

Raw telemetry frequently gives an analyst a PID and PPID but not a fully enriched process tree. TraceGuard maintains a small in-memory map:

```text
PID 4100 -> WINWORD.EXE
PID 4112 -> powershell.exe
```

When the child arrives, the engine can enrich it with the known parent image:

```text
WINWORD.EXE
    └── powershell.exe
          └── TG1002
          └── TG1003
```

Entries are removed on process-stop events. The map is intentionally transient and never becomes a hidden database.

---

## Build

### Requirements

- Windows 10/11 or Windows Server with the ETW provider available;
- Visual Studio 2022+ / MSVC with C++ desktop workload;
- CMake 3.22 or later;
- x64 build recommended.

### Configure and compile

```powershell
cmake -S . -B build -A x64 -DTRACEGUARD_BUILD_TESTS=ON
cmake --build build --config Release --parallel
```

Binary:

```text
build\Release\traceguard.exe
```

Run tests:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

---

## CLI

```text
traceguard capture [--seconds N] [--jsonl path] [--quiet]
traceguard replay <events.jsonl> [--json]
traceguard providers
traceguard --version
```

Examples:

```powershell
# 15-second interactive capture
traceguard.exe capture --seconds 15

# Record normalized telemetry and findings
traceguard.exe capture --seconds 60 --jsonl .\out\endpoint.jsonl

# Quiet event stream but still print findings
traceguard.exe capture --seconds 60 --quiet

# Replay the included safe synthetic dataset
traceguard.exe replay .\samples\demo-events.jsonl

# Produce only machine-readable findings
traceguard.exe replay .\samples\demo-events.jsonl --json
```

Capture duration is bounded to 1–3600 seconds in v1.

---

## Safe synthetic demo dataset

`samples/demo-events.jsonl` contains a small **synthetic** telemetry sequence used by CI. It includes:

- a Word process;
- a PowerShell child with an encoded-command switch;
- an executable launched from Temp;
- an image load from Temp;
- a benign Notepad event.

The replay smoke test verifies that the expected rules fire and that the benign example does not need special-case suppression.

No malware sample or executable payload is included in the repository.

---

## Tests and CI

GitHub Actions builds and executes the project on a real Windows runner using MSVC x64.

The pipeline checks:

- CMake configuration;
- Release compilation;
- unit tests;
- JSON event round-trip;
- parent/child state correlation;
- detection rules;
- `--version` CLI smoke test;
- provider configuration CLI smoke test;
- replay of the synthetic JSONL dataset.

CI intentionally does **not** require starting a privileged realtime ETW session because hosted-runner trace permissions can change. The live collector is separated from the deterministic core specifically so the detection engine remains testable.

---

## Repository layout

```text
Win-TraceGuard/
├── .github/workflows/ci.yml
├── include/traceguard/
│   ├── etw_session.hpp
│   ├── event.hpp
│   ├── jsonl.hpp
│   └── rule_engine.hpp
├── src/
│   ├── etw_session.cpp
│   ├── event.cpp
│   ├── jsonl.cpp
│   ├── main.cpp
│   └── rule_engine.cpp
├── tests/test_core.cpp
├── samples/demo-events.jsonl
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DETECTIONS.md
│   ├── OUTPUT.md
│   ├── THREAT_MODEL.md
│   └── assets/
├── CMakeLists.txt
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

---

## Design principles

**Read-only by default.** The endpoint being observed is never modified by a detection action.

**Normalized before detection.** ETW-specific parsing stays out of the rule engine.

**Explainable findings.** Every rule states exactly what matched and why it matters.

**Replayable telemetry.** Detection logic can be improved without reproducing a live event chain.

**Graceful partial data.** Missing ETW properties are expected and handled.

**No hidden network dependency.** v1 does not upload telemetry or query cloud reputation services.

---

## Limitations

TraceGuard v1 is intentionally not an EDR replacement.

- ETW property availability varies across Windows versions/provider schemas.
- command lines can be absent depending on the event/version/policy;
- parent image enrichment only works when the parent has been observed in the current session or is present in replay data;
- PID reuse is handled only by process-stop cleanup, not a persistent process identity model;
- there is no kernel driver;
- there is no remote collection or central management;
- v1 does not yet correlate network telemetry;
- the rules are analyst-oriented heuristics rather than claims of compromise.

These limits are documented because they are part of building defensible detection tooling.

---

## Roadmap

Potential future work that preserves the defensive boundary:

- optional ETW network-provider correlation;
- richer process identity using start time + PID;
- image signer/hash enrichment through a separate read-only module;
- configurable YAML/JSON detection rules;
- event filters and provider keyword controls;
- SARIF/Sigma-compatible export experiments;
- ETL-file offline replay;
- performance counters and dropped-event telemetry;
- richer Windows service and scheduled-task context;
- rule coverage/regression corpus.

---

## Security model

TraceGuard is designed for authorized defensive research, endpoint visibility and detection engineering. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`SECURITY.md`](SECURITY.md).

The sensor does not provide process injection, remote-memory writes, persistence, credential access, exploitation, security-product disabling or stealth/evasion functionality.

---

## Related portfolio project

**ProcSentinel-C** is the snapshot-oriented counterpart to TraceGuard: ProcSentinel analyzes process/PE state at a point in time, while Win-TraceGuard focuses on **telemetry over time and correlation**.

```text
ProcSentinel-C  -> snapshot / PE triage / endpoint state
Win-TraceGuard  -> ETW stream / behavioral detections / replay
```

Together they demonstrate two complementary approaches to native Windows endpoint security.

---

## License

MIT. See [`LICENSE`](LICENSE).
