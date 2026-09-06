# Architecture

Win-TraceGuard is split into small C11 modules so the ETW callback remains an ingestion boundary rather than becoming the entire application.

```text
Microsoft-Windows-Kernel-Process
              |
              v
       ETW session layer
 StartTrace / EnableTraceEx2
 OpenTrace / ProcessTrace / TDH
              |
              v
          TgEvent
 bounded normalized C structure
              |
        +-----+------+
        |            |
        v            v
 PID correlation     JSONL recorder
        |
        v
   C rule engine
        |
        v
     TgFinding
 console / JSONL / replay
```

## Module layout

| Module | Responsibility |
|---|---|
| `src/etw_session.c` | ETW/TDH lifecycle, provider resolution, property decoding and normalization |
| `src/event.c` | event/finding initialization and safe string helpers |
| `src/rule_engine.c` | transient PID state and explainable detection heuristics |
| `src/jsonl.c` | bounded serializer plus narrow replay parser |
| `src/main.c` | CLI, output, capture timeout and top-level ownership |

Public interfaces are plain `.h` files under `include/traceguard/`.

## C11 ownership model

The project deliberately uses explicit C ownership rather than constructors, exceptions or RAII.

- `TgEtwSession` is initialized with `tg_etw_session_init()` and released with `tg_etw_session_dispose()`.
- `TgRuleEngine` owns its transient process table after `tg_rule_engine_init()` and frees it with `tg_rule_engine_dispose()`.
- `TgJsonlWriter` owns a `FILE*` only while it is open.
- temporary TDH property buffers are allocated inside the ETW layer, copied into bounded normalized fields and freed before the callback returns.
- Win32 handles created by the CLI are closed explicitly on every exit path.

This makes resource ownership visible during code review.

## ETW collection layer

`src/etw_session.c` owns the realtime ETW session. The provider GUID is resolved dynamically by provider name with `TdhEnumerateProviders`, avoiding a magic GUID in the source tree. The session is created with `StartTraceW`, enabled with `EnableTraceEx2`, and consumed through `OpenTraceW` + `ProcessTrace`.

The event payload is decoded with `TdhGetPropertySize` / `TdhGetProperty`. Property allocations are capped, and only a bounded set of useful fields is normalized, including process ID, parent process ID, image path, command line and image-load metadata.

Property presence can vary across Windows builds and event versions. Missing fields are treated as partial telemetry rather than fatal parser errors.

## Normalization layer

Raw `EVENT_RECORD` pointers never enter the detection engine. The ETW layer copies accepted values into `TgEvent`, which contains fixed-capacity fields for timestamps, provider names, paths and command lines.

The normalized event kinds are:

- `TG_EVENT_PROCESS_START`
- `TG_EVENT_PROCESS_STOP`
- `TG_EVENT_IMAGE_LOAD`
- `TG_EVENT_OTHER`

Explicit process-stop and image-load evidence is classified before heuristic process-start inference so a stop record carrying parent metadata is not accidentally retained as a new process.

## Correlation state

Both the collector and rule engine use small transient PID-to-image tables for context. The rule-engine table exists so replay data can reproduce parent/child correlation without ETW.

Entries are removed on process-stop events. State is bounded and memory-only; it is not persisted.

## Detection layer

`tg_rule_engine_evaluate()` receives a normalized `TgEvent` and writes zero or more `TgFinding` structures into a caller-provided bounded array.

The engine does not execute payloads, inspect remote process memory, inject code, terminate processes or modify the endpoint. Findings are analyst triage signals, not malware verdicts.

Live ETW events and replayed events use the same detection function, which keeps rule behavior testable and deterministic.

## Recording and replay

`src/jsonl.c` serializes normalized events/findings into a flat JSONL contract using a bounded output buffer. The replay reader intentionally implements only that documented TraceGuard event shape rather than a general JSON parser.

```text
capture -> normalized JSONL -> rule change -> replay -> compare findings
```

The separation lets CI test detections without requiring permissions to start a realtime trace session.

## Capture timeout

The CLI uses a Win32 event plus `CreateThread` for the bounded capture timer. The timer calls the normal session-stop function when the requested interval expires. No C++ threading/runtime layer is involved.

## Trust boundaries

ETW property payloads and replay files are untrusted input.

The design therefore uses:

- capped TDH property allocation;
- bounded normalized fields;
- checked wide/narrow-to-UTF-8 conversions;
- bounded JSON output;
- narrow replay parsing;
- explicit process-table capacity;
- explicit handle/allocation cleanup;
- no automatic remediation.

## Build-language invariant

CMake declares `LANGUAGES C` and `CMAKE_C_STANDARD 11`. CI additionally searches the repository for `.cpp`, `.cc`, `.cxx`, `.hpp` and `.hh` files and fails if any are present. The pure-C property is therefore tested, not merely documented.
