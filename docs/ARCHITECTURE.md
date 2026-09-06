# Architecture

Win-TraceGuard is split into four intentionally small layers so the project can be read, tested and extended without turning the ETW callback into a monolith.

```text
Microsoft-Windows-Kernel-Process
              |
              v
       ETW session layer
 StartTrace / EnableTraceEx2
 OpenTrace / ProcessTrace / TDH
              |
              v
       Normalized Event model
 process_start / process_stop / image_load
              |
        +-----+------+
        |            |
        v            v
 Correlation state   JSONL recorder
        |
        v
   Detection engine
        |
        v
      Findings
 console / JSONL / replay
```

## ETW collection layer

`src/etw_session.cpp` owns the realtime ETW session. The provider GUID is resolved dynamically by provider name through `TdhEnumerateProviders`, avoiding a magic GUID in the source tree. The session is created with `StartTraceW`, the provider is enabled with `EnableTraceEx2`, and records are consumed with `OpenTraceW` + `ProcessTrace`.

The event payload is decoded with the Trace Data Helper API (`TdhGetPropertySize` / `TdhGetProperty`). TraceGuard intentionally asks for a short list of named properties such as `ProcessID`, `ParentProcessID`, `ImageName`, `CommandLine`, `ImageBase` and `ImageSize`. Missing properties do not crash the sensor; they simply produce a partial event.

## Normalization layer

Native ETW events are normalized into the `traceguard::Event` structure. The detection engine never consumes raw ETW pointers. This boundary makes the rule engine deterministic and replayable.

The v1 event kinds are `process_start`, `process_stop`, `image_load`, and `other`.

Process ancestry is enriched with a small in-memory PID-to-image map. The map is removed on process-stop events and is not persisted.

## Detection layer

`RuleEngine` evaluates explicit, explainable heuristics. It does not execute payloads, inspect remote process memory, inject code, block processes or modify the endpoint. Findings are analyst triage signals, not malware verdicts.

The detection engine can consume both live ETW events and a JSONL replay file. That separation gives the repository a testable detection-development workflow even when CI cannot start privileged ETW sessions.

## Recording and replay

Every normalized event can be written as one JSON object per line. Findings can be written to the same stream. The built-in replay command ignores non-event lines and re-runs the current detection rules over historical normalized events.

```text
capture -> normalized JSONL -> new rule -> replay -> compare findings
```

## Trust boundaries

The parser treats ETW property data and replay files as untrusted input. Size checks are applied before allocations, unknown or missing properties are tolerated, JSON replay parsing is limited to the flat v1 schema, and the sensor performs no automatic remediation.
