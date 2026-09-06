# Detection catalog

Win-TraceGuard v1 ships with a deliberately compact set of high-signal, explainable heuristics. They are intended for learning, hunting and endpoint triage rather than as a replacement for an EDR detection corpus.

| ID | Severity | Signal |
|---|---|---|
| TG1001 | Medium | Process starts from AppData, Temp, Downloads or `Users\\Public` |
| TG1002 | High | Office application spawns a command/script interpreter |
| TG1003 | High | PowerShell uses an encoded-command switch |
| TG1004 | High | `mshta.exe` is launched with HTTP/HTTPS content |
| TG1005 | High | `rundll32.exe` contains remote or script-like content |
| TG1006 | Medium | A Windows dual-use utility references content in a user-writable path |
| TG2001 | Medium | An image/DLL is loaded from a user-writable path |

## Detection philosophy

A match is not a statement that a host is compromised. TraceGuard emits the exact reason for a match and keeps the source event available so an analyst can validate context.

For example, `TG1001` is intentionally framed as *execution from a user-writable location*. Many legitimate updaters and developer tools execute there, so the correct next step is validation, not automatic containment.

## Parent/child correlation

`TG1002` uses either the parent image supplied in replay data or the in-memory parent PID table built from previous process-start events. Process-stop telemetry removes stale entries. This demonstrates stateful detection in plain C without requiring a database.

## Rule implementation

Rules live in `src/rule_engine.c` and consume only normalized `TgEvent` fields. ETW/TDH types are deliberately kept out of this layer.

`tg_rule_engine_evaluate()` writes findings into a caller-provided bounded array, which keeps ownership simple and avoids hidden allocations on every event.

A new rule should:

1. operate on normalized fields rather than ETW internals;
2. have a stable rule ID;
3. include severity, title and a plain-language rationale;
4. avoid claiming compromise from a single weak indicator;
5. include positive regression coverage and, where useful, a benign/negative control;
6. preserve the read-only defensive boundary.

## Current regression coverage

The C11 test executable covers every built-in rule (`TG1001`–`TG1006`, `TG2001`), a benign Notepad control, JSON event round-trip behavior, parent correlation and process-stop cleanup.
