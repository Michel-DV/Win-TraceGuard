# Threat model and safety boundary

Win-TraceGuard is a read-only telemetry and detection research sensor.

## In scope

- starting a realtime ETW session;
- subscribing to the `Microsoft-Windows-Kernel-Process` provider;
- normalizing process and image-load metadata;
- maintaining transient process ancestry state;
- applying local detection heuristics;
- recording normalized telemetry to JSONL;
- replaying normalized telemetry for rule testing.

## Explicitly out of scope

- process injection or remote-memory modification;
- credential access or token theft;
- persistence installation;
- command execution on remote systems;
- stealth/evasion features;
- disabling security products;
- exploitation;
- automatic process termination or quarantine;
- uploading telemetry to external services.

## Privilege model

ETW session creation may require an elevated console or membership in a group allowed to create or consume the relevant realtime trace session, depending on Windows policy. TraceGuard reports the Windows error and exits; it does not attempt to bypass access controls.

## Data sensitivity

Command lines can contain file paths, usernames, document names or secrets passed by poorly designed applications. JSONL output should therefore be treated as endpoint telemetry and protected accordingly.

## Failure behavior

The sensor fails open from the endpoint's perspective: if TraceGuard exits or cannot decode a property, it does not interfere with the observed process. Detection output is advisory only.
