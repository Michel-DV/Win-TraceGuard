# Security policy

## Supported version

The current supported line is **1.x**.

## Reporting a vulnerability

Please do not publish a working exploit for a bug in TraceGuard before giving the maintainer an opportunity to investigate it. Report issues privately through GitHub's security-reporting mechanism when available.

Useful reports include:

- malformed replay input that causes memory corruption or an uncontrolled allocation;
- ETW payload handling that can crash the sensor;
- path or JSON escaping bugs that corrupt recorded telemetry;
- unsafe handling of Windows handles or trace-session cleanup.

## Project boundary

TraceGuard is intentionally read-only. Requests to add credential theft, remote process injection, persistence, exploitation, security-control bypass or stealth/evasion are outside the project's scope.
