# Output contract

## Live console

Live capture prints normalized events and findings. Event lines begin with `[EVT ]`; findings use a severity tag.

```text
[EVT ] 2026-09-06T12:00:01.000Z process_start pid=4112 ppid=4100 image="...powershell.exe"
[HIGH] TG1002 | Office application spawned a command or script interpreter | pid=4112 | ...powershell.exe
       The parent/child relationship is uncommon in normal document workflows ...
```

## JSONL

The optional `--jsonl` output is append-free: each capture truncates the target file and writes one complete JSON object per line.

Event example:

```json
{"type":"event","timestamp_utc":"2026-09-06T12:00:01.000Z","kind":"process_start","pid":4112,"ppid":4100,"event_id":1,"opcode":1,"provider":"Microsoft-Windows-Kernel-Process","image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent_image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE","command_line":"powershell.exe -EncodedCommand SQBFAFgA","loaded_image":""}
```

Finding example:

```json
{"type":"finding","timestamp_utc":"2026-09-06T12:00:01.000Z","rule_id":"TG1003","severity":"high","title":"PowerShell command line contains an encoded-command switch","rationale":"...","pid":4112,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
```

## Replay compatibility

The v1 replay parser expects a flat JSON object and uses only the fields defined above. It intentionally does not attempt to be a general-purpose JSON implementation. Unknown fields are ignored; invalid lines and prior `finding` lines are skipped.
