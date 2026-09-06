#include "traceguard/rule_engine.h"

#include <stdlib.h>
#include <string.h>

static int tg_contains_any(const char* value, const char* const* needles, size_t count) {
    size_t i;
    if (value == NULL) return 0;
    for (i = 0; i < count; ++i) {
        if (needles[i] != NULL && strstr(value, needles[i]) != NULL) return 1;
    }
    return 0;
}

static int tg_is_user_writable_path(const char* path) {
    static const char* const needles[] = {
        "\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\"
    };
    char lower[TG_COMMAND_CAP];
    tg_ascii_lower_copy(path, lower, sizeof(lower));
    return tg_contains_any(lower, needles, sizeof(needles) / sizeof(needles[0]));
}

static int tg_is_script_host(const char* image) {
    char base[128];
    tg_basename_lower(image, base, sizeof(base));
    return strcmp(base, "powershell.exe") == 0 ||
           strcmp(base, "pwsh.exe") == 0 ||
           strcmp(base, "cmd.exe") == 0 ||
           strcmp(base, "wscript.exe") == 0 ||
           strcmp(base, "cscript.exe") == 0 ||
           strcmp(base, "mshta.exe") == 0;
}

static int tg_is_office_parent(const char* image) {
    char base[128];
    tg_basename_lower(image, base, sizeof(base));
    return strcmp(base, "winword.exe") == 0 ||
           strcmp(base, "excel.exe") == 0 ||
           strcmp(base, "powerpnt.exe") == 0 ||
           strcmp(base, "outlook.exe") == 0 ||
           strcmp(base, "onenote.exe") == 0;
}

static const char* tg_process_lookup(const TgRuleEngine* engine, uint32_t pid) {
    size_t i;
    if (engine == NULL || engine->entries == NULL || pid == 0) return NULL;
    for (i = 0; i < engine->capacity; ++i) {
        if (engine->entries[i].used && engine->entries[i].pid == pid) {
            return engine->entries[i].image;
        }
    }
    return NULL;
}

static void tg_process_store(TgRuleEngine* engine, uint32_t pid, const char* image) {
    size_t i;
    size_t free_index = (size_t)-1;
    if (engine == NULL || engine->entries == NULL || pid == 0 || image == NULL || image[0] == '\0') return;

    for (i = 0; i < engine->capacity; ++i) {
        if (engine->entries[i].used && engine->entries[i].pid == pid) {
            tg_copy_string(engine->entries[i].image, sizeof(engine->entries[i].image), image);
            return;
        }
        if (!engine->entries[i].used && free_index == (size_t)-1) free_index = i;
    }

    if (free_index != (size_t)-1) {
        engine->entries[free_index].used = 1;
        engine->entries[free_index].pid = pid;
        tg_copy_string(engine->entries[free_index].image, sizeof(engine->entries[free_index].image), image);
    }
}

static void tg_process_remove(TgRuleEngine* engine, uint32_t pid) {
    size_t i;
    if (engine == NULL || engine->entries == NULL || pid == 0) return;
    for (i = 0; i < engine->capacity; ++i) {
        if (engine->entries[i].used && engine->entries[i].pid == pid) {
            memset(&engine->entries[i], 0, sizeof(engine->entries[i]));
            return;
        }
    }
}

static void tg_make_finding(
    TgFinding* finding,
    const TgEvent* event,
    const char* rule_id,
    TgSeverity severity,
    const char* title,
    const char* rationale) {
    tg_finding_init(finding);
    tg_copy_string(finding->timestamp_utc, sizeof(finding->timestamp_utc), event->timestamp_utc);
    tg_copy_string(finding->rule_id, sizeof(finding->rule_id), rule_id);
    finding->severity = severity;
    tg_copy_string(finding->title, sizeof(finding->title), title);
    tg_copy_string(finding->rationale, sizeof(finding->rationale), rationale);
    finding->pid = event->pid;
    tg_copy_string(
        finding->image,
        sizeof(finding->image),
        event->image[0] != '\0' ? event->image : event->loaded_image);
}

static void tg_append_finding(
    TgFinding* findings,
    size_t capacity,
    size_t* count,
    const TgEvent* event,
    const char* rule_id,
    TgSeverity severity,
    const char* title,
    const char* rationale) {
    if (*count >= capacity) return;
    tg_make_finding(&findings[*count], event, rule_id, severity, title, rationale);
    ++(*count);
}

int tg_rule_engine_init(TgRuleEngine* engine) {
    if (engine == NULL) return 0;
    memset(engine, 0, sizeof(*engine));
    engine->entries = (TgProcessEntry*)calloc(TG_DEFAULT_PROCESS_CAPACITY, sizeof(TgProcessEntry));
    if (engine->entries == NULL) return 0;
    engine->capacity = TG_DEFAULT_PROCESS_CAPACITY;
    return 1;
}

void tg_rule_engine_reset(TgRuleEngine* engine) {
    if (engine == NULL || engine->entries == NULL) return;
    memset(engine->entries, 0, engine->capacity * sizeof(TgProcessEntry));
}

void tg_rule_engine_dispose(TgRuleEngine* engine) {
    if (engine == NULL) return;
    free(engine->entries);
    engine->entries = NULL;
    engine->capacity = 0;
}

size_t tg_rule_engine_evaluate(
    TgRuleEngine* engine,
    const TgEvent* input,
    TgFinding* findings,
    size_t findings_capacity) {
    TgEvent event;
    size_t count = 0;

    if (engine == NULL || input == NULL || findings == NULL || findings_capacity == 0) return 0;
    event = *input;

    if (event.parent_image[0] == '\0' && event.ppid != 0) {
        const char* known_parent = tg_process_lookup(engine, event.ppid);
        if (known_parent != NULL) {
            tg_copy_string(event.parent_image, sizeof(event.parent_image), known_parent);
        }
    }

    if (event.kind == TG_EVENT_PROCESS_START) {
        static const char* const encoded_switches[] = {
            " -enc ", " -enc\"", " -encodedcommand ", " /enc ", " -e "
        };
        static const char* const remote_markers[] = {"http://", "https://"};
        static const char* const rundll_markers[] = {"http://", "https://", "javascript:", "vbscript:"};
        char command_lower[TG_COMMAND_CAP];
        char base[128];

        tg_ascii_lower_copy(event.command_line, command_lower, sizeof(command_lower));
        tg_basename_lower(event.image, base, sizeof(base));

        if (tg_is_user_writable_path(event.image)) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1001", TG_SEVERITY_MEDIUM,
                "Executable started from a user-writable location",
                "Execution from AppData, Temp, Downloads or Users\\Public deserves analyst review because those paths are commonly writable by standard users.");
        }

        if (tg_is_office_parent(event.parent_image) && tg_is_script_host(event.image)) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1002", TG_SEVERITY_HIGH,
                "Office application spawned a command or script interpreter",
                "The parent/child relationship is uncommon in normal document workflows and is frequently useful as an initial-access or macro-abuse hunting signal.");
        }

        if ((strcmp(base, "powershell.exe") == 0 || strcmp(base, "pwsh.exe") == 0) &&
            tg_contains_any(command_lower, encoded_switches, sizeof(encoded_switches) / sizeof(encoded_switches[0]))) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1003", TG_SEVERITY_HIGH,
                "PowerShell command line contains an encoded-command switch",
                "Encoded PowerShell is not inherently malicious, but it reduces command-line transparency and is a strong triage signal when correlated with process ancestry.");
        }

        if (strcmp(base, "mshta.exe") == 0 &&
            tg_contains_any(command_lower, remote_markers, sizeof(remote_markers) / sizeof(remote_markers[0]))) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1004", TG_SEVERITY_HIGH,
                "MSHTA launched with a remote URL",
                "Remote-content execution through mshta.exe is a high-value living-off-the-land detection signal and should be validated against approved administrative activity.");
        }

        if (strcmp(base, "rundll32.exe") == 0 &&
            tg_contains_any(command_lower, rundll_markers, sizeof(rundll_markers) / sizeof(rundll_markers[0]))) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1005", TG_SEVERITY_HIGH,
                "Rundll32 command line contains remote or script-like content",
                "The command line contains content that is unusual for routine DLL invocation and merits immediate review.");
        }

        if ((strcmp(base, "regsvr32.exe") == 0 || strcmp(base, "rundll32.exe") == 0 || strcmp(base, "mshta.exe") == 0) &&
            tg_is_user_writable_path(event.command_line)) {
            tg_append_finding(
                findings, findings_capacity, &count, &event,
                "TG1006", TG_SEVERITY_MEDIUM,
                "Windows utility references content in a user-writable path",
                "A signed Windows utility is referencing AppData, Temp, Downloads or Users\\Public. This is an explainable dual-use heuristic, not a malware verdict.");
        }

        if (event.image[0] != '\0') tg_process_store(engine, event.pid, event.image);
    }

    if (event.kind == TG_EVENT_IMAGE_LOAD && tg_is_user_writable_path(event.loaded_image)) {
        tg_append_finding(
            findings, findings_capacity, &count, &event,
            "TG2001", TG_SEVERITY_MEDIUM,
            "Image loaded from a user-writable location",
            "A DLL or executable image was loaded from a commonly user-writable path. Validate the signer, origin and expected application behavior.");
    }

    if (event.kind == TG_EVENT_PROCESS_STOP) tg_process_remove(engine, event.pid);
    return count;
}
