#include "traceguard/etw_session.h"
#include "traceguard/jsonl.h"
#include "traceguard/rule_engine.h"

#include <Windows.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TG_VERSION "1.0.1"

typedef struct CaptureContext {
    TgRuleEngine engine;
    TgJsonlWriter writer;
    int writer_enabled;
    int quiet;
    size_t event_count;
    size_t finding_count;
} CaptureContext;

typedef struct StopThreadContext {
    TgEtwSession* session;
    HANDLE cancel_event;
    DWORD timeout_ms;
} StopThreadContext;

static void tg_print_banner(void) {
    printf("Win-TraceGuard %s | Windows ETW telemetry & detection sensor | C11\n", TG_VERSION);
}

static void tg_print_usage(void) {
    tg_print_banner();
    printf(
        "\nUsage:\n"
        "  traceguard capture [--seconds N] [--jsonl path] [--quiet]\n"
        "  traceguard replay <events.jsonl> [--json]\n"
        "  traceguard providers\n"
        "  traceguard --version\n\n"
        "Capture uses the Microsoft-Windows-Kernel-Process ETW provider.\n"
        "Depending on local ETW policy, an elevated console may be required.\n");
}

static const char* tg_severity_tag(TgSeverity severity) {
    switch (severity) {
        case TG_SEVERITY_HIGH: return "HIGH";
        case TG_SEVERITY_MEDIUM: return "MED ";
        case TG_SEVERITY_LOW: return "LOW ";
        default: return "INFO";
    }
}

static void tg_print_event(const TgEvent* event) {
    if (event == NULL) return;
    printf("[EVT ] %s %s pid=%lu", event->timestamp_utc, tg_event_kind_string(event->kind), (unsigned long)event->pid);
    if (event->ppid != 0) printf(" ppid=%lu", (unsigned long)event->ppid);
    if (event->image[0] != '\0') printf(" image=\"%s\"", event->image);
    if (event->loaded_image[0] != '\0') printf(" loaded=\"%s\"", event->loaded_image);
    putchar('\n');
}

static void tg_print_finding(const TgFinding* finding) {
    if (finding == NULL) return;
    printf(
        "[%s] %s | %s | pid=%lu",
        tg_severity_tag(finding->severity),
        finding->rule_id,
        finding->title,
        (unsigned long)finding->pid);
    if (finding->image[0] != '\0') printf(" | %s", finding->image);
    printf("\n       %s\n", finding->rationale);
}

static void tg_capture_event_callback(const TgEvent* event, void* user_context) {
    CaptureContext* context = (CaptureContext*)user_context;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    size_t i;

    if (event == NULL || context == NULL) return;
    ++context->event_count;
    if (!context->quiet) tg_print_event(event);
    if (context->writer_enabled) (void)tg_jsonl_write_event(&context->writer, event);

    count = tg_rule_engine_evaluate(
        &context->engine,
        event,
        findings,
        sizeof(findings) / sizeof(findings[0]));
    for (i = 0; i < count; ++i) {
        ++context->finding_count;
        tg_print_finding(&findings[i]);
        if (context->writer_enabled) (void)tg_jsonl_write_finding(&context->writer, &findings[i]);
    }
}

static DWORD WINAPI tg_stop_thread(LPVOID parameter) {
    StopThreadContext* context = (StopThreadContext*)parameter;
    if (context == NULL || context->session == NULL || context->cancel_event == NULL) return 0;
    if (WaitForSingleObject(context->cancel_event, context->timeout_ms) == WAIT_TIMEOUT) {
        tg_etw_session_stop(context->session);
    }
    return 0;
}

static int tg_parse_seconds(const char* text, unsigned int* seconds) {
    char* end = NULL;
    unsigned long value;
    if (text == NULL || seconds == NULL || text[0] == '\0') return 0;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0 || value > 3600UL) return 0;
    *seconds = (unsigned int)value;
    return 1;
}

static int tg_capture(int argc, char** argv) {
    unsigned int seconds = 15;
    const char* jsonl_path = NULL;
    CaptureContext context;
    TgEtwSession session;
    StopThreadContext stop_context;
    HANDLE stop_event = NULL;
    HANDLE thread = NULL;
    char error[1024];
    int ok;
    int i;

    memset(&context, 0, sizeof(context));
    memset(&session, 0, sizeof(session));
    memset(&stop_context, 0, sizeof(stop_context));
    error[0] = '\0';

    for (i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            if (!tg_parse_seconds(argv[++i], &seconds)) {
                fprintf(stderr, "--seconds must be an integer between 1 and 3600.\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--jsonl") == 0 && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (strcmp(argv[i], "--quiet") == 0) {
            context.quiet = 1;
        } else {
            fprintf(stderr, "Unknown capture option: %s\n", argv[i]);
            return 2;
        }
    }

    if (!tg_rule_engine_init(&context.engine)) {
        fprintf(stderr, "Unable to initialize the detection engine.\n");
        return 1;
    }

    if (jsonl_path != NULL) {
        if (!tg_jsonl_writer_open(&context.writer, jsonl_path)) {
            fprintf(stderr, "Unable to open JSONL output: %s\n", jsonl_path);
            tg_rule_engine_dispose(&context.engine);
            return 1;
        }
        context.writer_enabled = 1;
    }

    tg_etw_session_init(&session, tg_capture_event_callback, &context);
    if (!tg_etw_session_start(&session, error, sizeof(error))) {
        fprintf(stderr, "TraceGuard capture failed: %s\n", error);
        tg_etw_session_dispose(&session);
        if (context.writer_enabled) tg_jsonl_writer_close(&context.writer);
        tg_rule_engine_dispose(&context.engine);
        return 1;
    }

    tg_print_banner();
    printf("[+] Session: WinTraceGuard realtime session\n");
    printf("[+] Provider: Microsoft-Windows-Kernel-Process\n");
    printf("[+] Duration: %us\n", seconds);
    if (jsonl_path != NULL) printf("[+] JSONL: %s\n", jsonl_path);

    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (stop_event == NULL) {
        fprintf(stderr, "Unable to create the capture timer event.\n");
        tg_etw_session_stop(&session);
        tg_etw_session_dispose(&session);
        if (context.writer_enabled) tg_jsonl_writer_close(&context.writer);
        tg_rule_engine_dispose(&context.engine);
        return 1;
    }

    stop_context.session = &session;
    stop_context.cancel_event = stop_event;
    stop_context.timeout_ms = seconds * 1000U;
    thread = CreateThread(NULL, 0, tg_stop_thread, &stop_context, 0, NULL);
    if (thread == NULL) {
        fprintf(stderr, "Unable to create the capture timer thread.\n");
        CloseHandle(stop_event);
        tg_etw_session_stop(&session);
        tg_etw_session_dispose(&session);
        if (context.writer_enabled) tg_jsonl_writer_close(&context.writer);
        tg_rule_engine_dispose(&context.engine);
        return 1;
    }

    ok = tg_etw_session_run(&session, error, sizeof(error));
    SetEvent(stop_event);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(stop_event);
    tg_etw_session_stop(&session);

    printf("\nCapture summary: %zu events, %zu findings.\n", context.event_count, context.finding_count);
    if (!ok) fprintf(stderr, "%s\n", error);

    tg_etw_session_dispose(&session);
    if (context.writer_enabled) tg_jsonl_writer_close(&context.writer);
    tg_rule_engine_dispose(&context.engine);
    return ok ? 0 : 1;
}

static int tg_replay(int argc, char** argv) {
    const char* path;
    int json = 0;
    FILE* input = NULL;
    TgRuleEngine engine;
    char line[TG_JSON_LINE_CAP];
    size_t events = 0;
    size_t findings_count = 0;
    size_t rejected = 0;
    int i;

    if (argc < 3) {
        fprintf(stderr, "replay requires a JSONL path.\n");
        return 2;
    }
    path = argv[2];

    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--json") == 0) json = 1;
        else {
            fprintf(stderr, "Unknown replay option: %s\n", argv[i]);
            return 2;
        }
    }

    if (fopen_s(&input, path, "rb") != 0 || input == NULL) {
        fprintf(stderr, "Unable to open replay file: %s\n", path);
        return 1;
    }
    if (!tg_rule_engine_init(&engine)) {
        fclose(input);
        fprintf(stderr, "Unable to initialize the detection engine.\n");
        return 1;
    }

    while (fgets(line, sizeof(line), input) != NULL) {
        TgEvent event;
        TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
        size_t match_count;
        size_t match_index;
        size_t length = strlen(line);

        while (length > 0 && (line[length - 1] == '\r' || line[length - 1] == '\n')) line[--length] = '\0';
        if (length == 0) continue;
        if (!tg_parse_event_json_line(line, &event)) {
            ++rejected;
            continue;
        }

        ++events;
        match_count = tg_rule_engine_evaluate(
            &engine,
            &event,
            findings,
            sizeof(findings) / sizeof(findings[0]));
        for (match_index = 0; match_index < match_count; ++match_index) {
            ++findings_count;
            if (json) {
                char output[TG_JSON_LINE_CAP];
                if (tg_finding_to_json(&findings[match_index], output, sizeof(output))) puts(output);
            } else {
                tg_print_finding(&findings[match_index]);
            }
        }
    }

    if (!json) {
        printf("Replay summary: %zu events, %zu findings", events, findings_count);
        if (rejected != 0) printf(", %zu non-event/invalid lines ignored", rejected);
        printf(".\n");
    }

    tg_rule_engine_dispose(&engine);
    fclose(input);
    return 0;
}

int main(int argc, char** argv) {
    const char* command;
    if (argc < 2) {
        tg_print_usage();
        return 0;
    }

    command = argv[1];
    if (strcmp(command, "--version") == 0 || strcmp(command, "-V") == 0) {
        printf("Win-TraceGuard %s (C11)\n", TG_VERSION);
        return 0;
    }
    if (strcmp(command, "capture") == 0) return tg_capture(argc, argv);
    if (strcmp(command, "replay") == 0) return tg_replay(argc, argv);
    if (strcmp(command, "providers") == 0) {
        printf("Configured ETW providers:\n");
        printf("  Microsoft-Windows-Kernel-Process  process/image telemetry\n");
        return 0;
    }
    if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        tg_print_usage();
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n\n", command);
    tg_print_usage();
    return 2;
}
