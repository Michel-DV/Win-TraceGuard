#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TG_TIMESTAMP_CAP 40
#define TG_PROVIDER_CAP 96
#define TG_PATH_CAP 1024
#define TG_COMMAND_CAP 4096
#define TG_RULE_ID_CAP 16
#define TG_TITLE_CAP 192
#define TG_RATIONALE_CAP 768

typedef enum TgEventKind {
    TG_EVENT_PROCESS_START = 0,
    TG_EVENT_PROCESS_STOP,
    TG_EVENT_IMAGE_LOAD,
    TG_EVENT_OTHER
} TgEventKind;

typedef enum TgSeverity {
    TG_SEVERITY_INFO = 0,
    TG_SEVERITY_LOW,
    TG_SEVERITY_MEDIUM,
    TG_SEVERITY_HIGH
} TgSeverity;

typedef struct TgEvent {
    char timestamp_utc[TG_TIMESTAMP_CAP];
    TgEventKind kind;
    uint32_t pid;
    uint32_t ppid;
    uint16_t event_id;
    uint8_t opcode;
    char provider[TG_PROVIDER_CAP];
    char image[TG_PATH_CAP];
    char parent_image[TG_PATH_CAP];
    char command_line[TG_COMMAND_CAP];
    char loaded_image[TG_PATH_CAP];
} TgEvent;

typedef struct TgFinding {
    char timestamp_utc[TG_TIMESTAMP_CAP];
    char rule_id[TG_RULE_ID_CAP];
    TgSeverity severity;
    char title[TG_TITLE_CAP];
    char rationale[TG_RATIONALE_CAP];
    uint32_t pid;
    char image[TG_PATH_CAP];
} TgFinding;

void tg_event_init(TgEvent* event);
void tg_finding_init(TgFinding* finding);
const char* tg_event_kind_string(TgEventKind kind);
const char* tg_severity_string(TgSeverity severity);
void tg_copy_string(char* destination, size_t capacity, const char* source);
void tg_ascii_lower_copy(const char* source, char* destination, size_t capacity);
void tg_basename_lower(const char* path, char* destination, size_t capacity);

#ifdef __cplusplus
}
#endif
