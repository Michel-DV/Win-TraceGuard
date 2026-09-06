#include "traceguard/event.h"

#include <ctype.h>
#include <string.h>

void tg_event_init(TgEvent* event) {
    if (event == NULL) return;
    memset(event, 0, sizeof(*event));
    event->kind = TG_EVENT_OTHER;
}

void tg_finding_init(TgFinding* finding) {
    if (finding == NULL) return;
    memset(finding, 0, sizeof(*finding));
    finding->severity = TG_SEVERITY_INFO;
}

const char* tg_event_kind_string(TgEventKind kind) {
    switch (kind) {
        case TG_EVENT_PROCESS_START: return "process_start";
        case TG_EVENT_PROCESS_STOP: return "process_stop";
        case TG_EVENT_IMAGE_LOAD: return "image_load";
        default: return "other";
    }
}

const char* tg_severity_string(TgSeverity severity) {
    switch (severity) {
        case TG_SEVERITY_LOW: return "low";
        case TG_SEVERITY_MEDIUM: return "medium";
        case TG_SEVERITY_HIGH: return "high";
        default: return "info";
    }
}

void tg_copy_string(char* destination, size_t capacity, const char* source) {
    size_t length;
    if (destination == NULL || capacity == 0) return;
    destination[0] = '\0';
    if (source == NULL) return;
    length = strlen(source);
    if (length >= capacity) length = capacity - 1;
    if (length != 0) memcpy(destination, source, length);
    destination[length] = '\0';
}

void tg_ascii_lower_copy(const char* source, char* destination, size_t capacity) {
    size_t i = 0;
    if (destination == NULL || capacity == 0) return;
    destination[0] = '\0';
    if (source == NULL) return;

    while (source[i] != '\0' && i + 1 < capacity) {
        destination[i] = (char)tolower((unsigned char)source[i]);
        ++i;
    }
    destination[i] = '\0';
}

void tg_basename_lower(const char* path, char* destination, size_t capacity) {
    const char* base;
    const char* slash;
    const char* backslash;

    if (destination == NULL || capacity == 0) return;
    destination[0] = '\0';
    if (path == NULL) return;

    base = path;
    slash = strrchr(path, '/');
    backslash = strrchr(path, '\\');
    if (slash != NULL && slash + 1 > base) base = slash + 1;
    if (backslash != NULL && backslash + 1 > base) base = backslash + 1;
    tg_ascii_lower_copy(base, destination, capacity);
}
