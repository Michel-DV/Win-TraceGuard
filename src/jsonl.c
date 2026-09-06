#include "traceguard/jsonl.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int tg_append_raw(char* output, size_t capacity, size_t* used, const char* text) {
    size_t length;
    if (output == NULL || used == NULL || text == NULL || *used >= capacity) return 0;
    length = strlen(text);
    if (length >= capacity - *used) return 0;
    memcpy(output + *used, text, length);
    *used += length;
    output[*used] = '\0';
    return 1;
}

static int tg_append_char(char* output, size_t capacity, size_t* used, char value) {
    if (output == NULL || used == NULL || *used + 1 >= capacity) return 0;
    output[(*used)++] = value;
    output[*used] = '\0';
    return 1;
}

static int tg_append_escaped(char* output, size_t capacity, size_t* used, const char* value) {
    const unsigned char* cursor = (const unsigned char*)(value != NULL ? value : "");
    while (*cursor != 0) {
        const char* escape = NULL;
        char unicode_escape[7];
        switch (*cursor) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default: break;
        }

        if (escape != NULL) {
            if (!tg_append_raw(output, capacity, used, escape)) return 0;
        } else if (*cursor < 0x20) {
            int written = snprintf(unicode_escape, sizeof(unicode_escape), "\\u%04x", (unsigned int)*cursor);
            if (written != 6 || !tg_append_raw(output, capacity, used, unicode_escape)) return 0;
        } else {
            if (!tg_append_char(output, capacity, used, (char)*cursor)) return 0;
        }
        ++cursor;
    }
    return 1;
}

static int tg_append_json_string_field(
    char* output,
    size_t capacity,
    size_t* used,
    const char* prefix,
    const char* value) {
    return tg_append_raw(output, capacity, used, prefix) &&
           tg_append_escaped(output, capacity, used, value) &&
           tg_append_char(output, capacity, used, '"');
}

static int tg_append_uint_field(
    char* output,
    size_t capacity,
    size_t* used,
    const char* prefix,
    unsigned long value) {
    char number[32];
    int written = snprintf(number, sizeof(number), "%lu", value);
    if (written <= 0 || (size_t)written >= sizeof(number)) return 0;
    return tg_append_raw(output, capacity, used, prefix) && tg_append_raw(output, capacity, used, number);
}

int tg_event_to_json(const TgEvent* event, char* output, size_t capacity) {
    size_t used = 0;
    if (event == NULL || output == NULL || capacity == 0) return 0;
    output[0] = '\0';

    if (!tg_append_raw(output, capacity, &used, "{\"type\":\"event\"")) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"timestamp_utc\":\"", event->timestamp_utc)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"kind\":\"", tg_event_kind_string(event->kind))) return 0;
    if (!tg_append_uint_field(output, capacity, &used, ",\"pid\":", event->pid)) return 0;
    if (!tg_append_uint_field(output, capacity, &used, ",\"ppid\":", event->ppid)) return 0;
    if (!tg_append_uint_field(output, capacity, &used, ",\"event_id\":", event->event_id)) return 0;
    if (!tg_append_uint_field(output, capacity, &used, ",\"opcode\":", event->opcode)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"provider\":\"", event->provider)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"image\":\"", event->image)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"parent_image\":\"", event->parent_image)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"command_line\":\"", event->command_line)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"loaded_image\":\"", event->loaded_image)) return 0;
    return tg_append_char(output, capacity, &used, '}');
}

int tg_finding_to_json(const TgFinding* finding, char* output, size_t capacity) {
    size_t used = 0;
    if (finding == NULL || output == NULL || capacity == 0) return 0;
    output[0] = '\0';

    if (!tg_append_raw(output, capacity, &used, "{\"type\":\"finding\"")) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"timestamp_utc\":\"", finding->timestamp_utc)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"rule_id\":\"", finding->rule_id)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"severity\":\"", tg_severity_string(finding->severity))) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"title\":\"", finding->title)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"rationale\":\"", finding->rationale)) return 0;
    if (!tg_append_uint_field(output, capacity, &used, ",\"pid\":", finding->pid)) return 0;
    if (!tg_append_json_string_field(output, capacity, &used, ",\"image\":\"", finding->image)) return 0;
    return tg_append_char(output, capacity, &used, '}');
}

static const char* tg_find_value(const char* line, const char* key) {
    char needle[96];
    const char* position;
    const char* colon;
    int written;

    if (line == NULL || key == NULL) return NULL;
    written = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (written <= 0 || (size_t)written >= sizeof(needle)) return NULL;
    position = strstr(line, needle);
    if (position == NULL) return NULL;
    colon = strchr(position + written, ':');
    if (colon == NULL) return NULL;
    ++colon;
    while (*colon != '\0' && isspace((unsigned char)*colon)) ++colon;
    return colon;
}

static int tg_extract_string(const char* line, const char* key, char* output, size_t capacity) {
    const char* cursor = tg_find_value(line, key);
    size_t used = 0;

    if (output == NULL || capacity == 0) return 0;
    output[0] = '\0';
    if (cursor == NULL || *cursor != '"') return 0;
    ++cursor;

    while (*cursor != '\0') {
        char value = *cursor++;
        if (value == '"') {
            output[used] = '\0';
            return 1;
        }
        if (value == '\\') {
            char escaped = *cursor++;
            if (escaped == '\0') return 0;
            switch (escaped) {
                case '"': value = '"'; break;
                case '\\': value = '\\'; break;
                case '/': value = '/'; break;
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                default: return 0;
            }
        }
        if (used + 1 >= capacity) return 0;
        output[used++] = value;
    }
    return 0;
}

static int tg_extract_uint(const char* line, const char* key, uint32_t* output) {
    const char* cursor = tg_find_value(line, key);
    char* end = NULL;
    unsigned long value;

    if (cursor == NULL || output == NULL || !isdigit((unsigned char)*cursor)) return 0;
    errno = 0;
    value = strtoul(cursor, &end, 10);
    if (errno != 0 || end == cursor || value > 0xffffffffUL) return 0;
    *output = (uint32_t)value;
    return 1;
}

static TgEventKind tg_parse_kind(const char* kind) {
    if (strcmp(kind, "process_start") == 0) return TG_EVENT_PROCESS_START;
    if (strcmp(kind, "process_stop") == 0) return TG_EVENT_PROCESS_STOP;
    if (strcmp(kind, "image_load") == 0) return TG_EVENT_IMAGE_LOAD;
    return TG_EVENT_OTHER;
}

int tg_parse_event_json_line(const char* line, TgEvent* event) {
    char type[32];
    char kind[32];
    uint32_t value = 0;

    if (line == NULL || event == NULL) return 0;
    tg_event_init(event);
    if (!tg_extract_string(line, "type", type, sizeof(type)) || strcmp(type, "event") != 0) return 0;
    if (!tg_extract_string(line, "kind", kind, sizeof(kind))) return 0;

    event->kind = tg_parse_kind(kind);
    (void)tg_extract_string(line, "timestamp_utc", event->timestamp_utc, sizeof(event->timestamp_utc));
    if (tg_extract_uint(line, "pid", &value)) event->pid = value;
    if (tg_extract_uint(line, "ppid", &value)) event->ppid = value;
    if (tg_extract_uint(line, "event_id", &value)) event->event_id = (uint16_t)(value & 0xffffU);
    if (tg_extract_uint(line, "opcode", &value)) event->opcode = (uint8_t)(value & 0xffU);
    (void)tg_extract_string(line, "provider", event->provider, sizeof(event->provider));
    (void)tg_extract_string(line, "image", event->image, sizeof(event->image));
    (void)tg_extract_string(line, "parent_image", event->parent_image, sizeof(event->parent_image));
    (void)tg_extract_string(line, "command_line", event->command_line, sizeof(event->command_line));
    (void)tg_extract_string(line, "loaded_image", event->loaded_image, sizeof(event->loaded_image));
    return 1;
}

int tg_jsonl_writer_open(TgJsonlWriter* writer, const char* path) {
    if (writer == NULL || path == NULL) return 0;
    writer->file = NULL;
    return fopen_s(&writer->file, path, "wb") == 0 && writer->file != NULL;
}

void tg_jsonl_writer_close(TgJsonlWriter* writer) {
    if (writer == NULL || writer->file == NULL) return;
    fclose(writer->file);
    writer->file = NULL;
}

int tg_jsonl_write_event(TgJsonlWriter* writer, const TgEvent* event) {
    char line[TG_JSON_LINE_CAP];
    if (writer == NULL || writer->file == NULL || !tg_event_to_json(event, line, sizeof(line))) return 0;
    return fprintf(writer->file, "%s\n", line) >= 0 && fflush(writer->file) == 0;
}

int tg_jsonl_write_finding(TgJsonlWriter* writer, const TgFinding* finding) {
    char line[TG_JSON_LINE_CAP];
    if (writer == NULL || writer->file == NULL || !tg_finding_to_json(finding, line, sizeof(line))) return 0;
    return fprintf(writer->file, "%s\n", line) >= 0 && fflush(writer->file) == 0;
}
