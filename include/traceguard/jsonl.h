#pragma once

#include "traceguard/event.h"

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TG_JSON_LINE_CAP 16384

typedef struct TgJsonlWriter {
    FILE* file;
} TgJsonlWriter;

int tg_event_to_json(const TgEvent* event, char* output, size_t capacity);
int tg_finding_to_json(const TgFinding* finding, char* output, size_t capacity);
int tg_parse_event_json_line(const char* line, TgEvent* event);

int tg_jsonl_writer_open(TgJsonlWriter* writer, const char* path);
void tg_jsonl_writer_close(TgJsonlWriter* writer);
int tg_jsonl_write_event(TgJsonlWriter* writer, const TgEvent* event);
int tg_jsonl_write_finding(TgJsonlWriter* writer, const TgFinding* finding);

#ifdef __cplusplus
}
#endif
