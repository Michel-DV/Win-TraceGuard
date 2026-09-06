#pragma once

#include "traceguard/event.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TG_MAX_FINDINGS_PER_EVENT 8
#define TG_DEFAULT_PROCESS_CAPACITY 1024

typedef struct TgProcessEntry {
    uint32_t pid;
    int used;
    char image[TG_PATH_CAP];
} TgProcessEntry;

typedef struct TgRuleEngine {
    TgProcessEntry* entries;
    size_t capacity;
} TgRuleEngine;

int tg_rule_engine_init(TgRuleEngine* engine);
void tg_rule_engine_reset(TgRuleEngine* engine);
void tg_rule_engine_dispose(TgRuleEngine* engine);
size_t tg_rule_engine_evaluate(
    TgRuleEngine* engine,
    const TgEvent* event,
    TgFinding* findings,
    size_t findings_capacity);

#ifdef __cplusplus
}
#endif
