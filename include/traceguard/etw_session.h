#pragma once

#include "traceguard/event.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <evntrace.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*TgEventCallback)(const TgEvent* event, void* user_context);

typedef struct TgEtwProcessEntry {
    uint32_t pid;
    int used;
    char image[TG_PATH_CAP];
} TgEtwProcessEntry;

typedef struct TgEtwSession {
    TgEventCallback callback;
    void* user_context;
    TRACEHANDLE session_handle;
    TRACEHANDLE consumer_handle;
    wchar_t session_name[128];
    GUID provider_guid;
    volatile LONG stopping;
    TgEtwProcessEntry* process_entries;
    size_t process_capacity;
} TgEtwSession;

void tg_etw_session_init(TgEtwSession* session, TgEventCallback callback, void* user_context);
void tg_etw_session_dispose(TgEtwSession* session);
int tg_etw_session_start(TgEtwSession* session, char* error, size_t error_capacity);
int tg_etw_session_run(TgEtwSession* session, char* error, size_t error_capacity);
void tg_etw_session_stop(TgEtwSession* session);
const wchar_t* tg_etw_session_name(const TgEtwSession* session);

#ifdef __cplusplus
}
#endif
