#include "traceguard/etw_session.h"

#include <tdh.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define TG_ETW_PROCESS_CAPACITY 1024U
#define TG_MAX_PROPERTY_BYTES (1024U * 1024U)

static const wchar_t TG_PROVIDER_NAME[] = L"Microsoft-Windows-Kernel-Process";

static void tg_set_error(char* error, size_t capacity, const char* text) {
    if (error == NULL || capacity == 0) return;
    tg_copy_string(error, capacity, text != NULL ? text : "Unknown error");
}

static void tg_windows_error_text(ULONG code, char* output, size_t capacity) {
    LPWSTR buffer = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length;

    if (output == NULL || capacity == 0) return;
    output[0] = '\0';
    length = FormatMessageW(flags, NULL, code, 0, (LPWSTR)&buffer, 0, NULL);
    if (length != 0 && buffer != NULL) {
        while (length > 0 && (buffer[length - 1] == L'\r' || buffer[length - 1] == L'\n' || buffer[length - 1] == L' ')) {
            buffer[--length] = L'\0';
        }
        if (length > 0) {
            int written = WideCharToMultiByte(CP_UTF8, 0, buffer, (int)length, output, (int)(capacity - 1), NULL, NULL);
            if (written > 0) output[written] = '\0';
        }
        LocalFree(buffer);
    }
    if (output[0] == '\0') {
        (void)snprintf(output, capacity, "Windows error %lu", (unsigned long)code);
        output[capacity - 1] = '\0';
    }
}

static void tg_error_with_code(
    char* error,
    size_t error_capacity,
    const char* prefix,
    ULONG code,
    const char* suffix) {
    char detail[512];
    if (error == NULL || error_capacity == 0) return;
    tg_windows_error_text(code, detail, sizeof(detail));
    (void)snprintf(
        error,
        error_capacity,
        "%s%s%s",
        prefix != NULL ? prefix : "",
        detail,
        suffix != NULL ? suffix : "");
    error[error_capacity - 1] = '\0';
}

static int tg_resolve_provider_guid(const wchar_t* provider_name, GUID* guid, char* error, size_t error_capacity) {
    ULONG size = 0;
    ULONG status;
    PROVIDER_ENUMERATION_INFO* info;
    ULONG i;

    status = TdhEnumerateProviders(NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        tg_error_with_code(error, error_capacity, "TdhEnumerateProviders(size) failed: ", status, "");
        return 0;
    }

    info = (PROVIDER_ENUMERATION_INFO*)calloc(1, size);
    if (info == NULL) {
        tg_set_error(error, error_capacity, "Unable to allocate the ETW provider enumeration buffer.");
        return 0;
    }

    status = TdhEnumerateProviders(info, &size);
    if (status != ERROR_SUCCESS) {
        free(info);
        tg_error_with_code(error, error_capacity, "TdhEnumerateProviders failed: ", status, "");
        return 0;
    }

    for (i = 0; i < info->NumberOfProviders; ++i) {
        const TRACE_PROVIDER_INFO* entry = &info->TraceProviderInfoArray[i];
        const wchar_t* name;
        if (entry->ProviderNameOffset == 0 || entry->ProviderNameOffset >= size) continue;
        name = (const wchar_t*)((const BYTE*)info + entry->ProviderNameOffset);
        if (_wcsicmp(name, provider_name) == 0) {
            *guid = entry->ProviderGuid;
            free(info);
            return 1;
        }
    }

    free(info);
    tg_set_error(error, error_capacity, "ETW provider Microsoft-Windows-Kernel-Process was not found on this system.");
    return 0;
}

static BYTE* tg_read_property(EVENT_RECORD* record, const wchar_t* name, ULONG* output_size) {
    PROPERTY_DATA_DESCRIPTOR descriptor;
    ULONG size = 0;
    ULONG status;
    BYTE* buffer;

    if (output_size != NULL) *output_size = 0;
    if (record == NULL || name == NULL) return NULL;

    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    descriptor.ArrayIndex = ULONG_MAX;

    status = TdhGetPropertySize(record, 0, NULL, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size == 0 || size > TG_MAX_PROPERTY_BYTES) return NULL;

    buffer = (BYTE*)malloc(size);
    if (buffer == NULL) return NULL;
    status = TdhGetProperty(record, 0, NULL, 1, &descriptor, size, buffer);
    if (status != ERROR_SUCCESS) {
        free(buffer);
        return NULL;
    }

    if (output_size != NULL) *output_size = size;
    return buffer;
}

static int tg_has_property(EVENT_RECORD* record, const wchar_t* name) {
    ULONG size = 0;
    BYTE* data = tg_read_property(record, name, &size);
    if (data == NULL) return 0;
    free(data);
    return size != 0;
}

static uint32_t tg_read_u32(
    EVENT_RECORD* record,
    const wchar_t* const* names,
    size_t name_count,
    uint32_t fallback) {
    size_t i;
    for (i = 0; i < name_count; ++i) {
        ULONG size = 0;
        BYTE* bytes = tg_read_property(record, names[i], &size);
        if (bytes == NULL) continue;
        if (size == sizeof(uint32_t)) {
            uint32_t value = 0;
            memcpy(&value, bytes, sizeof(value));
            free(bytes);
            return value;
        }
        if (size == sizeof(uint64_t)) {
            uint64_t value = 0;
            memcpy(&value, bytes, sizeof(value));
            free(bytes);
            return (uint32_t)(value & 0xffffffffULL);
        }
        free(bytes);
    }
    return fallback;
}

static int tg_property_looks_wide(const BYTE* bytes, ULONG size) {
    ULONG i;
    ULONG checks = 0;
    ULONG zero_high = 0;
    if (bytes == NULL || size < sizeof(wchar_t) || (size % sizeof(wchar_t)) != 0) return 0;
    for (i = 1; i < size && checks < 16; i += 2, ++checks) {
        if (bytes[i] == 0) ++zero_high;
    }
    return checks != 0 && zero_high * 2 >= checks;
}

static int tg_wide_to_utf8(const wchar_t* value, size_t length, char* output, size_t capacity) {
    int written;
    if (output == NULL || capacity == 0) return 0;
    output[0] = '\0';
    if (value == NULL || length == 0) return 1;
    if (length > (size_t)INT_MAX || capacity - 1 > (size_t)INT_MAX) return 0;

    written = WideCharToMultiByte(
        CP_UTF8,
        0,
        value,
        (int)length,
        output,
        (int)(capacity - 1),
        NULL,
        NULL);
    if (written <= 0) return 0;
    output[written] = '\0';
    return 1;
}

static int tg_read_text(
    EVENT_RECORD* record,
    const wchar_t* const* names,
    size_t name_count,
    char* output,
    size_t capacity) {
    size_t i;
    if (output == NULL || capacity == 0) return 0;
    output[0] = '\0';

    for (i = 0; i < name_count; ++i) {
        ULONG size = 0;
        BYTE* bytes = tg_read_property(record, names[i], &size);
        if (bytes == NULL) continue;

        if (tg_property_looks_wide(bytes, size)) {
            const wchar_t* text = (const wchar_t*)bytes;
            size_t count = size / sizeof(wchar_t);
            size_t length = 0;
            while (length < count && text[length] != L'\0') ++length;
            if (length != 0 && tg_wide_to_utf8(text, length, output, capacity)) {
                free(bytes);
                return 1;
            }
        } else {
            size_t length = 0;
            while (length < size && bytes[length] != 0) ++length;
            if (length != 0 && length <= (size_t)INT_MAX) {
                int wide_length = MultiByteToWideChar(CP_ACP, 0, (const char*)bytes, (int)length, NULL, 0);
                if (wide_length > 0) {
                    wchar_t* wide = (wchar_t*)calloc((size_t)wide_length + 1, sizeof(wchar_t));
                    if (wide != NULL) {
                        if (MultiByteToWideChar(CP_ACP, 0, (const char*)bytes, (int)length, wide, wide_length) > 0) {
                            int ok = tg_wide_to_utf8(wide, (size_t)wide_length, output, capacity);
                            free(wide);
                            if (ok) {
                                free(bytes);
                                return 1;
                            }
                        } else {
                            free(wide);
                        }
                    }
                }
            }
        }
        free(bytes);
    }
    return 0;
}

static void tg_format_timestamp(const LARGE_INTEGER* timestamp, char* output, size_t capacity) {
    FILETIME file_time;
    SYSTEMTIME system_time;
    if (output == NULL || capacity == 0) return;
    output[0] = '\0';
    if (timestamp == NULL) return;

    file_time.dwLowDateTime = timestamp->LowPart;
    file_time.dwHighDateTime = (DWORD)timestamp->HighPart;
    memset(&system_time, 0, sizeof(system_time));
    if (!FileTimeToSystemTime(&file_time, &system_time)) return;
    (void)snprintf(
        output,
        capacity,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        system_time.wYear,
        system_time.wMonth,
        system_time.wDay,
        system_time.wHour,
        system_time.wMinute,
        system_time.wSecond,
        system_time.wMilliseconds);
    output[capacity - 1] = '\0';
}

static TgEventKind tg_classify_event(EVENT_RECORD* record, const char* command_line, const char* image) {
    UCHAR opcode = record->EventHeader.EventDescriptor.Opcode;

    if (opcode == EVENT_TRACE_TYPE_END || opcode == 2) return TG_EVENT_PROCESS_STOP;
    if (image != NULL && image[0] != '\0' &&
        (tg_has_property(record, L"ImageBase") || tg_has_property(record, L"ImageSize"))) {
        return TG_EVENT_IMAGE_LOAD;
    }
    if ((command_line != NULL && command_line[0] != '\0') ||
        tg_has_property(record, L"ParentProcessID") ||
        tg_has_property(record, L"ParentId")) {
        return TG_EVENT_PROCESS_START;
    }
    if (opcode == EVENT_TRACE_TYPE_START || opcode == 1) return TG_EVENT_PROCESS_START;
    return TG_EVENT_OTHER;
}

static const char* tg_etw_process_lookup(const TgEtwSession* session, uint32_t pid) {
    size_t i;
    if (session == NULL || session->process_entries == NULL || pid == 0) return NULL;
    for (i = 0; i < session->process_capacity; ++i) {
        if (session->process_entries[i].used && session->process_entries[i].pid == pid) {
            return session->process_entries[i].image;
        }
    }
    return NULL;
}

static void tg_etw_process_store(TgEtwSession* session, uint32_t pid, const char* image) {
    size_t i;
    size_t free_index = (size_t)-1;
    if (session == NULL || session->process_entries == NULL || pid == 0 || image == NULL || image[0] == '\0') return;

    for (i = 0; i < session->process_capacity; ++i) {
        if (session->process_entries[i].used && session->process_entries[i].pid == pid) {
            tg_copy_string(session->process_entries[i].image, sizeof(session->process_entries[i].image), image);
            return;
        }
        if (!session->process_entries[i].used && free_index == (size_t)-1) free_index = i;
    }
    if (free_index != (size_t)-1) {
        session->process_entries[free_index].used = 1;
        session->process_entries[free_index].pid = pid;
        tg_copy_string(session->process_entries[free_index].image, sizeof(session->process_entries[free_index].image), image);
    }
}

static void tg_etw_process_remove(TgEtwSession* session, uint32_t pid) {
    size_t i;
    if (session == NULL || session->process_entries == NULL || pid == 0) return;
    for (i = 0; i < session->process_capacity; ++i) {
        if (session->process_entries[i].used && session->process_entries[i].pid == pid) {
            memset(&session->process_entries[i], 0, sizeof(session->process_entries[i]));
            return;
        }
    }
}

static void tg_etw_on_event(TgEtwSession* session, EVENT_RECORD* record) {
    static const wchar_t* const image_names[] = {L"ImageName", L"ImageFileName", L"FileName"};
    static const wchar_t* const command_names[] = {L"CommandLine"};
    static const wchar_t* const pid_names[] = {L"ProcessID", L"ProcessId"};
    static const wchar_t* const ppid_names[] = {L"ParentProcessID", L"ParentProcessId", L"ParentId"};
    TgEvent event;
    char image[TG_PATH_CAP];
    const char* known;

    if (session == NULL || record == NULL) return;
    tg_event_init(&event);
    image[0] = '\0';

    (void)tg_read_text(record, image_names, sizeof(image_names) / sizeof(image_names[0]), image, sizeof(image));
    (void)tg_read_text(record, command_names, sizeof(command_names) / sizeof(command_names[0]), event.command_line, sizeof(event.command_line));

    tg_format_timestamp(&record->EventHeader.TimeStamp, event.timestamp_utc, sizeof(event.timestamp_utc));
    event.event_id = record->EventHeader.EventDescriptor.Id;
    event.opcode = record->EventHeader.EventDescriptor.Opcode;
    tg_copy_string(event.provider, sizeof(event.provider), "Microsoft-Windows-Kernel-Process");
    event.pid = tg_read_u32(record, pid_names, sizeof(pid_names) / sizeof(pid_names[0]), record->EventHeader.ProcessId);
    event.ppid = tg_read_u32(record, ppid_names, sizeof(ppid_names) / sizeof(ppid_names[0]), 0);
    event.kind = tg_classify_event(record, event.command_line, image);

    if (event.kind == TG_EVENT_IMAGE_LOAD) {
        tg_copy_string(event.loaded_image, sizeof(event.loaded_image), image);
        known = tg_etw_process_lookup(session, event.pid);
        if (known != NULL) tg_copy_string(event.image, sizeof(event.image), known);
    } else {
        tg_copy_string(event.image, sizeof(event.image), image);
    }

    if (event.ppid != 0) {
        known = tg_etw_process_lookup(session, event.ppid);
        if (known != NULL) tg_copy_string(event.parent_image, sizeof(event.parent_image), known);
    }

    if (event.kind == TG_EVENT_PROCESS_START && event.image[0] != '\0') {
        tg_etw_process_store(session, event.pid, event.image);
    }

    if (session->callback != NULL) session->callback(&event, session->user_context);
    if (event.kind == TG_EVENT_PROCESS_STOP) tg_etw_process_remove(session, event.pid);
}

static void WINAPI tg_etw_record_callback(EVENT_RECORD* record) {
    TgEtwSession* session;
    if (record == NULL || record->UserContext == NULL) return;
    session = (TgEtwSession*)record->UserContext;
    tg_etw_on_event(session, record);
}

void tg_etw_session_init(TgEtwSession* session, TgEventCallback callback, void* user_context) {
    if (session == NULL) return;
    memset(session, 0, sizeof(*session));
    session->callback = callback;
    session->user_context = user_context;
    session->process_entries = (TgEtwProcessEntry*)calloc(TG_ETW_PROCESS_CAPACITY, sizeof(TgEtwProcessEntry));
    if (session->process_entries != NULL) session->process_capacity = TG_ETW_PROCESS_CAPACITY;
    (void)_snwprintf_s(
        session->session_name,
        sizeof(session->session_name) / sizeof(session->session_name[0]),
        _TRUNCATE,
        L"WinTraceGuard-%lu",
        (unsigned long)GetCurrentProcessId());
}

void tg_etw_session_dispose(TgEtwSession* session) {
    if (session == NULL) return;
    tg_etw_session_stop(session);
    free(session->process_entries);
    session->process_entries = NULL;
    session->process_capacity = 0;
}

int tg_etw_session_start(TgEtwSession* session, char* error, size_t error_capacity) {
    size_t properties_size;
    EVENT_TRACE_PROPERTIES* properties;
    ULONG status;
    EVENT_TRACE_LOGFILEW logfile;

    if (session == NULL) {
        tg_set_error(error, error_capacity, "Invalid ETW session.");
        return 0;
    }
    if (session->process_entries == NULL || session->process_capacity == 0) {
        tg_set_error(error, error_capacity, "ETW process-correlation state could not be allocated.");
        return 0;
    }
    if (session->session_handle != 0) {
        tg_set_error(error, error_capacity, "ETW session is already running.");
        return 0;
    }

    InterlockedExchange(&session->stopping, 0);
    if (!tg_resolve_provider_guid(TG_PROVIDER_NAME, &session->provider_guid, error, error_capacity)) return 0;

    properties_size = sizeof(EVENT_TRACE_PROPERTIES) + 256U * sizeof(wchar_t);
    properties = (EVENT_TRACE_PROPERTIES*)calloc(1, properties_size);
    if (properties == NULL) {
        tg_set_error(error, error_capacity, "Unable to allocate ETW session properties.");
        return 0;
    }

    properties->Wnode.BufferSize = (ULONG)properties_size;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    status = StartTraceW(&session->session_handle, session->session_name, properties);
    free(properties);
    if (status != ERROR_SUCCESS) {
        session->session_handle = 0;
        tg_error_with_code(
            error,
            error_capacity,
            "StartTraceW failed: ",
            status,
            ". Try an elevated console if ETW session permissions are restricted.");
        return 0;
    }

    status = EnableTraceEx2(
        session->session_handle,
        &session->provider_guid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        0,
        NULL);
    if (status != ERROR_SUCCESS) {
        tg_error_with_code(error, error_capacity, "EnableTraceEx2 failed: ", status, "");
        tg_etw_session_stop(session);
        return 0;
    }

    memset(&logfile, 0, sizeof(logfile));
    logfile.LoggerName = session->session_name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = tg_etw_record_callback;
    logfile.Context = session;

    session->consumer_handle = OpenTraceW(&logfile);
    if (session->consumer_handle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG code = GetLastError();
        session->consumer_handle = 0;
        tg_error_with_code(error, error_capacity, "OpenTraceW failed: ", code, "");
        tg_etw_session_stop(session);
        return 0;
    }

    return 1;
}

int tg_etw_session_run(TgEtwSession* session, char* error, size_t error_capacity) {
    TRACEHANDLE handle;
    ULONG status;
    if (session == NULL || session->consumer_handle == 0) {
        tg_set_error(error, error_capacity, "ETW consumer is not open.");
        return 0;
    }

    handle = session->consumer_handle;
    status = ProcessTrace(&handle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        tg_error_with_code(error, error_capacity, "ProcessTrace failed: ", status, "");
        return 0;
    }
    return 1;
}

void tg_etw_session_stop(TgEtwSession* session) {
    if (session == NULL) return;
    if (InterlockedExchange(&session->stopping, 1) != 0) return;

    if (session->session_handle != 0) {
        size_t properties_size = sizeof(EVENT_TRACE_PROPERTIES) + 256U * sizeof(wchar_t);
        EVENT_TRACE_PROPERTIES* properties = (EVENT_TRACE_PROPERTIES*)calloc(1, properties_size);
        if (properties != NULL) {
            properties->Wnode.BufferSize = (ULONG)properties_size;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            (void)ControlTraceW(
                session->session_handle,
                session->session_name,
                properties,
                EVENT_TRACE_CONTROL_STOP);
            free(properties);
        }
        session->session_handle = 0;
    }

    if (session->consumer_handle != 0 && session->consumer_handle != INVALID_PROCESSTRACE_HANDLE) {
        (void)CloseTrace(session->consumer_handle);
        session->consumer_handle = 0;
    }
}

const wchar_t* tg_etw_session_name(const TgEtwSession* session) {
    return session != NULL ? session->session_name : L"";
}
