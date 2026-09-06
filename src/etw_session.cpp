#include "traceguard/etw_session.hpp"

#include <tdh.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace traceguard {
namespace {

constexpr wchar_t kProviderName[] = L"Microsoft-Windows-Kernel-Process";

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string out(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), out.data(), required, nullptr, nullptr);
    return out;
}

std::string ErrorText(ULONG code) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD len = FormatMessageW(flags, nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring message = len && buffer ? std::wstring(buffer, len) : L"Windows error " + std::to_wstring(code);
    if (buffer) LocalFree(buffer);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) message.pop_back();
    return WideToUtf8(message);
}

bool ResolveProviderGuid(const wchar_t* provider_name, GUID& guid, std::string& error) {
    ULONG size = 0;
    ULONG status = TdhEnumerateProviders(nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        error = "TdhEnumerateProviders(size) failed: " + ErrorText(status);
        return false;
    }

    std::vector<std::byte> buffer(size);
    auto* info = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buffer.data());
    status = TdhEnumerateProviders(info, &size);
    if (status != ERROR_SUCCESS) {
        error = "TdhEnumerateProviders failed: " + ErrorText(status);
        return false;
    }

    for (ULONG i = 0; i < info->NumberOfProviders; ++i) {
        const auto& entry = info->TraceProviderInfoArray[i];
        if (entry.ProviderNameOffset == 0 || entry.ProviderNameOffset >= size) continue;
        const auto* name = reinterpret_cast<const wchar_t*>(buffer.data() + entry.ProviderNameOffset);
        if (_wcsicmp(name, provider_name) == 0) {
            guid = entry.ProviderGuid;
            return true;
        }
    }

    error = "ETW provider Microsoft-Windows-Kernel-Process was not found on this system.";
    return false;
}

std::vector<std::byte> ReadProperty(EVENT_RECORD* record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    ULONG status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size);
    if (status != ERROR_SUCCESS || size == 0 || size > (1024U * 1024U)) return {};

    std::vector<std::byte> buffer(size);
    status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, reinterpret_cast<PBYTE>(buffer.data()));
    if (status != ERROR_SUCCESS) return {};
    return buffer;
}

std::uint32_t ReadU32(EVENT_RECORD* record, const std::initializer_list<const wchar_t*>& names, std::uint32_t fallback = 0) {
    for (const wchar_t* name : names) {
        auto bytes = ReadProperty(record, name);
        if (bytes.size() == sizeof(std::uint32_t)) {
            std::uint32_t value = 0;
            std::memcpy(&value, bytes.data(), sizeof(value));
            return value;
        }
        if (bytes.size() == sizeof(std::uint64_t)) {
            std::uint64_t value = 0;
            std::memcpy(&value, bytes.data(), sizeof(value));
            return static_cast<std::uint32_t>(value & 0xffffffffULL);
        }
    }
    return fallback;
}

std::wstring ReadText(EVENT_RECORD* record, const std::initializer_list<const wchar_t*>& names) {
    for (const wchar_t* name : names) {
        auto bytes = ReadProperty(record, name);
        if (bytes.empty()) continue;

        if ((bytes.size() % sizeof(wchar_t)) == 0 && bytes.size() >= sizeof(wchar_t)) {
            const auto* ptr = reinterpret_cast<const wchar_t*>(bytes.data());
            const std::size_t count = bytes.size() / sizeof(wchar_t);
            std::size_t len = 0;
            while (len < count && ptr[len] != L'\0') ++len;
            if (len > 0) return std::wstring(ptr, len);
        }

        const auto* chars = reinterpret_cast<const char*>(bytes.data());
        std::size_t len = 0;
        while (len < bytes.size() && chars[len] != '\0') ++len;
        if (len > 0) {
            const int required = MultiByteToWideChar(CP_ACP, 0, chars, static_cast<int>(len), nullptr, 0);
            if (required > 0) {
                std::wstring out(static_cast<std::size_t>(required), L'\0');
                MultiByteToWideChar(CP_ACP, 0, chars, static_cast<int>(len), out.data(), required);
                return out;
            }
        }
    }
    return {};
}

bool HasProperty(EVENT_RECORD* record, const wchar_t* name) {
    return !ReadProperty(record, name).empty();
}

std::string FormatTimestamp(const LARGE_INTEGER& timestamp) {
    FILETIME ft{};
    ft.dwLowDateTime = timestamp.LowPart;
    ft.dwHighDateTime = static_cast<DWORD>(timestamp.HighPart);
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&ft, &st)) return {};

    char buffer[40]{};
    sprintf_s(buffer, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buffer;
}

EventKind ClassifyEvent(EVENT_RECORD* record, const std::wstring& command_line, const std::wstring& image) {
    const auto opcode = record->EventHeader.EventDescriptor.Opcode;
    if (!command_line.empty() || HasProperty(record, L"ParentProcessID") || HasProperty(record, L"ParentId")) return EventKind::ProcessStart;
    if (opcode == EVENT_TRACE_TYPE_END || opcode == 2) return EventKind::ProcessStop;
    if (!image.empty() && (HasProperty(record, L"ImageBase") || HasProperty(record, L"ImageSize"))) return EventKind::ImageLoad;
    if (opcode == EVENT_TRACE_TYPE_START || opcode == 1) return EventKind::ProcessStart;
    return EventKind::Other;
}

} // namespace

EtwSession::EtwSession(EventCallback callback) : callback_(std::move(callback)) {
    session_name_ = L"WinTraceGuard-" + std::to_wstring(GetCurrentProcessId());
}

EtwSession::~EtwSession() { Stop(); }

bool EtwSession::Start(std::string& error) {
    if (session_handle_ != 0) {
        error = "ETW session is already running.";
        return false;
    }

    stopping_ = false;
    if (!ResolveProviderGuid(kProviderName, provider_guid_, error)) return false;

    constexpr std::size_t name_chars = 256;
    const std::size_t properties_size = sizeof(EVENT_TRACE_PROPERTIES) + name_chars * sizeof(wchar_t);
    std::vector<std::byte> properties_buffer(properties_size);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer.data());
    properties->Wnode.BufferSize = static_cast<ULONG>(properties_size);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&session_handle_, session_name_.c_str(), properties);
    if (status != ERROR_SUCCESS) {
        error = "StartTraceW failed: " + ErrorText(status) + ". Try an elevated console if ETW session permissions are restricted.";
        session_handle_ = 0;
        return false;
    }

    status = EnableTraceEx2(session_handle_, &provider_guid_, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        error = "EnableTraceEx2 failed: " + ErrorText(status);
        Stop();
        return false;
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(session_name_.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwSession::EventRecordCallbackThunk;
    logfile.Context = this;

    consumer_handle_ = OpenTraceW(&logfile);
    if (consumer_handle_ == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG code = GetLastError();
        error = "OpenTraceW failed: " + ErrorText(code);
        consumer_handle_ = 0;
        Stop();
        return false;
    }
    return true;
}

bool EtwSession::Run(std::string& error) {
    if (consumer_handle_ == 0) {
        error = "ETW consumer is not open.";
        return false;
    }
    TRACEHANDLE handle = consumer_handle_;
    const ULONG status = ProcessTrace(&handle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        error = "ProcessTrace failed: " + ErrorText(status);
        return false;
    }
    return true;
}

void EtwSession::Stop() {
    if (stopping_.exchange(true)) return;

    if (session_handle_ != 0) {
        constexpr std::size_t name_chars = 256;
        const std::size_t properties_size = sizeof(EVENT_TRACE_PROPERTIES) + name_chars * sizeof(wchar_t);
        std::vector<std::byte> properties_buffer(properties_size);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_buffer.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(properties_size);
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(session_handle_, session_name_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        session_handle_ = 0;
    }

    if (consumer_handle_ != 0 && consumer_handle_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(consumer_handle_);
        consumer_handle_ = 0;
    }
}

void WINAPI EtwSession::EventRecordCallbackThunk(EVENT_RECORD* record) {
    if (!record || !record->UserContext) return;
    static_cast<EtwSession*>(record->UserContext)->OnEvent(record);
}

void EtwSession::OnEvent(EVENT_RECORD* record) {
    const std::wstring image_w = ReadText(record, {L"ImageName", L"ImageFileName", L"FileName"});
    const std::wstring command_w = ReadText(record, {L"CommandLine"});

    Event event;
    event.timestamp_utc = FormatTimestamp(record->EventHeader.TimeStamp);
    event.event_id = record->EventHeader.EventDescriptor.Id;
    event.opcode = record->EventHeader.EventDescriptor.Opcode;
    event.provider = "Microsoft-Windows-Kernel-Process";
    event.pid = ReadU32(record, {L"ProcessID", L"ProcessId"}, record->EventHeader.ProcessId);
    event.ppid = ReadU32(record, {L"ParentProcessID", L"ParentProcessId", L"ParentId"}, 0);
    event.kind = ClassifyEvent(record, command_w, image_w);
    event.command_line = WideToUtf8(command_w);

    const std::string image = WideToUtf8(image_w);
    if (event.kind == EventKind::ImageLoad) {
        event.loaded_image = image;
        const auto it = process_images_.find(event.pid);
        if (it != process_images_.end()) event.image = it->second;
    } else {
        event.image = image;
    }

    if (event.ppid != 0) {
        const auto parent = process_images_.find(event.ppid);
        if (parent != process_images_.end()) event.parent_image = parent->second;
    }

    if (event.kind == EventKind::ProcessStart && !event.image.empty()) process_images_[event.pid] = event.image;
    callback_(event);
    if (event.kind == EventKind::ProcessStop) process_images_.erase(event.pid);
}

} // namespace traceguard
