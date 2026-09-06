#pragma once

#include "traceguard/event.hpp"

#include <Windows.h>
#include <evntrace.h>

#include <atomic>
#include <functional>
#include <string>
#include <unordered_map>

namespace traceguard {

class EtwSession {
public:
    using EventCallback = std::function<void(Event)>;

    explicit EtwSession(EventCallback callback);
    ~EtwSession();

    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    bool Start(std::string& error);
    bool Run(std::string& error);
    void Stop();

    const std::wstring& session_name() const noexcept { return session_name_; }

private:
    static void WINAPI EventRecordCallbackThunk(EVENT_RECORD* record);
    void OnEvent(EVENT_RECORD* record);

    EventCallback callback_;
    TRACEHANDLE session_handle_{0};
    TRACEHANDLE consumer_handle_{0};
    std::wstring session_name_;
    GUID provider_guid_{};
    std::atomic<bool> stopping_{false};
    std::unordered_map<std::uint32_t, std::string> process_images_;
};

} // namespace traceguard
