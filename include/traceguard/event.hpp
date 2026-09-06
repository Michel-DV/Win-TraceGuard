#pragma once

#include <cstdint>
#include <string>

namespace traceguard {

enum class EventKind { ProcessStart, ProcessStop, ImageLoad, Other };
enum class Severity { Info, Low, Medium, High };

struct Event {
    std::string timestamp_utc;
    EventKind kind{EventKind::Other};
    std::uint32_t pid{0};
    std::uint32_t ppid{0};
    std::uint16_t event_id{0};
    std::uint8_t opcode{0};
    std::string provider;
    std::string image;
    std::string parent_image;
    std::string command_line;
    std::string loaded_image;
};

struct Finding {
    std::string timestamp_utc;
    std::string rule_id;
    Severity severity{Severity::Info};
    std::string title;
    std::string rationale;
    std::uint32_t pid{0};
    std::string image;
};

std::string ToString(EventKind kind);
std::string ToString(Severity severity);
std::string JsonEscape(const std::string& value);
std::string LowerAscii(std::string value);
std::string BasenameLower(const std::string& path);

} // namespace traceguard
