#include "traceguard/event.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace traceguard {

std::string ToString(EventKind kind) {
    switch (kind) {
        case EventKind::ProcessStart: return "process_start";
        case EventKind::ProcessStop: return "process_stop";
        case EventKind::ImageLoad: return "image_load";
        default: return "other";
    }
}

std::string ToString(Severity severity) {
    switch (severity) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        default: return "info";
    }
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    out << "\\u00" << hex[(ch >> 4) & 0x0f] << hex[ch & 0x0f];
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    return out.str();
}

std::string LowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string BasenameLower(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    return LowerAscii(pos == std::string::npos ? path : path.substr(pos + 1));
}

} // namespace traceguard
