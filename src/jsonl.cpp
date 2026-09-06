#include "traceguard/jsonl.hpp"

#include <charconv>
#include <cctype>
#include <sstream>

namespace traceguard {
namespace {

std::optional<std::string> ExtractString(const std::string& line, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos = line.find(':', pos + needle.size());
    if (pos == std::string::npos) return std::nullopt;
    ++pos;
    while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
    if (pos >= line.size() || line[pos] != '"') return std::nullopt;
    ++pos;

    std::string out;
    while (pos < line.size()) {
        char c = line[pos++];
        if (c == '"') return out;
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (pos >= line.size()) return std::nullopt;
        const char esc = line[pos++];
        switch (esc) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> ExtractUInt(const std::string& line, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos = line.find(':', pos + needle.size());
    if (pos == std::string::npos) return std::nullopt;
    ++pos;
    while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;

    const char* begin = line.data() + pos;
    const char* end = line.data() + line.size();
    std::uint32_t value = 0;
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{}) return std::nullopt;
    return value;
}

EventKind ParseKind(const std::string& kind) {
    if (kind == "process_start") return EventKind::ProcessStart;
    if (kind == "process_stop") return EventKind::ProcessStop;
    if (kind == "image_load") return EventKind::ImageLoad;
    return EventKind::Other;
}

} // namespace

std::string EventToJson(const Event& e) {
    std::ostringstream out;
    out << "{\"type\":\"event\""
        << ",\"timestamp_utc\":\"" << JsonEscape(e.timestamp_utc) << "\""
        << ",\"kind\":\"" << ToString(e.kind) << "\""
        << ",\"pid\":" << e.pid
        << ",\"ppid\":" << e.ppid
        << ",\"event_id\":" << e.event_id
        << ",\"opcode\":" << static_cast<unsigned int>(e.opcode)
        << ",\"provider\":\"" << JsonEscape(e.provider) << "\""
        << ",\"image\":\"" << JsonEscape(e.image) << "\""
        << ",\"parent_image\":\"" << JsonEscape(e.parent_image) << "\""
        << ",\"command_line\":\"" << JsonEscape(e.command_line) << "\""
        << ",\"loaded_image\":\"" << JsonEscape(e.loaded_image) << "\"}";
    return out.str();
}

std::string FindingToJson(const Finding& f) {
    std::ostringstream out;
    out << "{\"type\":\"finding\""
        << ",\"timestamp_utc\":\"" << JsonEscape(f.timestamp_utc) << "\""
        << ",\"rule_id\":\"" << JsonEscape(f.rule_id) << "\""
        << ",\"severity\":\"" << ToString(f.severity) << "\""
        << ",\"title\":\"" << JsonEscape(f.title) << "\""
        << ",\"rationale\":\"" << JsonEscape(f.rationale) << "\""
        << ",\"pid\":" << f.pid
        << ",\"image\":\"" << JsonEscape(f.image) << "\"}";
    return out.str();
}

std::optional<Event> ParseEventJsonLine(const std::string& line) {
    const auto type = ExtractString(line, "type");
    if (!type || *type != "event") return std::nullopt;

    const auto kind = ExtractString(line, "kind");
    if (!kind) return std::nullopt;

    Event e;
    e.timestamp_utc = ExtractString(line, "timestamp_utc").value_or("");
    e.kind = ParseKind(*kind);
    e.pid = ExtractUInt(line, "pid").value_or(0);
    e.ppid = ExtractUInt(line, "ppid").value_or(0);
    e.event_id = static_cast<std::uint16_t>(ExtractUInt(line, "event_id").value_or(0));
    e.opcode = static_cast<std::uint8_t>(ExtractUInt(line, "opcode").value_or(0));
    e.provider = ExtractString(line, "provider").value_or("");
    e.image = ExtractString(line, "image").value_or("");
    e.parent_image = ExtractString(line, "parent_image").value_or("");
    e.command_line = ExtractString(line, "command_line").value_or("");
    e.loaded_image = ExtractString(line, "loaded_image").value_or("");
    return e;
}

JsonlWriter::JsonlWriter(const std::string& path) : out_(path, std::ios::out | std::ios::trunc) {}
bool JsonlWriter::good() const { return out_.good(); }
void JsonlWriter::Write(const Event& event) { out_ << EventToJson(event) << '\n'; out_.flush(); }
void JsonlWriter::Write(const Finding& finding) { out_ << FindingToJson(finding) << '\n'; out_.flush(); }

} // namespace traceguard
