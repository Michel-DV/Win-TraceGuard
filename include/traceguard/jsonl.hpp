#pragma once

#include "traceguard/event.hpp"

#include <fstream>
#include <optional>
#include <string>

namespace traceguard {

std::string EventToJson(const Event& event);
std::string FindingToJson(const Finding& finding);
std::optional<Event> ParseEventJsonLine(const std::string& line);

class JsonlWriter {
public:
    explicit JsonlWriter(const std::string& path);
    bool good() const;
    void Write(const Event& event);
    void Write(const Finding& finding);

private:
    std::ofstream out_;
};

} // namespace traceguard
