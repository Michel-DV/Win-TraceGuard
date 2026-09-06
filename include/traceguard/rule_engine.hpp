#pragma once

#include "traceguard/event.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace traceguard {

class RuleEngine {
public:
    std::vector<Finding> Evaluate(Event event);
    void Reset();

private:
    std::unordered_map<std::uint32_t, std::string> process_images_;

    static Finding MakeFinding(
        const Event& event,
        std::string rule_id,
        Severity severity,
        std::string title,
        std::string rationale);
};

} // namespace traceguard
