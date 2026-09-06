#include "traceguard/rule_engine.hpp"

#include <initializer_list>
#include <utility>

namespace traceguard {
namespace {

bool ContainsAny(const std::string& value, const std::initializer_list<const char*>& needles) {
    for (const char* needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool IsUserWritablePath(const std::string& path) {
    const auto lower = LowerAscii(path);
    return ContainsAny(lower, {"\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\"});
}

bool IsScriptHost(const std::string& image) {
    const auto base = BasenameLower(image);
    return base == "powershell.exe" || base == "pwsh.exe" || base == "cmd.exe" ||
           base == "wscript.exe" || base == "cscript.exe" || base == "mshta.exe";
}

bool IsOfficeParent(const std::string& image) {
    const auto base = BasenameLower(image);
    return base == "winword.exe" || base == "excel.exe" || base == "powerpnt.exe" ||
           base == "outlook.exe" || base == "onenote.exe";
}

} // namespace

Finding RuleEngine::MakeFinding(
    const Event& event,
    std::string rule_id,
    Severity severity,
    std::string title,
    std::string rationale) {
    Finding f;
    f.timestamp_utc = event.timestamp_utc;
    f.rule_id = std::move(rule_id);
    f.severity = severity;
    f.title = std::move(title);
    f.rationale = std::move(rationale);
    f.pid = event.pid;
    f.image = event.image.empty() ? event.loaded_image : event.image;
    return f;
}

std::vector<Finding> RuleEngine::Evaluate(Event event) {
    std::vector<Finding> findings;

    if (event.parent_image.empty() && event.ppid != 0) {
        const auto it = process_images_.find(event.ppid);
        if (it != process_images_.end()) event.parent_image = it->second;
    }

    if (event.kind == EventKind::ProcessStart) {
        const auto cmd_lower = LowerAscii(event.command_line);
        const auto base = BasenameLower(event.image);

        if (IsUserWritablePath(event.image)) {
            findings.push_back(MakeFinding(
                event, "TG1001", Severity::Medium,
                "Executable started from a user-writable location",
                "Execution from AppData, Temp, Downloads or Users\\Public deserves analyst review because those paths are commonly writable by standard users."));
        }

        if (IsOfficeParent(event.parent_image) && IsScriptHost(event.image)) {
            findings.push_back(MakeFinding(
                event, "TG1002", Severity::High,
                "Office application spawned a command or script interpreter",
                "The parent/child relationship is uncommon in normal document workflows and is frequently useful as an initial-access or macro-abuse hunting signal."));
        }

        if ((base == "powershell.exe" || base == "pwsh.exe") &&
            ContainsAny(cmd_lower, {" -enc ", " -enc\"", " -encodedcommand ", " /enc ", " -e "})) {
            findings.push_back(MakeFinding(
                event, "TG1003", Severity::High,
                "PowerShell command line contains an encoded-command switch",
                "Encoded PowerShell is not inherently malicious, but it reduces command-line transparency and is a strong triage signal when correlated with process ancestry."));
        }

        if (base == "mshta.exe" && ContainsAny(cmd_lower, {"http://", "https://"})) {
            findings.push_back(MakeFinding(
                event, "TG1004", Severity::High,
                "MSHTA launched with a remote URL",
                "Remote-content execution through mshta.exe is a high-value living-off-the-land detection signal and should be validated against approved administrative activity."));
        }

        if (base == "rundll32.exe" && ContainsAny(cmd_lower, {"http://", "https://", "javascript:", "vbscript:"})) {
            findings.push_back(MakeFinding(
                event, "TG1005", Severity::High,
                "Rundll32 command line contains remote or script-like content",
                "The command line contains content that is unusual for routine DLL invocation and merits immediate review."));
        }

        if ((base == "regsvr32.exe" || base == "rundll32.exe" || base == "mshta.exe") && IsUserWritablePath(event.command_line)) {
            findings.push_back(MakeFinding(
                event, "TG1006", Severity::Medium,
                "Windows utility references content in a user-writable path",
                "A signed Windows utility is referencing AppData, Temp, Downloads or Users\\Public. This is an explainable dual-use heuristic, not a malware verdict."));
        }

        if (!event.image.empty()) process_images_[event.pid] = event.image;
    }

    if (event.kind == EventKind::ImageLoad && IsUserWritablePath(event.loaded_image)) {
        findings.push_back(MakeFinding(
            event, "TG2001", Severity::Medium,
            "Image loaded from a user-writable location",
            "A DLL or executable image was loaded from a commonly user-writable path. Validate the signer, origin and expected application behavior."));
    }

    if (event.kind == EventKind::ProcessStop) process_images_.erase(event.pid);
    return findings;
}

void RuleEngine::Reset() { process_images_.clear(); }

} // namespace traceguard
