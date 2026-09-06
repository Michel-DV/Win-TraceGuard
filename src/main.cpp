#include "traceguard/etw_session.hpp"
#include "traceguard/jsonl.hpp"
#include "traceguard/rule_engine.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

constexpr const char* kVersion = "1.0.0";

void PrintBanner() {
    std::cout << "Win-TraceGuard " << kVersion << " | Windows ETW telemetry & detection sensor\n";
}

void PrintUsage() {
    PrintBanner();
    std::cout
        << "\nUsage:\n"
        << "  traceguard capture [--seconds N] [--jsonl path] [--quiet]\n"
        << "  traceguard replay <events.jsonl> [--json]\n"
        << "  traceguard providers\n"
        << "  traceguard --version\n\n"
        << "Capture uses the Microsoft-Windows-Kernel-Process ETW provider.\n"
        << "Depending on local ETW policy, an elevated console may be required.\n";
}

const char* SeverityTag(traceguard::Severity severity) {
    switch (severity) {
        case traceguard::Severity::High: return "HIGH";
        case traceguard::Severity::Medium: return "MED ";
        case traceguard::Severity::Low: return "LOW ";
        default: return "INFO";
    }
}

void PrintEvent(const traceguard::Event& e) {
    std::cout << "[EVT ] " << e.timestamp_utc << " " << traceguard::ToString(e.kind)
              << " pid=" << e.pid;
    if (e.ppid) std::cout << " ppid=" << e.ppid;
    if (!e.image.empty()) std::cout << " image=\"" << e.image << "\"";
    if (!e.loaded_image.empty()) std::cout << " loaded=\"" << e.loaded_image << "\"";
    std::cout << '\n';
}

void PrintFinding(const traceguard::Finding& f) {
    std::cout << "[" << SeverityTag(f.severity) << "] " << f.rule_id << " | " << f.title
              << " | pid=" << f.pid;
    if (!f.image.empty()) std::cout << " | " << f.image;
    std::cout << "\n       " << f.rationale << '\n';
}

int Capture(int argc, char** argv) {
    unsigned int seconds = 15;
    std::string jsonl_path;
    bool quiet = false;

    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--seconds" && i + 1 < argc) {
            try {
                seconds = static_cast<unsigned int>(std::stoul(argv[++i]));
            } catch (...) {
                std::cerr << "Invalid --seconds value.\n";
                return 2;
            }
            if (seconds == 0 || seconds > 3600) {
                std::cerr << "--seconds must be between 1 and 3600.\n";
                return 2;
            }
        } else if (arg == "--jsonl" && i + 1 < argc) {
            jsonl_path = argv[++i];
        } else if (arg == "--quiet") {
            quiet = true;
        } else {
            std::cerr << "Unknown capture option: " << arg << '\n';
            return 2;
        }
    }

    std::unique_ptr<traceguard::JsonlWriter> writer;
    if (!jsonl_path.empty()) {
        writer = std::make_unique<traceguard::JsonlWriter>(jsonl_path);
        if (!writer->good()) {
            std::cerr << "Unable to open JSONL output: " << jsonl_path << '\n';
            return 1;
        }
    }

    traceguard::RuleEngine engine;
    std::size_t event_count = 0;
    std::size_t finding_count = 0;

    traceguard::EtwSession session([&](traceguard::Event event) {
        ++event_count;
        if (!quiet) PrintEvent(event);
        if (writer) writer->Write(event);

        auto findings = engine.Evaluate(std::move(event));
        for (const auto& finding : findings) {
            ++finding_count;
            PrintFinding(finding);
            if (writer) writer->Write(finding);
        }
    });

    std::string error;
    if (!session.Start(error)) {
        std::cerr << "TraceGuard capture failed: " << error << '\n';
        return 1;
    }

    PrintBanner();
    std::cout << "[+] Session: WinTraceGuard realtime session\n"
              << "[+] Provider: Microsoft-Windows-Kernel-Process\n"
              << "[+] Duration: " << seconds << "s\n";
    if (writer) std::cout << "[+] JSONL: " << jsonl_path << '\n';

    std::thread stopper([&session, seconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
        session.Stop();
    });

    const bool ok = session.Run(error);
    if (stopper.joinable()) stopper.join();

    std::cout << "\nCapture summary: " << event_count << " events, " << finding_count << " findings.\n";
    if (!ok) {
        std::cerr << error << '\n';
        return 1;
    }
    return 0;
}

int Replay(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "replay requires a JSONL path.\n";
        return 2;
    }

    const std::string path = argv[2];
    bool json = false;
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--json") json = true;
        else {
            std::cerr << "Unknown replay option: " << arg << '\n';
            return 2;
        }
    }

    std::ifstream in(path);
    if (!in) {
        std::cerr << "Unable to open replay file: " << path << '\n';
        return 1;
    }

    traceguard::RuleEngine engine;
    std::string line;
    std::size_t events = 0;
    std::size_t findings = 0;
    std::size_t rejected = 0;

    while (std::getline(in, line)) {
        if (line.empty()) continue;
        auto event = traceguard::ParseEventJsonLine(line);
        if (!event) {
            ++rejected;
            continue;
        }
        ++events;
        auto matches = engine.Evaluate(*event);
        for (const auto& finding : matches) {
            ++findings;
            if (json) std::cout << traceguard::FindingToJson(finding) << '\n';
            else PrintFinding(finding);
        }
    }

    if (!json) {
        std::cout << "Replay summary: " << events << " events, " << findings << " findings";
        if (rejected) std::cout << ", " << rejected << " non-event/invalid lines ignored";
        std::cout << ".\n";
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    const std::string command = argv[1];
    if (command == "--version" || command == "-V") {
        std::cout << "Win-TraceGuard " << kVersion << '\n';
        return 0;
    }
    if (command == "capture") return Capture(argc, argv);
    if (command == "replay") return Replay(argc, argv);
    if (command == "providers") {
        std::cout << "Configured ETW providers:\n"
                  << "  Microsoft-Windows-Kernel-Process  process/image telemetry\n";
        return 0;
    }
    if (command == "help" || command == "--help" || command == "-h") {
        PrintUsage();
        return 0;
    }

    std::cerr << "Unknown command: " << command << "\n\n";
    PrintUsage();
    return 2;
}
