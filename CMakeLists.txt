cmake_minimum_required(VERSION 3.22)
project(WinTraceGuard VERSION 1.0.1 LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "Win-TraceGuard is a Windows-only project.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(TRACEGUARD_BUILD_TESTS "Build TraceGuard tests" ON)

add_library(traceguard_core STATIC
    src/event.c
    src/jsonl.c
    src/rule_engine.c
)

target_include_directories(traceguard_core PUBLIC include)
target_compile_definitions(traceguard_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(traceguard_core PRIVATE
    $<$<C_COMPILER_ID:MSVC>:/W4 /utf-8>
)

add_library(traceguard_etw STATIC src/etw_session.c)
target_include_directories(traceguard_etw PUBLIC include)
target_link_libraries(traceguard_etw PUBLIC traceguard_core tdh advapi32)
target_compile_definitions(traceguard_etw PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(traceguard_etw PRIVATE
    $<$<C_COMPILER_ID:MSVC>:/W4 /utf-8>
)

add_executable(traceguard src/main.c)
target_link_libraries(traceguard PRIVATE traceguard_core traceguard_etw)
target_compile_definitions(traceguard PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(traceguard PRIVATE
    $<$<C_COMPILER_ID:MSVC>:/W4 /utf-8>
)

if(TRACEGUARD_BUILD_TESTS)
    enable_testing()
    add_executable(traceguard_tests tests/test_core.c)
    target_link_libraries(traceguard_tests PRIVATE traceguard_core)
    target_compile_options(traceguard_tests PRIVATE
        $<$<C_COMPILER_ID:MSVC>:/W4 /utf-8>
    )
    add_test(NAME traceguard_core_tests COMMAND traceguard_tests)
endif()
