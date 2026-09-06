cmake_minimum_required(VERSION 3.22)
project(WinTraceGuard VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Win-TraceGuard is a Windows-only project.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TRACEGUARD_BUILD_TESTS "Build TraceGuard tests" ON)

add_library(traceguard_core STATIC
    src/event.cpp
    src/jsonl.cpp
    src/rule_engine.cpp
)

target_include_directories(traceguard_core PUBLIC include)
target_compile_definitions(traceguard_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(traceguard_core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc /utf-8>
)

add_library(traceguard_etw STATIC src/etw_session.cpp)
target_include_directories(traceguard_etw PUBLIC include)
target_link_libraries(traceguard_etw PUBLIC traceguard_core tdh advapi32)
target_compile_definitions(traceguard_etw PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(traceguard_etw PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc /utf-8>
)

add_executable(traceguard src/main.cpp)
target_link_libraries(traceguard PRIVATE traceguard_core traceguard_etw)
target_compile_options(traceguard PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc /utf-8>
)

if(TRACEGUARD_BUILD_TESTS)
    enable_testing()
    add_executable(traceguard_tests tests/test_core.cpp)
    target_link_libraries(traceguard_tests PRIVATE traceguard_core)
    target_compile_options(traceguard_tests PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc /utf-8>
    )
    add_test(NAME traceguard_core_tests COMMAND traceguard_tests)
endif()
