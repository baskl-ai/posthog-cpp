# Unit tests (no network required)
add_executable(unit_tests unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE posthog)

# MAC ID test
add_executable(test_mac_id test_mac_id.cpp)
target_link_libraries(test_mac_id PRIVATE posthog)

# Internal user detection test
add_executable(test_internal_user test_internal_user.cpp)

enable_testing()
add_test(NAME unit_tests COMMAND unit_tests)
add_test(NAME test_internal_user COMMAND test_internal_user)

# Exercise real terminate/abort handlers, then parse in a fresh process.
add_executable(terminate_tests terminate_tests.cpp)
target_link_libraries(terminate_tests PRIVATE posthog)
set(terminate_scenarios exception multiline unknown explicit empty long unicode open_failure)
if(UNIX)
    list(APPEND terminate_scenarios abort foreign)
    # MSVC keeps terminate handlers per thread, so a foreign thread never
    # reaches ours there; on Unix the hook is process-wide.
    add_library(foreign_thrower SHARED foreign_thrower.cpp)
    target_link_libraries(terminate_tests PRIVATE foreign_thrower)
    target_compile_definitions(terminate_tests PRIVATE POSTHOG_TEST_FOREIGN_MODULE=1)
endif()
if(WIN32)
    list(APPEND terminate_scenarios native no_filter)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND terminate_scenarios write_failure)
endif()
foreach(scenario IN LISTS terminate_scenarios)
    add_test(NAME terminate_${scenario}
        COMMAND ${CMAKE_COMMAND} -DPROGRAM=$<TARGET_FILE:terminate_tests>
                -DSCENARIO=${scenario} -P ${CMAKE_CURRENT_SOURCE_DIR}/terminate_test.cmake)
endforeach()

# Basic example (requires API key)
add_executable(basic basic.cpp)
target_link_libraries(basic PRIVATE posthog)

# Crash handler example (requires API key)
add_executable(crash crash.cpp)
target_link_libraries(crash PRIVATE posthog)

# Logging example (requires API key)
add_executable(logging_example ../examples/logging.cpp)
target_link_libraries(logging_example PRIVATE posthog)

# A release-like fixture: hidden functions, no PDBs, no inline/tail-call shortcuts.
# It is copied without symbols and run from two installation paths by the test.
add_executable(stacktrace_probe stacktrace_probe.cpp)
target_link_libraries(stacktrace_probe PRIVATE posthog)
set_target_properties(stacktrace_probe PROPERTIES CXX_VISIBILITY_PRESET hidden)
if(MSVC)
    target_compile_options(stacktrace_probe PRIVATE /O2)
    target_link_options(stacktrace_probe PRIVATE /DEBUG:NONE)
else()
    target_compile_options(stacktrace_probe PRIVATE -O2 -g0)
    set_target_properties(stacktrace_probe PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
    cmake_policy(SET CMP0083 NEW)
    include(CheckPIESupported)
    check_pie_supported()
    # Mach-O dladdr can resolve local nlist symbols even with hidden visibility.
    # Strip the fixture explicitly so the offset fallback is actually exercised.
    add_custom_command(TARGET stacktrace_probe POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:stacktrace_probe>)
    if(APPLE)
        add_custom_command(TARGET stacktrace_probe POST_BUILD
            COMMAND codesign --force --sign - $<TARGET_FILE:stacktrace_probe>)
    endif()
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(crash_frames_tests crash_frames_tests.cpp)
target_link_libraries(crash_frames_tests PRIVATE posthog)
add_test(NAME crash_frames COMMAND crash_frames_tests)
add_executable(crash_report_probe crash_report_probe.cpp)
target_link_libraries(crash_report_probe PRIVATE posthog)
add_test(NAME crash_report_stability COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_crash_reports.py $<TARGET_FILE:crash_report_probe>)
if(POSTHOG_USE_CURL AND (TARGET libcurl_static OR TARGET CURL::libcurl))
    add_test(NAME crash_report_http COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_crash_reports.py $<TARGET_FILE:crash_report_probe> http)
    set_tests_properties(crash_report_http PROPERTIES TIMEOUT 60)
endif()
add_test(NAME symbolize COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_symbolize.py)
set_tests_properties(crash_frames crash_report_stability symbolize PROPERTIES TIMEOUT 60)
add_test(NAME stacktrace_stability COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_stacktrace_stability.py $<TARGET_FILE:stacktrace_probe>)

if(WIN32)
    add_executable(windows_crash_tests windows_crash_tests.cpp windows_crash_other.cpp)
    target_include_directories(windows_crash_tests PRIVATE ../include)
    target_link_libraries(windows_crash_tests PRIVATE psapi shell32)
    add_test(NAME windows_crash_tests COMMAND windows_crash_tests)
    set_tests_properties(windows_crash_tests PROPERTIES TIMEOUT 60)
endif()
