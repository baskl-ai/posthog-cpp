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
    list(APPEND terminate_scenarios abort)
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
if(POSTHOG_USE_CURL AND (TARGET CURL::libcurl OR TARGET libcurl_static))
    add_executable(crash_payload_probe crash_payload_probe.cpp)
    target_link_libraries(crash_payload_probe PRIVATE posthog)
    add_test(NAME crash_payload COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_crash_payload.py $<TARGET_FILE:crash_payload_probe>)
endif()
if(APPLE)
    add_executable(native_metadata_probe native_metadata_probe.cpp)
    target_link_libraries(native_metadata_probe PRIVATE posthog)
    add_library(native_metadata_module MODULE native_metadata_module.cpp)
    target_include_directories(native_metadata_module PRIVATE ../include)
    set_target_properties(native_metadata_module PROPERTIES CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN TRUE)
    target_compile_options(native_metadata_probe PRIVATE -g)
    target_compile_options(native_metadata_module PRIVATE -g)
    add_test(NAME native_metadata COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/test_native_metadata.py $<TARGET_FILE:native_metadata_probe>
        $<TARGET_FILE:native_metadata_module>)
endif()
add_test(NAME stacktrace_stability COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_stacktrace_stability.py $<TARGET_FILE:stacktrace_probe>)

if(WIN32)
    add_executable(windows_crash_tests windows_crash_tests.cpp windows_crash_other.cpp)
    target_include_directories(windows_crash_tests PRIVATE ../include)
    target_link_libraries(windows_crash_tests PRIVATE psapi shell32)
    add_test(NAME windows_crash_tests COMMAND windows_crash_tests)
    set_tests_properties(windows_crash_tests PROPERTIES TIMEOUT 60)
endif()
