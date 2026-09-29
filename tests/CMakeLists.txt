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
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME stacktrace_stability COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_stacktrace_stability.py $<TARGET_FILE:stacktrace_probe>)
