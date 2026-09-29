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
