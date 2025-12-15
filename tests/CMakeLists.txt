# Unit tests (no network required)
add_executable(unit_tests unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE posthog)

enable_testing()
add_test(NAME unit_tests COMMAND unit_tests)

# Basic example (requires API key)
add_executable(basic basic.cpp)
target_link_libraries(basic PRIVATE posthog)

# Crash handler example (requires API key)
add_executable(crash crash.cpp)
target_link_libraries(crash PRIVATE posthog)
