# Basic example
add_executable(basic basic.cpp)
target_link_libraries(basic PRIVATE posthog)

# Crash handler example
add_executable(crash crash.cpp)
target_link_libraries(crash PRIVATE posthog)
