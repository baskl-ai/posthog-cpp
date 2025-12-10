cmake_minimum_required(VERSION 3.16)
project(posthog-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(POSTHOG_USE_CURL "Use libcurl for HTTP requests" ON)
option(POSTHOG_BUILD_EXAMPLES "Build example applications" OFF)
option(POSTHOG_USE_BUNDLED_JSON "Use bundled nlohmann/json (disable if parent project provides it)" ON)

# Library sources
set(POSTHOG_SOURCES
    src/posthog.cpp
)

set(POSTHOG_HEADERS
    include/posthog/posthog.h
    include/posthog/machine_id.h
    include/posthog/stacktrace.h
    include/posthog/crash_handler.h
)

# Create library
add_library(posthog STATIC ${POSTHOG_SOURCES} ${POSTHOG_HEADERS})
add_library(PostHog::posthog ALIAS posthog)

target_include_directories(posthog
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# nlohmann/json handling
if(POSTHOG_USE_BUNDLED_JSON)
    # Use bundled json.hpp from include/nlohmann/
    message(STATUS "PostHog: Using bundled nlohmann/json")
else()
    # Parent project must provide nlohmann/json include path
    message(STATUS "PostHog: Using external nlohmann/json (parent project provides it)")
endif()

# Platform-specific settings
if(WIN32)
    target_link_libraries(posthog PRIVATE dbghelp)
    target_compile_definitions(posthog PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(APPLE)
    # macOS needs no extra libs for backtrace
else()
    # Linux may need -ldl for dladdr
    target_link_libraries(posthog PRIVATE dl)
endif()

# Optional: libcurl
if(POSTHOG_USE_CURL)
    find_package(CURL QUIET)
    if(CURL_FOUND)
        target_link_libraries(posthog PRIVATE CURL::libcurl)
        target_compile_definitions(posthog PRIVATE POSTHOG_USE_CURL)
        message(STATUS "PostHog: Using libcurl for HTTP")
    else()
        message(STATUS "PostHog: libcurl not found, HTTP disabled (events logged to console)")
    endif()
endif()

# Examples
if(POSTHOG_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation
include(GNUInstallDirs)

install(TARGETS posthog
    EXPORT posthog-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/posthog
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT posthog-targets
    FILE posthog-targets.cmake
    NAMESPACE PostHog::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/posthog
)

# Package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/posthog-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/posthog-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/posthog
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/posthog-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/posthog-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/posthog-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/posthog
)
