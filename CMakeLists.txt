cmake_minimum_required(VERSION 3.16)
project(posthog-cpp VERSION 1.4.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(POSTHOG_USE_CURL "Use libcurl for HTTP requests" ON)
option(POSTHOG_BUILD_TESTS "Build test applications" OFF)

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

# nlohmann/json: bundled in include/nlohmann/
# JSON_SKIP_LIBRARY_VERSION_CHECK is defined in posthog.cpp to avoid
# version mismatch warnings if parent project uses different version

# Pass library version to code
target_compile_definitions(posthog PRIVATE
    POSTHOG_VERSION="${PROJECT_VERSION}"
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(posthog PRIVATE dbghelp iphlpapi)
    target_compile_definitions(posthog PRIVATE
        _CRT_SECURE_NO_WARNINGS
        # Windows-specific compiler flags
        # _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR: Fix for VS2022 17.10+ breaking change with std::mutex
        # See: https://github.com/microsoft/STL/issues/4730
        _DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR
    )
elseif(APPLE)
    # macOS needs no extra libs for backtrace
else()
    # Linux may need -ldl for dladdr
    target_link_libraries(posthog PRIVATE dl)
endif()

# Optional: libcurl
if(POSTHOG_USE_CURL)
    # Check if libcurl_static target exists (from FetchContent in parent project)
    if(TARGET libcurl_static)
        target_link_libraries(posthog PRIVATE libcurl_static)
        target_compile_definitions(posthog PRIVATE POSTHOG_USE_CURL)
        message(STATUS "PostHog: Using libcurl (FetchContent)")
    else()
        # Try to find system libcurl
        find_package(CURL QUIET)
        if(CURL_FOUND)
            target_link_libraries(posthog PRIVATE CURL::libcurl)
            target_compile_definitions(posthog PRIVATE POSTHOG_USE_CURL)
            message(STATUS "PostHog: Using libcurl (system)")
        else()
            message(STATUS "PostHog: libcurl not found, HTTP disabled (events logged to console)")
        endif()
    endif()
endif()

# Tests
if(POSTHOG_BUILD_TESTS)
    # Fetch curl for tests only if POSTHOG_USE_CURL is ON and no curl target exists
    if(POSTHOG_USE_CURL AND NOT TARGET libcurl_static AND NOT TARGET CURL::libcurl)
        message(STATUS "PostHog Tests: Fetching libcurl via FetchContent")
        include(FetchContent)
        FetchContent_Declare(
            curl
            URL https://github.com/curl/curl/releases/download/curl-8_5_0/curl-8.5.0.tar.gz
        )
        set(BUILD_CURL_EXE OFF CACHE INTERNAL "")
        set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
        set(BUILD_TESTING OFF CACHE INTERNAL "")
        set(CURL_DISABLE_FTP ON CACHE INTERNAL "")
        set(CURL_DISABLE_LDAP ON CACHE INTERNAL "")
        set(CURL_USE_LIBSSH2 OFF CACHE INTERNAL "")
        if(APPLE)
            set(CURL_USE_SECTRANSP ON CACHE INTERNAL "")
            set(CURL_USE_OPENSSL OFF CACHE INTERNAL "")
        elseif(WIN32)
            set(CURL_USE_SCHANNEL ON CACHE INTERNAL "")
            set(CURL_USE_OPENSSL OFF CACHE INTERNAL "")
        else()
            set(CURL_USE_OPENSSL ON CACHE INTERNAL "")
        endif()
        FetchContent_MakeAvailable(curl)

        # Now libcurl_static target exists, link it to posthog
        if(TARGET libcurl_static)
            target_link_libraries(posthog PRIVATE libcurl_static)
            target_compile_definitions(posthog PRIVATE POSTHOG_USE_CURL)
            message(STATUS "PostHog: Using libcurl for tests (FetchContent)")
        endif()
    endif()

    add_subdirectory(tests)
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
