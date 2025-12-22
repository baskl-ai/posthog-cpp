/**
 * @file test_internal_user.cpp
 * @brief Test internal user detection via marker file and environment variable
 *
 * Tests the ability to filter analytics by internal/external users using:
 * 1. Marker file: ~/.bskl_internal
 * 2. Environment variable: BSKL_INTERNAL_USER=1
 *
 * Usage:
 *   ./test_internal_user
 */

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/**
 * @brief Check if current machine is an internal user
 * @details Mirrors the implementation in Client/AIM_Analytics.cpp
 */
static bool isInternalUser() {
    // Check environment variable first
    const char* env = std::getenv("BSKL_INTERNAL_USER");
    if (env && std::string(env) == "1") {
        return true;
    }

    // Check for marker file in home directory
    std::string home_dir;

#ifdef _WIN32
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        home_dir = userprofile;
    }
#else
    const char* home = std::getenv("HOME");
    if (home) {
        home_dir = home;
    }
#endif

    if (home_dir.empty()) {
        return false;
    }

    std::string marker_path = home_dir;
#ifdef _WIN32
    marker_path += "\\.bskl_internal";
#else
    marker_path += "/.bskl_internal";
#endif

    // Check if file exists
    std::ifstream file(marker_path);
    return file.good();
}

int main() {
    std::cout << "=== Internal User Detection Test ===" << std::endl;

    // Test 1: Check current status
    std::cout << "\n[Test 1] Current internal user status:" << std::endl;
    bool is_internal = isInternalUser();
    std::cout << "  is_internal_user: " << (is_internal ? "true" : "false") << std::endl;

    // Show marker file path
    std::string home_dir;
#ifdef _WIN32
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) home_dir = userprofile;
    std::string marker_path = home_dir + "\\.bskl_internal";
#else
    const char* home = std::getenv("HOME");
    if (home) home_dir = home;
    std::string marker_path = home_dir + "/.bskl_internal";
#endif

    std::cout << "  Marker file path: " << marker_path << std::endl;

    std::ifstream marker_file(marker_path);
    std::cout << "  Marker file exists: " << (marker_file.good() ? "yes" : "no") << std::endl;
    marker_file.close();

    // Test 2: Environment variable override
    std::cout << "\n[Test 2] Environment variable override:" << std::endl;
    const char* env = std::getenv("BSKL_INTERNAL_USER");
    if (env) {
        std::cout << "  BSKL_INTERNAL_USER=" << env << std::endl;
        std::cout << "  Override active: " << (std::string(env) == "1" ? "yes" : "no") << std::endl;
    } else {
        std::cout << "  BSKL_INTERNAL_USER not set" << std::endl;
        std::cout << "  To test override: export BSKL_INTERNAL_USER=1" << std::endl;
    }

    // Test 3: Instructions for creating marker
    std::cout << "\n[Test 3] How to mark this machine as internal user:" << std::endl;
#ifdef _WIN32
    std::cout << "  Windows: type nul > %USERPROFILE%\\.bskl_internal" << std::endl;
#else
    std::cout << "  macOS/Linux: touch ~/.bskl_internal" << std::endl;
#endif

    // Test 4: Instructions for removing marker
    std::cout << "\n[Test 4] How to mark this machine as external user:" << std::endl;
#ifdef _WIN32
    std::cout << "  Windows: del %USERPROFILE%\\.bskl_internal" << std::endl;
#else
    std::cout << "  macOS/Linux: rm ~/.bskl_internal" << std::endl;
#endif

    // Summary
    std::cout << "\n=== Summary ===" << std::endl;
    if (is_internal) {
        std::cout << "✓ This machine is configured as INTERNAL user" << std::endl;
        std::cout << "  Analytics events will be tagged with is_internal_user=true" << std::endl;
        std::cout << "  Filter in PostHog dashboard: is_internal_user != true" << std::endl;
    } else {
        std::cout << "✓ This machine is configured as EXTERNAL user" << std::endl;
        std::cout << "  Analytics events will be tagged with is_internal_user=false" << std::endl;
        std::cout << "  Events will appear in normal analytics" << std::endl;
    }

    return 0;
}
