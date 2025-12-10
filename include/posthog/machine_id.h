/**
 * @file machine_id.h
 * @brief Cross-platform machine ID retrieval (header-only)
 *
 * Supports:
 * - macOS: IOPlatformUUID via system_profiler
 * - Windows: MachineGuid from registry
 * - Linux: /etc/machine-id or /var/lib/dbus/machine-id
 */

#ifndef POSTHOG_MACHINE_ID_H
#define POSTHOG_MACHINE_ID_H

#include <string>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#elif __APPLE__
#include <unistd.h>
#else
#include <fstream>
#endif

namespace PostHog {
namespace MachineID {

/**
 * @brief Get unique hardware machine ID for this computer
 * @return Machine ID string (UUID format on macOS/Windows, hex string on Linux)
 *
 * macOS: Returns IOPlatformUUID (e.g., "12345678-ABCD-...")
 * Windows: Returns MachineGuid from registry (e.g., "12345678-ABCD-...")
 * Linux: Returns /etc/machine-id content (32-char hex)
 */
inline std::string get() {
#ifdef __APPLE__
    // macOS: Use system_profiler to get IOPlatformUUID (hardware UUID)
    FILE* pipe = popen("system_profiler SPHardwareDataType 2>/dev/null | grep 'Hardware UUID' | awk '{print $3}'", "r");
    if (!pipe) {
        return "";
    }

    char buffer[256];
    std::string result;

    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result = buffer;
        // Remove trailing newline
        if (!result.empty() && result.back() == '\n') {
            result.pop_back();
        }
    }

    pclose(pipe);
    return result;

#elif _WIN32
    // Windows: Read MachineGuid from registry
    // Location: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid

    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        return "";
    }

    char buffer[256];
    DWORD bufferSize = sizeof(buffer);
    DWORD type;

    result = RegQueryValueExA(
        hKey,
        "MachineGuid",
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer),
        &bufferSize
    );

    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_SZ) {
        return std::string(buffer);
    }

    return "";

#else
    // Linux: Read /etc/machine-id (systemd) or /var/lib/dbus/machine-id (older)
    std::ifstream file("/etc/machine-id");
    if (!file.is_open()) {
        file.open("/var/lib/dbus/machine-id");
    }

    if (!file.is_open()) {
        return "";
    }

    std::string machineId;
    std::getline(file, machineId);
    file.close();

    // Remove any whitespace
    machineId.erase(std::remove_if(machineId.begin(), machineId.end(), ::isspace), machineId.end());

    return machineId;
#endif
}

/**
 * @brief Get machine ID with fallback to persistent file
 * @param fallbackPath Path to store fallback ID if hardware ID unavailable
 * @return Machine ID string (empty if all methods fail)
 */
inline std::string getWithFallback(const std::string& fallbackPath = "") {
    std::string hwId = get();

    if (!hwId.empty()) {
        return hwId;
    }

    // Hardware ID failed - use fallback file if provided
    if (!fallbackPath.empty()) {
        std::ifstream inFile(fallbackPath);
        if (inFile.is_open()) {
            std::string fallbackId;
            std::getline(inFile, fallbackId);
            inFile.close();

            if (!fallbackId.empty()) {
                return fallbackId;
            }
        }
    }

    return "";
}

} // namespace MachineID
} // namespace PostHog

#endif // POSTHOG_MACHINE_ID_H
