/**
 * @file machine_id.h
 * @brief Cross-platform machine ID generation (header-only)
 *
 * Generates unique machine ID from MAC address using SHA256 hash.
 * Algorithm is compatible with Python's uuid.getnode().
 */

#ifndef POSTHOG_MACHINE_ID_H
#define POSTHOG_MACHINE_ID_H

#include <string>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <picosha2.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#endif

namespace PostHog {
namespace MachineID {

/**
 * @brief Get MAC address as 48-bit number (like Python's uuid.getnode())
 * @return MAC address as uint64_t, 0 if failed
 *
 * Returns the MAC address of the first non-loopback network interface.
 */
inline uint64_t getMacAddressAsNumber() {
#ifdef _WIN32
    // Windows: Use GetAdaptersAddresses
    ULONG bufferSize = 15000;
    std::vector<char> buffer(bufferSize);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    ULONG result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addresses, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addresses, &bufferSize);
    }

    if (result != NO_ERROR) {
        return 0;
    }

    for (PIP_ADAPTER_ADDRESSES adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->PhysicalAddressLength == 6) {
            uint64_t mac = 0;
            for (int i = 0; i < 6; i++) {
                mac |= static_cast<uint64_t>(adapter->PhysicalAddress[i]) << (8 * (5 - i));
            }
            if (mac != 0) {
                return mac;
            }
        }
    }
    return 0;

#elif defined(__APPLE__)
    // macOS: Use getifaddrs with AF_LINK
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        return 0;
    }

    uint64_t mac = 0;
    for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;

        struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
        if (sdl->sdl_alen != 6) continue;

        unsigned char* macBytes = reinterpret_cast<unsigned char*>(LLADDR(sdl));

        // Skip zero MAC addresses
        bool allZero = true;
        for (int i = 0; i < 6; i++) {
            if (macBytes[i] != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) continue;

        // Convert to uint64_t (big-endian, MSB first)
        for (int i = 0; i < 6; i++) {
            mac |= static_cast<uint64_t>(macBytes[i]) << (8 * (5 - i));
        }
        break;
    }

    freeifaddrs(ifap);
    return mac;

#else
    // Linux: Use getifaddrs with AF_PACKET
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) {
        return 0;
    }

    uint64_t mac = 0;
    for (struct ifaddrs* ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

        struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen != 6) continue;

        // Skip zero MAC addresses
        bool allZero = true;
        for (int i = 0; i < 6; i++) {
            if (sll->sll_addr[i] != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) continue;

        // Convert to uint64_t (big-endian, MSB first)
        for (int i = 0; i < 6; i++) {
            mac |= static_cast<uint64_t>(sll->sll_addr[i]) << (8 * (5 - i));
        }
        break;
    }

    freeifaddrs(ifap);
    return mac;
#endif
}

/**
 * @brief Generate hashed ID from MAC address number (for testing)
 * @param node MAC address as 48-bit number
 * @return UUID-formatted string
 */
inline std::string getHashedMacIdFromNode(uint64_t node) {
    if (node == 0) {
        return "";
    }

    // Extract bytes with Python-compatible bit shifts
    std::vector<std::string> bytes;
    for (int shift = 0; shift < 12; shift += 2) {
        uint8_t byte = (node >> shift) & 0xff;
        std::ostringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        bytes.push_back(ss.str());
    }

    // Reverse and join with ':'
    std::ostringstream macStream;
    for (int i = static_cast<int>(bytes.size()) - 1; i >= 0; i--) {
        macStream << bytes[i];
        if (i > 0) macStream << ':';
    }
    std::string macAddress = macStream.str();

    // SHA256 hash
    std::string hashHex = picosha2::hash256_hex_string(macAddress);

    // Format as UUID
    if (hashHex.length() < 32) {
        return "";
    }

    std::ostringstream uuid;
    uuid << hashHex.substr(0, 8) << '-'
         << hashHex.substr(8, 4) << '-'
         << hashHex.substr(12, 4) << '-'
         << hashHex.substr(16, 4) << '-'
         << hashHex.substr(20, 12);

    return uuid.str();
}

/**
 * @brief Generate hashed MAC ID (Python uuid.getnode() compatible)
 * @return UUID-formatted string (e.g., "5da68340-5f4e-b9d1-f2db-f1533b85c877")
 *
 * Algorithm compatible with Python's uuid.getnode() + SHA256 hashing.
 * Generates deterministic ID from network adapter MAC address.
 */
inline std::string getHashedMacId() {
    return getHashedMacIdFromNode(getMacAddressAsNumber());
}

/**
 * @brief Get hashed MAC ID with fallback to file storage
 * @param fallbackPath Path to store/read ID (for persistence across MAC changes)
 * @return UUID-formatted string
 *
 * If fallbackPath exists, reads ID from file.
 * Otherwise generates new ID and saves to file.
 */
inline std::string getHashedMacIdWithFallback(const std::string& fallbackPath) {
    // Try to read existing ID from file
    if (!fallbackPath.empty()) {
        std::ifstream inFile(fallbackPath);
        if (inFile.is_open()) {
            std::string existingId;
            std::getline(inFile, existingId);
            inFile.close();

            // Trim whitespace
            existingId.erase(0, existingId.find_first_not_of(" \t\n\r"));
            existingId.erase(existingId.find_last_not_of(" \t\n\r") + 1);

            if (!existingId.empty()) {
                return existingId;
            }
        }
    }

    // Generate new ID
    std::string newId = getHashedMacId();
    if (newId.empty()) {
        return "";
    }

    // Save to file if path provided
    if (!fallbackPath.empty()) {
        std::ofstream outFile(fallbackPath);
        if (outFile.is_open()) {
            outFile << newId;
            outFile.close();
        }
    }

    return newId;
}

} // namespace MachineID
} // namespace PostHog

#endif // POSTHOG_MACHINE_ID_H
