/**
 * @file test_mac_id.cpp
 * @brief Test MAC-based ID generation matches Python algorithm
 */

#include <iostream>
#include <iomanip>
#include "posthog/machine_id.h"

int main() {
    std::cout << "=== Testing MAC-based ID generation ===" << std::endl;

    // Get MAC address
    uint64_t mac = PostHog::MachineID::getMacAddressAsNumber();
    std::cout << "MAC address (number): " << mac << std::endl;
    std::cout << "MAC address (hex): 0x" << std::hex << mac << std::dec << std::endl;

    // Show byte extraction (Python's quirky algorithm)
    std::cout << "\nByte extraction (shift by 0,2,4,6,8,10 bits):" << std::endl;
    for (int shift = 0; shift < 12; shift += 2) {
        uint8_t byte = (mac >> shift) & 0xff;
        std::cout << "  (mac >> " << shift << ") & 0xff = " << static_cast<int>(byte)
                  << " = 0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte)
                  << std::dec << std::endl;
    }

    // Generate hashed ID
    std::string hashedId = PostHog::MachineID::getHashedMacId();
    std::cout << "\nGenerated hashed MAC ID: " << hashedId << std::endl;

    std::cout << "\n=== Compare with Python output ===" << std::endl;
    std::cout << "Run this Python code and compare:" << std::endl;
    std::cout << "import uuid, hashlib" << std::endl;
    std::cout << "node = uuid.getnode()" << std::endl;
    std::cout << "mac = ':'.join(['{:02x}'.format((node >> e) & 0xff) for e in range(0, 12, 2)][::-1])" << std::endl;
    std::cout << "print(str(uuid.UUID(hashlib.sha256(mac.encode()).hexdigest()[:32])))" << std::endl;

    return 0;
}
