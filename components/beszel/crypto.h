#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace esphome::beszel {

bool initialize_crypto();
bool verify_ed25519(const uint8_t signature[64], const uint8_t *message, size_t length,
                    const uint8_t public_key[32]);
std::string factory_mac_fingerprint(const uint8_t mac[6]);

}  // namespace esphome::beszel
