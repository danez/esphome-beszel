#include "crypto.h"

#include <cstring>

#include <sodium.h>

namespace esphome::beszel {

bool initialize_crypto() {
#ifdef USE_ESP32
  // ESPHome's reduced ESP-IDF port has no usable sysrandom backend, so
  // sodium_init() deliberately aborts while trying to initialize randomness.
  // Beszel only hashes and verifies signatures; those deterministic primitives
  // have no global or random initialization requirement in this port.
  return true;
#else
  // The complete desktop library supports normal global initialization. Both
  // first initialization (0) and already initialized (1) are successful.
  return sodium_init() >= 0;
#endif
}

bool verify_ed25519(const uint8_t signature[64], const uint8_t *message, size_t length,
                    const uint8_t public_key[32]) {
#ifdef USE_ESP32
  // ESPHome's embedded package omits the generic crypto_sign wrapper. The
  // pinned verifier translation unit supplies this public Ed25519 entry point.
  return crypto_sign_ed25519_verify_detached(signature, message, static_cast<unsigned long long>(length), public_key) == 0;
#else
  // Desktop tests use the complete system libsodium API.
  return crypto_sign_verify_detached(signature, message, static_cast<unsigned long long>(length), public_key) == 0;
#endif
}

std::string factory_mac_fingerprint(const uint8_t mac[6]) {
  // The NUL is part of the domain separator defined by the protocol; it is not
  // merely a C-string terminator and must be hashed with the MAC.
  static constexpr uint8_t prefix[] = {'e', 's', 'p', 'h', 'o', 'm', 'e', '-', 'b', 'e', 's', 'z', 'e', 'l', '\0'};
  uint8_t input[sizeof(prefix) + 6];
  memcpy(input, prefix, sizeof(prefix));
  memcpy(input + sizeof(prefix), mac, 6);
  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, input, sizeof(input));
  static constexpr char hex[] = "0123456789abcdef";
  std::string result;
  result.reserve(64);
  for (uint8_t byte : digest) {
    result += hex[byte >> 4];
    result += hex[byte & 0x0f];
  }
  return result;
}

}  // namespace esphome::beszel
