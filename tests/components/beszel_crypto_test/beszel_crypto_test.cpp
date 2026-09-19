#include "beszel_crypto_test.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "esphome/components/beszel/crypto.h"
#include "esphome/core/log.h"

namespace esphome::beszel_crypto_test {

static const char *const TAG = "beszel.crypto_test";

namespace {

uint8_t hex_nibble(char value) { return value <= '9' ? value - '0' : value - 'a' + 10; }

template<size_t N> std::array<uint8_t, N> from_hex(const char *text) {
  std::array<uint8_t, N> result{};
  for (size_t i = 0; i < N; i++)
    result[i] = static_cast<uint8_t>((hex_nibble(text[i * 2]) << 4) | hex_nibble(text[i * 2 + 1]));
  return result;
}

}  // namespace

void BeszelCryptoTest::setup() {
  const auto public_key = from_hex<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
  const auto signature = from_hex<64>(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
  const uint8_t message[] = {0x72};

  bool passed = true;
  const auto expect = [&passed](bool condition, const char *name) {
    if (!condition) {
      ESP_LOGE(TAG, "FAIL: %s", name);
      passed = false;
    }
  };
  expect(esphome::beszel::initialize_crypto(), "crypto initialization");
  expect(esphome::beszel::verify_ed25519(signature.data(), message, sizeof(message), public_key.data()),
         "RFC 8032 valid signature");

  auto modified_message = message[0];
  modified_message ^= 1;
  expect(!esphome::beszel::verify_ed25519(signature.data(), &modified_message, 1, public_key.data()),
         "modified message rejection");

  auto modified_signature = signature;
  modified_signature[0] ^= 1;
  expect(!esphome::beszel::verify_ed25519(modified_signature.data(), message, sizeof(message), public_key.data()),
         "modified signature rejection");

  auto noncanonical_s = signature;
  const auto group_order = from_hex<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
  memcpy(noncanonical_s.data() + 32, group_order.data(), group_order.size());
  expect(!esphome::beszel::verify_ed25519(noncanonical_s.data(), message, sizeof(message), public_key.data()),
         "non-canonical signature scalar rejection");

  auto noncanonical_r = signature;
  const auto field_prime = from_hex<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
  memcpy(noncanonical_r.data(), field_prime.data(), field_prime.size());
  expect(!esphome::beszel::verify_ed25519(noncanonical_r.data(), message, sizeof(message), public_key.data()),
         "non-canonical signature point rejection");
  expect(!esphome::beszel::verify_ed25519(signature.data(), message, sizeof(message), field_prime.data()),
         "non-canonical public key rejection");

  std::array<uint8_t, 32> identity_key{};
  identity_key[0] = 1;
  expect(!esphome::beszel::verify_ed25519(signature.data(), message, sizeof(message), identity_key.data()),
         "identity public key rejection");
  const std::array<uint8_t, 32> zero_key{};
  expect(!esphome::beszel::verify_ed25519(signature.data(), message, sizeof(message), zero_key.data()),
         "zero public key rejection");

  if (passed) {
    ESP_LOGI(TAG, "PASS: embedded Ed25519 verifier accepted the RFC 8032 vector and rejected all invalid inputs");
  } else {
    this->mark_failed();
  }
}

}  // namespace esphome::beszel_crypto_test
