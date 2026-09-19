#include <cassert>
#include <cstdint>
#include <cstring>

#include <sodium.h>

#include "../components/beszel/crypto.h"

static uint8_t decode_hex(char c) {
  return c <= '9' ? c - '0' : c - 'a' + 10;
}

static void from_hex(const char *text, uint8_t *out, size_t size) {
  for (size_t i = 0; i < size; i++) out[i] = uint8_t(decode_hex(text[i * 2]) << 4 | decode_hex(text[i * 2 + 1]));
}

int main() {
  // Match production's requirement instead of relying on desktop libsodium
  // having been initialized by unrelated process code.
  assert(esphome::beszel::initialize_crypto());

  uint8_t public_key[32], signature[64];
  from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", public_key, sizeof(public_key));
  from_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" \
           "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", signature, sizeof(signature));
  assert(esphome::beszel::verify_ed25519(signature, nullptr, 0, public_key));
  signature[0] ^= 1;
  assert(!esphome::beszel::verify_ed25519(signature, nullptr, 0, public_key));

  uint8_t seed[crypto_sign_SEEDBYTES]{}, generated_public_key[crypto_sign_PUBLICKEYBYTES], private_key[crypto_sign_SECRETKEYBYTES];
  for (size_t i = 0; i < sizeof(seed); i++) seed[i] = uint8_t(i);
  assert(crypto_sign_seed_keypair(generated_public_key, private_key, seed) == 0);
  uint8_t token[] = "test-token";
  uint8_t token_signature[crypto_sign_BYTES]; unsigned long long signature_length;
  assert(crypto_sign_detached(token_signature, &signature_length, token, sizeof(token) - 1, private_key) == 0);
  assert(signature_length == sizeof(token_signature));
  assert(esphome::beszel::verify_ed25519(token_signature, token, sizeof(token) - 1, generated_public_key));
  token[0] ^= 1;
  assert(!esphome::beszel::verify_ed25519(token_signature, token, sizeof(token) - 1, generated_public_key));
  token[0] ^= 1;
  generated_public_key[0] ^= 1;
  assert(!esphome::beszel::verify_ed25519(token_signature, token, sizeof(token) - 1, generated_public_key));

  uint8_t go_public_key[32], go_signature[64];
  from_hex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", go_public_key,
           sizeof(go_public_key));
  from_hex("9cee02da0eddbb8c6c72ed5498520ba11d5502891d5c0403d9236fe26a6f2451"
           "759d2bb228f3fa12586aaf10c607e17095e1acd50d01a6c9f5cd7584d138ed02",
           go_signature, sizeof(go_signature));
  assert(esphome::beszel::verify_ed25519(go_signature, token, sizeof(token) - 1, go_public_key));

  const uint8_t mac_a[] = {0, 1, 2, 3, 4, 5};
  const uint8_t mac_b[] = {0, 1, 2, 3, 4, 6};
  auto fingerprint_a = esphome::beszel::factory_mac_fingerprint(mac_a);
  assert(fingerprint_a.size() == 64);
  assert(fingerprint_a == esphome::beszel::factory_mac_fingerprint(mac_a));
  assert(fingerprint_a != esphome::beszel::factory_mac_fingerprint(mac_b));
}
