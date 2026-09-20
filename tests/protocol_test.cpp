#include <cassert>
#include <cstdint>
#include <string>
#include <type_traits>

#include "../components/beszel/cbor.h"
#include "fixtures/protocol_fixtures.h"

static std::string hex_bytes(const char *hex) {
  std::string result;
  for (size_t i = 0; hex[i]; i += 2) result.push_back(static_cast<char>(std::stoi(std::string(hex + i, 2), nullptr, 16)));
  return result;
}

static void request_fixtures_decode() {
  using esphome::beszel::HubRequest;
  HubRequest request;
  auto check = hex_bytes(beszel::test_fixtures::check_fingerprint_true);
  assert(esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(check.data()), check.size(), request));
  assert(request.action == 1 && request.request_id == 7 && request.need_sys_info && request.has_signature);
  auto check_without_info = hex_bytes(beszel::test_fixtures::check_fingerprint_false);
  request = {};
  assert(esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(check_without_info.data()), check_without_info.size(), request));
  assert(request.action == 1 && request.request_id == 7 && !request.need_sys_info);
  auto get = hex_bytes(beszel::test_fixtures::get_data);
  request = {};
  assert(esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(get.data()), get.size(), request));
  assert(request.action == 0 && request.request_id == 42 && request.cache_time_ms == 1500 && request.include_details);
}

static void malformed_fixtures_fail() {
  uint8_t output[256]{};
  esphome::beszel::HubRequest empty_request;
  assert(!esphome::beszel::decode_hub_request(output, 0, empty_request));
  assert(!esphome::beszel::encode_error_response(output, 4, 42, "too large"));
  auto bytes = hex_bytes(beszel::test_fixtures::get_data);
  esphome::beszel::HubRequest request;
  assert(!esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(bytes.data()), bytes.size() - 1, request));

  const auto short_signature = hex_bytes("a2000101a10041aa");
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(short_signature.data()), short_signature.size(), request));
  std::string long_signature = hex_bytes("a2000101a1005841");
  long_signature.append(65, '\0');
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(long_signature.data()), long_signature.size(), request));

  assert(esphome::beszel::encode_fingerprint_response(output, sizeof(output), 7,
                                                       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                                       "esp32-lab", "ESPHome lab node"));
  auto expected = hex_bytes(beszel::test_fixtures::fingerprint_response);
  assert(std::string(reinterpret_cast<char *>(output), expected.size()) == expected);

  assert(esphome::beszel::encode_fingerprint_response(output, sizeof(output), 7,
                                                       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                                       "esp32-lab", "esp32-lab"));
  expected = hex_bytes(beszel::test_fixtures::universal_identity_response);
  assert(std::string(reinterpret_cast<char *>(output), expected.size()) == expected);

  assert(esphome::beszel::encode_error_response(output, sizeof(output), 42, "request not supported"));
  expected = hex_bytes(beszel::test_fixtures::error_response);
  assert(std::string(reinterpret_cast<char *>(output), expected.size()) == expected);

  assert(esphome::beszel::encode_error_response(output, sizeof(output), 42, "authentication required"));
  expected = hex_bytes(beszel::test_fixtures::authentication_required_response);
  assert(std::string(reinterpret_cast<char *>(output), expected.size()) == expected);

}

static esphome::beszel::SystemMetrics populated_metrics() {
  esphome::beszel::SystemMetrics metrics;
  metrics.total_heap = 1073741824ULL;
  metrics.free_heap = 268435456ULL;
  metrics.flash_size = 4 * 1024 * 1024;
  metrics.flash_used = 1024 * 1024;
  metrics.uptime_seconds = 123456;
  metrics.hostname = "esp32-lab";
  metrics.idf_version = "v5.5.5";
  metrics.chip_model = "ESP32";
  metrics.esphome_version = "ESPHome 2026.8.2";
  metrics.cores = 2;
  return metrics;
}

static void populated_data_response() {
  uint8_t output[512]{};
  size_t written = 0;
  auto metrics = populated_metrics();
  assert(esphome::beszel::encode_data_response(output, sizeof(output), 42, metrics, &written));
  const auto expected = hex_bytes(beszel::test_fixtures::populated_data_response);
  assert(written == expected.size());
  assert(std::string(reinterpret_cast<char *>(output), written) == expected);
  assert(!esphome::beszel::encode_data_response(output, 4, 42, metrics));

  metrics.architecture = "riscv";
  assert(esphome::beszel::encode_data_response(output, sizeof(output), 42, metrics, &written));
  const std::string riscv_response(reinterpret_cast<char *>(output), written);
  assert(riscv_response.find("riscv") != std::string::npos);
  assert(riscv_response.find("xtensa") == std::string::npos);

  // Invalid free-heap values are clamped to zero used memory. Comparing them
  // with their valid zero-used counterparts also catches NaN or underflow.
  uint8_t valid[512]{};
  uint8_t invalid[512]{};
  size_t valid_size = 0;
  size_t invalid_size = 0;
  metrics.total_heap = 0;
  metrics.free_heap = 0;
  assert(esphome::beszel::encode_data_response(valid, sizeof(valid), 42, metrics, &valid_size));
  metrics.free_heap = UINT64_MAX;
  assert(esphome::beszel::encode_data_response(invalid, sizeof(invalid), 42, metrics, &invalid_size));
  assert(valid_size == invalid_size);
  assert(std::string(reinterpret_cast<char *>(valid), valid_size) ==
         std::string(reinterpret_cast<char *>(invalid), invalid_size));

  metrics.total_heap = 100;
  metrics.free_heap = 100;
  assert(esphome::beszel::encode_data_response(valid, sizeof(valid), 42, metrics, &valid_size));
  metrics.free_heap = 101;
  assert(esphome::beszel::encode_data_response(invalid, sizeof(invalid), 42, metrics, &invalid_size));
  assert(valid_size == invalid_size);
  assert(std::string(reinterpret_cast<char *>(valid), valid_size) ==
         std::string(reinterpret_cast<char *>(invalid), invalid_size));

  metrics.flash_size = 100;
  metrics.flash_used = 0;
  assert(esphome::beszel::encode_data_response(valid, sizeof(valid), 42, metrics, &valid_size));
  metrics.flash_used = 101;
  assert(esphome::beszel::encode_data_response(invalid, sizeof(invalid), 42, metrics, &invalid_size));
  assert(valid_size == invalid_size);
  assert(std::string(reinterpret_cast<char *>(valid), valid_size) ==
         std::string(reinterpret_cast<char *>(invalid), invalid_size));
}

static void temperature_data_response() {
  uint8_t output[512]{};
  size_t written = 0;
  auto metrics = populated_metrics();
  metrics.has_temperature = true;
  metrics.temperature = 42.5;
  assert(esphome::beszel::encode_data_response(output, sizeof(output), 42, metrics, &written));
  const auto expected = hex_bytes(beszel::test_fixtures::temperature_data_response);
  assert(written == expected.size());
  assert(std::string(reinterpret_cast<char *>(output), written) == expected);
}

static void tolerant_unknown_keys_and_strict_types() {
  const std::string unknown = hex_bytes(
      "a4000101a3005840000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01f509f4020709f4");
  esphome::beszel::HubRequest request;
  assert(esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(unknown.data()), unknown.size(), request));

  const std::string wrong_type = hex_bytes("a100fb0000000000000000");
  assert(!esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(wrong_type.data()), wrong_type.size(), request));
  const std::string overflowing_id = hex_bytes("a1021b0000000100000000");
  assert(!esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(overflowing_id.data()), overflowing_id.size(), request));
  const std::string overflowing_cache = hex_bytes("a20100a1001b0000000100000000");
  assert(!esphome::beszel::decode_hub_request(reinterpret_cast<const uint8_t *>(overflowing_cache.data()), overflowing_cache.size(), request));
}

static void map_order_and_duplicate_keys() {
  using esphome::beszel::HubRequest;

  const std::string fingerprint_data_first = hex_bytes(
      "a301a2005840000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01f502070001");
  HubRequest request;
  assert(esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(fingerprint_data_first.data()), fingerprint_data_first.size(), request));
  assert(request.action == 1 && request.request_id == 7 && request.need_sys_info && request.has_signature);
  for (size_t i = 0; i < 1000; i++) {
    assert(esphome::beszel::decode_hub_request(
        reinterpret_cast<const uint8_t *>(fingerprint_data_first.data()), fingerprint_data_first.size(), request));
  }

  const std::string get_data_action_last = hex_bytes("a301a2001905dc01f502182a0000");
  assert(esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(get_data_action_last.data()), get_data_action_last.size(), request));
  assert(request.action == 0 && request.request_id == 42 && request.cache_time_ms == 1500 && request.include_details);

  const std::string duplicate_action = hex_bytes("a200000001");
  request.action = 99;
  request.signature.fill(1);
  request.has_signature = true;
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(duplicate_action.data()), duplicate_action.size(), request));
  assert(request.action == 0 && !request.has_signature);

  const std::string duplicate_data = hex_bytes("a3000001a001a0");
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(duplicate_data.data()), duplicate_data.size(), request));

  const std::string duplicate_request_id = hex_bytes("a3000002010202");
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(duplicate_request_id.data()), duplicate_request_id.size(), request));

  const std::string duplicate_inner_key = hex_bytes("a2000001a200010002");
  assert(!esphome::beszel::decode_hub_request(
      reinterpret_cast<const uint8_t *>(duplicate_inner_key.data()), duplicate_inner_key.size(), request));
}

int main() {
  // A trivially copyable request cannot hide vector/string heap allocations in
  // the untrusted decode path.
  static_assert(std::is_trivially_copyable_v<esphome::beszel::HubRequest>);
  request_fixtures_decode();
  malformed_fixtures_fail();
  populated_data_response();
  temperature_data_response();
  tolerant_unknown_keys_and_strict_types();
  map_order_and_duplicate_keys();
}
