#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>

namespace esphome::beszel {

class CborReader {
 public:
  CborReader(const uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool map(size_t &count);
  bool array(size_t &count);
  bool uint64(uint64_t &value);
  bool boolean(bool &value);
  bool bytes(uint8_t *value, size_t size);
  bool text(std::string &value, size_t max_size);
  bool item(const uint8_t *&data, size_t &size);
  bool skip();
  bool done() const { return pos_ == size_; }

 private:
  // This codec intentionally supports only definite-length CBOR used by the
  // Beszel protocol. Indefinite items and unsupported additional info fail.
  bool head(uint8_t &major, uint64_t &value);
  bool skip_item(size_t depth);
  bool take(size_t size, const uint8_t *&value);
  const uint8_t *data_;
  size_t size_;
  size_t pos_{0};
};

class CborWriter {
 public:
  CborWriter(uint8_t *data, size_t size) : data_(data), size_(size) {}
  bool map(size_t count);
  bool array(size_t count);
  bool uint64(uint64_t value);
  bool boolean(bool value);
  bool bytes(const uint8_t *value, size_t size);
  bool text(const char *value);
  bool text(const std::string &value) { return text(value.c_str()); }
  bool floating(double value);
  size_t size() const { return pos_; }

 private:
  bool head(uint8_t major, uint64_t value);
  bool put(uint8_t value);
  bool put(const uint8_t *value, size_t size);
  uint8_t *data_;
  size_t size_;
  size_t pos_{0};
};

struct HubRequest {
  // These primitives are the complete bounded model needed by the two v1 Hub
  // actions; retaining the generic nested CBOR tree would waste scarce RAM.
  uint8_t action{0};
  bool has_request_id{false};
  uint32_t request_id{0};
  // Authentication is handled before the peer is trusted, so its fixed-size
  // protocol value must not trigger allocator work on hostile input.
  std::array<uint8_t, 64> signature{};
  bool has_signature{false};
  bool need_sys_info{false};
  uint16_t cache_time_ms{0};
  bool include_details{false};
};

struct SystemMetrics {
  uint64_t total_heap{0};
  uint64_t free_heap{0};
  uint64_t flash_size{0};
  uint64_t flash_used{0};
  uint64_t uptime_seconds{0};
  const char *hostname{nullptr};
  const char *idf_version{nullptr};
  const char *chip_model{nullptr};
  const char *architecture{"xtensa"};
  const char *esphome_version{nullptr};
  uint8_t cores{1};
  // Beszel stores temperatures as a named Celsius map. Keep the value inline
  // because this first implementation reports only the on-chip sensor.
  bool has_temperature{false};
  double temperature{0};
};

bool decode_hub_request(const uint8_t *data, size_t size, HubRequest &request);
bool encode_fingerprint_response(uint8_t *data, size_t size, uint32_t request_id,
                                 const char *fingerprint, const char *hostname, const char *name,
                                 size_t *written = nullptr);
bool encode_error_response(uint8_t *data, size_t size, uint32_t request_id, const char *error,
                           size_t *written = nullptr);
bool encode_data_response(uint8_t *data, size_t size, uint32_t request_id,
                          const SystemMetrics &metrics, size_t *written = nullptr);

}  // namespace esphome::beszel
