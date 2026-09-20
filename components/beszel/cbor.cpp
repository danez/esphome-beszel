#include "cbor.h"

#include <cstring>
#include <utility>

namespace esphome::beszel {

bool CborReader::take(size_t size, const uint8_t *&value) {
  if (size > size_ - pos_) return false;
  value = data_ + pos_;
  pos_ += size;
  return true;
}

bool CborReader::head(uint8_t &major, uint64_t &value) {
  const uint8_t *p;
  if (!take(1, p)) return false;
  major = p[0] >> 5;
  uint8_t info = p[0] & 31;
  if (info < 24) { value = info; return true; }
  size_t bytes = info == 24 ? 1 : info == 25 ? 2 : info == 26 ? 4 : info == 27 ? 8 : 0;
  if (!bytes || !take(bytes, p)) return false;
  value = 0;
  for (size_t i = 0; i < bytes; i++) value = (value << 8) | p[i];
  return true;
}

bool CborReader::map(size_t &count) { uint8_t m; uint64_t n; if (!head(m, n) || m != 5 || n > SIZE_MAX) return false; count = n; return true; }
bool CborReader::array(size_t &count) { uint8_t m; uint64_t n; if (!head(m, n) || m != 4 || n > SIZE_MAX) return false; count = n; return true; }
bool CborReader::uint64(uint64_t &value) { uint8_t m; return head(m, value) && m == 0; }
bool CborReader::boolean(bool &value) {
  if (pos_ == size_ || (data_[pos_] != 0xf4 && data_[pos_] != 0xf5)) return false;
  value = data_[pos_++] == 0xf5;
  return true;
}

bool CborReader::bytes(uint8_t *value, size_t size) {
  uint8_t m; uint64_t n; const uint8_t *p;
  if (!head(m, n) || m != 2 || n != size || !take(size, p)) return false;
  memcpy(value, p, size);
  return true;
}

bool CborReader::text(std::string &value, size_t max_size) {
  uint8_t m; uint64_t n; const uint8_t *p;
  if (!head(m, n) || m != 3 || n > max_size || n > SIZE_MAX || !take(n, p)) return false;
  value.assign(reinterpret_cast<const char *>(p), n); return true;
}

bool CborReader::skip_item(size_t depth) {
  // Unknown fields provide forward compatibility, but their nesting and item
  // counts remain bounded so hostile CBOR cannot consume unbounded stack/time.
  if (depth > 8) return false;
  uint8_t m; uint64_t n;
  if (!head(m, n)) return false;
  if (m == 4 || m == 5) {
    if (n > 64) return false;
    size_t items = m == 5 ? n * 2 : n;
    for (size_t i = 0; i < items; i++) if (!skip_item(depth + 1)) return false;
  } else if (m == 2 || m == 3) {
    const uint8_t *p; if (n > SIZE_MAX || !take(n, p)) return false;
  }
  return true;
}
bool CborReader::skip() { return skip_item(0); }

bool CborReader::item(const uint8_t *&data, size_t &size) {
  // Preserve a bounded view into the input so an outer map can be decoded
  // without assuming that its type-discriminating field appears first.
  const size_t start = pos_;
  if (!skip()) return false;
  data = data_ + start;
  size = pos_ - start;
  return true;
}

bool CborWriter::put(uint8_t value) { if (pos_ == size_) return false; data_[pos_++] = value; return true; }
bool CborWriter::put(const uint8_t *value, size_t size) { if (size > size_ - pos_) return false; memcpy(data_ + pos_, value, size); pos_ += size; return true; }
bool CborWriter::head(uint8_t major, uint64_t value) {
  if (value < 24) return put(uint8_t(major << 5 | value));
  if (value <= UINT8_MAX) return put(uint8_t(major << 5 | 24)) && put(uint8_t(value));
  if (value <= UINT16_MAX) { uint8_t b[] = {uint8_t(value >> 8), uint8_t(value)}; return put(uint8_t(major << 5 | 25)) && put(b, 2); }
  if (value <= UINT32_MAX) { uint8_t b[] = {uint8_t(value >> 24), uint8_t(value >> 16), uint8_t(value >> 8), uint8_t(value)}; return put(uint8_t(major << 5 | 26)) && put(b, 4); }
  uint8_t b[8]; for (int i = 7; i >= 0; i--) b[7 - i] = uint8_t(value >> (i * 8));
  return put(uint8_t(major << 5 | 27)) && put(b, 8);
}
bool CborWriter::map(size_t count) { return head(5, count); }
bool CborWriter::array(size_t count) { return head(4, count); }
bool CborWriter::uint64(uint64_t value) { return head(0, value); }
bool CborWriter::boolean(bool value) { return put(value ? 0xf5 : 0xf4); }
bool CborWriter::bytes(const uint8_t *value, size_t size) { return head(2, size) && put(value, size); }
bool CborWriter::text(const char *value) { size_t n = strlen(value); return head(3, n) && put(reinterpret_cast<const uint8_t *>(value), n); }
bool CborWriter::floating(double value) { uint64_t bits; memcpy(&bits, &value, 8); uint8_t b[8]; for (int i = 7; i >= 0; i--) b[7 - i] = uint8_t(bits >> (i * 8)); return put(0xfb) && put(b, 8); }

namespace {

bool decode_fingerprint_data(const uint8_t *data, size_t size, HubRequest &request) {
  CborReader r(data, size);
  size_t count;
  if (!r.map(count) || count > 4) return false;
  bool signature_seen = false;
  bool need_sys_info_seen = false;
  for (size_t i = 0; i < count; i++) {
    uint64_t key;
    if (!r.uint64(key)) return false;
    if (key == 0) {
      if (signature_seen || !r.bytes(request.signature.data(), request.signature.size())) return false;
      signature_seen = true;
      request.has_signature = true;
    } else if (key == 1) {
      if (need_sys_info_seen || !r.boolean(request.need_sys_info)) return false;
      need_sys_info_seen = true;
    } else if (!r.skip()) {
      return false;
    }
  }
  return r.done();
}

bool decode_get_data(const uint8_t *data, size_t size, HubRequest &request) {
  CborReader r(data, size);
  size_t count;
  if (!r.map(count) || count > 4) return false;
  bool cache_time_seen = false;
  bool include_details_seen = false;
  for (size_t i = 0; i < count; i++) {
    uint64_t key;
    if (!r.uint64(key)) return false;
    if (key == 0) {
      uint64_t cache_time;
      if (cache_time_seen || !r.uint64(cache_time) || cache_time > UINT16_MAX) return false;
      request.cache_time_ms = static_cast<uint16_t>(cache_time);
      cache_time_seen = true;
    } else if (key == 1) {
      if (include_details_seen || !r.boolean(request.include_details)) return false;
      include_details_seen = true;
    } else if (!r.skip()) {
      return false;
    }
  }
  return r.done();
}

}  // namespace

bool decode_hub_request(const uint8_t *data, size_t size, HubRequest &request) {
  request = {};
  HubRequest decoded;
  CborReader r(data, size);
  size_t count;
  if (!r.map(count) || count > 16) return false;

  bool action_seen = false;
  bool data_seen = false;
  bool request_id_seen = false;
  const uint8_t *action_data = nullptr;
  size_t action_data_size = 0;
  for (size_t i = 0; i < count; i++) {
    uint64_t key;
    if (!r.uint64(key)) return false;
    if (key == 0) {
      uint64_t action;
      if (action_seen || !r.uint64(action) || action > UINT8_MAX) return false;
      decoded.action = static_cast<uint8_t>(action);
      action_seen = true;
    } else if (key == 1) {
      if (data_seen || !r.item(action_data, action_data_size)) return false;
      data_seen = true;
    } else if (key == 2) {
      uint64_t request_id;
      if (request_id_seen || !r.uint64(request_id) || request_id > UINT32_MAX) return false;
      decoded.request_id = static_cast<uint32_t>(request_id);
      decoded.has_request_id = true;
      request_id_seen = true;
    } else if (!r.skip()) {
      return false;
    }
  }
  if (!r.done() || !action_seen) return false;
  if (data_seen && decoded.action == 1 && !decode_fingerprint_data(action_data, action_data_size, decoded)) return false;
  if (data_seen && decoded.action == 0 && !decode_get_data(action_data, action_data_size, decoded)) return false;
  request = std::move(decoded);
  return true;
}

namespace {

bool encode_response_start(CborWriter &writer, uint32_t id, uint64_t response_key) {
  // Every Hub response is {0: request ID, response-key: payload}.
  return writer.map(2) && writer.uint64(0) && writer.uint64(id) && writer.uint64(response_key);
}

bool encode_system_stats(CborWriter &writer, const SystemMetrics &metrics,
                         double total_gib, double used_gib, double used_pct,
                         double flash_gib, double flash_used_gib, double flash_used_pct) {
  // Keep the declared map size beside the fields so protocol changes are easy
  // to audit. Numeric keys are fixed by Beszel's CombinedData wire format.
  if (!writer.map(7 + (metrics.has_temperature ? 1 : 0))) return false;
  if (!writer.uint64(0) || !writer.floating(0) ||
      !writer.uint64(2) || !writer.floating(total_gib) ||
      !writer.uint64(3) || !writer.floating(used_gib) ||
      !writer.uint64(4) || !writer.floating(used_pct) ||
      !writer.uint64(9) || !writer.floating(flash_gib) ||
      !writer.uint64(10) || !writer.floating(flash_used_gib) ||
      !writer.uint64(11) || !writer.floating(flash_used_pct))
    return false;
  // Key 20 is Beszel's map of sensor name to degrees Celsius.
  return !metrics.has_temperature ||
         (writer.uint64(20) && writer.map(1) && writer.text("SoC") &&
          writer.floating(metrics.temperature));
}

bool encode_host_stats(CborWriter &writer, const SystemMetrics &metrics, double used_pct, double flash_used_pct) {
  if (!writer.map(8)) return false;
  return writer.uint64(3) && writer.uint64(metrics.cores) &&
         writer.uint64(5) && writer.uint64(metrics.uptime_seconds) &&
         writer.uint64(6) && writer.floating(0) &&
         writer.uint64(7) && writer.floating(used_pct) &&
         writer.uint64(8) && writer.floating(flash_used_pct) &&
         writer.uint64(10) && writer.text("0.19.0") &&
         writer.uint64(18) && writer.uint64(0) &&
         writer.uint64(20) && writer.uint64(2);
}

bool encode_system_details(CborWriter &writer, const SystemMetrics &metrics) {
  if (!writer.map(9)) return false;
  return writer.uint64(0) && writer.text(metrics.hostname) &&
         writer.uint64(1) && writer.text(metrics.idf_version) &&
         writer.uint64(2) && writer.uint64(metrics.cores) &&
         writer.uint64(3) && writer.uint64(metrics.cores) &&
         writer.uint64(4) && writer.text(metrics.chip_model) &&
         writer.uint64(5) && writer.uint64(0) &&
         writer.uint64(6) && writer.text(metrics.esphome_version) &&
         writer.uint64(7) && writer.text(metrics.architecture) &&
         writer.uint64(9) && writer.uint64(metrics.total_heap);
}

bool finish_response(const CborWriter &writer, bool encoded, size_t *written) {
  if (encoded && written != nullptr) *written = writer.size();
  return encoded;
}

}  // namespace

bool encode_fingerprint_response(uint8_t *data, size_t size, uint32_t id, const char *fingerprint, const char *hostname,
                                 const char *name, size_t *written) {
  CborWriter writer(data, size);
  const size_t fields = 1 + (hostname != nullptr) + (name != nullptr);
  if (!encode_response_start(writer, id, 2) || !writer.map(fields) ||
      !writer.uint64(0) || !writer.text(fingerprint))
    return false;
  if (hostname != nullptr && (!writer.uint64(1) || !writer.text(hostname))) return false;
  if (name != nullptr && (!writer.uint64(3) || !writer.text(name))) return false;
  return finish_response(writer, true, written);
}

bool encode_error_response(uint8_t *data, size_t size, uint32_t id, const char *error, size_t *written) {
  CborWriter writer(data, size);
  const bool encoded = encode_response_start(writer, id, 3) && writer.text(error);
  return finish_response(writer, encoded, written);
}

bool encode_data_response(uint8_t *data, size_t size, uint32_t id, const SystemMetrics &m, size_t *written) {
  CborWriter writer(data, size);
  const uint64_t used = m.free_heap <= m.total_heap ? m.total_heap - m.free_heap : 0;
  const double total_gib = static_cast<double>(m.total_heap) / 1073741824.0;
  const double used_gib = static_cast<double>(used) / 1073741824.0;
  const double used_pct = m.total_heap == 0 ? 0.0 : 100.0 * static_cast<double>(used) / static_cast<double>(m.total_heap);
  const uint64_t flash_used = m.flash_used <= m.flash_size ? m.flash_used : 0;
  const double flash_gib = static_cast<double>(m.flash_size) / 1073741824.0;
  const double flash_used_gib = static_cast<double>(flash_used) / 1073741824.0;
  const double flash_used_pct = m.flash_size == 0 ? 0.0 : 100.0 * static_cast<double>(flash_used) / static_cast<double>(m.flash_size);
  const bool encoded = encode_response_start(writer, id, 1) && writer.map(4) &&
                       writer.uint64(0) && encode_system_stats(writer, m, total_gib, used_gib, used_pct,
                                                               flash_gib, flash_used_gib, flash_used_pct) &&
                       writer.uint64(1) && encode_host_stats(writer, m, used_pct, flash_used_pct) &&
                       writer.uint64(2) && writer.array(0) &&
                       writer.uint64(4) && encode_system_details(writer, m);
  return finish_response(writer, encoded, written);
}

}  // namespace esphome::beszel
