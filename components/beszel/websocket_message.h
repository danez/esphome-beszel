#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace esphome::beszel {

enum class MessageResult : uint8_t { ACCEPTED, COMPLETE, REJECTED };

class WebSocketMessage {
 public:
  static constexpr size_t MAX_SIZE = 2048;

  void reset(bool allow_initial_continuation = false);
  MessageResult push(uint8_t opcode, bool fin, int payload_length, int payload_offset,
                     const char *data, int data_length);
  const uint8_t *data() const { return data_.data(); }
  size_t size() const { return size_; }

 private:
  MessageResult reject_();

  std::array<uint8_t, MAX_SIZE> data_{};
  size_t size_{0};
  size_t frame_offset_{0};
  size_t frame_length_{0};
  uint8_t frame_opcode_{0};
  bool frame_fin_{false};
  bool frame_active_{false};
  bool message_active_{false};
  bool allow_initial_continuation_{false};
};

}  // namespace esphome::beszel
