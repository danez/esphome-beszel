#include "websocket_message.h"

#include <cstring>

namespace esphome::beszel {

namespace {
constexpr uint8_t OPCODE_CONTINUATION = 0x00;
constexpr uint8_t OPCODE_BINARY = 0x02;
}

void WebSocketMessage::reset(bool allow_initial_continuation) {
  this->size_ = 0;
  this->frame_offset_ = 0;
  this->frame_length_ = 0;
  this->frame_opcode_ = 0;
  this->frame_fin_ = false;
  this->frame_active_ = false;
  this->message_active_ = false;
  this->allow_initial_continuation_ = allow_initial_continuation;
}

MessageResult WebSocketMessage::reject_() {
  this->reset();
  return MessageResult::REJECTED;
}

MessageResult WebSocketMessage::push(uint8_t opcode, bool fin, int payload_length,
                                     int payload_offset, const char *data, int data_length) {
  if (payload_length < 0 || payload_offset < 0 || data_length < 0 ||
      (data_length > 0 && data == nullptr))
    return this->reject_();

  const size_t length = static_cast<size_t>(payload_length);
  const size_t offset = static_cast<size_t>(payload_offset);
  const size_t chunk = static_cast<size_t>(data_length);
  if (offset > length || chunk > length - offset || length > MAX_SIZE || (chunk == 0 && offset < length))
    return this->reject_();

  if (offset == 0) {
    if (this->frame_active_)
      return this->reject_();
    if (opcode == OPCODE_BINARY) {
      if (this->message_active_)
        return this->reject_();
      this->size_ = 0;
      this->message_active_ = true;
      this->allow_initial_continuation_ = false;
    } else if (opcode == OPCODE_CONTINUATION) {
      if (!this->message_active_) {
        // ESP-IDF can label payload received with the upgrade response as a
        // continuation. Permit that compatibility case only for the first
        // data frame after a new connection.
        if (!this->allow_initial_continuation_)
          return this->reject_();
        this->size_ = 0;
        this->message_active_ = true;
        this->allow_initial_continuation_ = false;
      }
    } else {
      return this->reject_();
    }
    this->frame_active_ = true;
    this->frame_offset_ = 0;
    this->frame_length_ = length;
    this->frame_opcode_ = opcode;
    this->frame_fin_ = fin;
  } else if (!this->frame_active_ || offset != this->frame_offset_ ||
             length != this->frame_length_ || opcode != this->frame_opcode_ || fin != this->frame_fin_) {
    return this->reject_();
  }

  if (offset != this->frame_offset_ || chunk > MAX_SIZE - this->size_)
    return this->reject_();
  if (chunk != 0)
    std::memcpy(this->data_.data() + this->size_, data, chunk);
  this->size_ += chunk;
  this->frame_offset_ += chunk;

  if (this->frame_offset_ != this->frame_length_)
    return MessageResult::ACCEPTED;

  this->frame_active_ = false;
  if (!this->frame_fin_)
    return MessageResult::ACCEPTED;

  this->message_active_ = false;
  return MessageResult::COMPLETE;
}

}  // namespace esphome::beszel
