#include <cassert>
#include <cstring>

#include "../components/beszel/websocket_message.h"

using esphome::beszel::MessageResult;
using esphome::beszel::WebSocketMessage;

static void tcp_chunks_and_websocket_fragments() {
  WebSocketMessage message;
  message.reset();
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::ACCEPTED);
  assert(message.push(2, false, 4, 2, "cd", 2) == MessageResult::ACCEPTED);
  assert(message.push(0, true, 2, 0, "ef", 2) == MessageResult::COMPLETE);
  assert(message.size() == 6 && std::memcmp(message.data(), "abcdef", 6) == 0);

  message.reset();
  assert(message.push(2, true, 3, 0, "abc", 3) == MessageResult::COMPLETE);
}

static void rejects_inconsistent_sequences() {
  WebSocketMessage message;
  message.reset();
  assert(message.push(0, true, 1, 0, "a", 1) == MessageResult::REJECTED);
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::ACCEPTED);
  assert(message.push(2, false, 4, 3, "d", 1) == MessageResult::REJECTED);
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::ACCEPTED);
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::REJECTED);
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::ACCEPTED);
  assert(message.push(2, false, 5, 2, "cd", 2) == MessageResult::REJECTED);
  assert(message.push(2, false, 4, 0, "ab", 2) == MessageResult::ACCEPTED);
  assert(message.push(2, true, 4, 2, "cd", 2) == MessageResult::REJECTED);
  assert(message.push(2, true, 1, 0, nullptr, 1) == MessageResult::REJECTED);
  assert(message.push(2, true, 1, -1, "a", 1) == MessageResult::REJECTED);
  assert(message.push(2, true, 1, 0, "a", -1) == MessageResult::REJECTED);
  assert(message.push(2, true, 1, 0, "ab", 2) == MessageResult::REJECTED);
  assert(message.push(2, true, 1, 0, "", 0) == MessageResult::REJECTED);
  assert(message.push(2, true, 2049, 0, "", 0) == MessageResult::REJECTED);

  assert(message.push(2, false, 1, 0, "a", 1) == MessageResult::ACCEPTED);
  assert(message.push(2, true, 1, 0, "b", 1) == MessageResult::REJECTED);

  message.reset();
  assert(message.push(2, false, 1, 0, "a", 1) == MessageResult::ACCEPTED);
  message.reset();  // A disconnect discards the incomplete message.
  assert(message.push(0, true, 1, 0, "b", 1) == MessageResult::REJECTED);
}

static void initial_continuation_is_one_shot() {
  WebSocketMessage message;
  message.reset(true);
  assert(message.push(0, true, 1, 0, "a", 1) == MessageResult::COMPLETE);
  assert(message.push(0, true, 1, 0, "b", 1) == MessageResult::REJECTED);

  message.reset(true);
  assert(message.push(2, true, 1, 0, "a", 1) == MessageResult::COMPLETE);
  assert(message.push(0, true, 1, 0, "b", 1) == MessageResult::REJECTED);
}

int main() {
  tcp_chunks_and_websocket_fragments();
  rejects_inconsistent_sequences();
  initial_continuation_is_one_shot();
}
