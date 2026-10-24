#pragma once

#include <atomic>

#include "esp_websocket_client.h"

namespace esphome::beszel {

// Main-task methods; only stop_task_ accesses the client after start().
class WebSocketStop {
 public:
  bool start(esp_websocket_client_handle_t client);
  bool pending() const { return this->pending_; }
  bool poll();

 private:
  static void stop_task_(void *arg);
  esp_websocket_client_handle_t client_{nullptr};
  bool pending_{false};
  std::atomic<bool> done_{false};
};

}  // namespace esphome::beszel
