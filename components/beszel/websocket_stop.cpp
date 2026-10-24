#include "websocket_stop.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace esphome::beszel {

bool WebSocketStop::start(esp_websocket_client_handle_t client) {
  if (client == nullptr || this->pending_)
    return false;
  this->client_ = client;
  this->done_.store(false);
  this->pending_ = true;
  // stop() can wait through a stalled TLS handshake. Keep that wait, and
  // destruction of its transport, off ESPHome's watchdog-monitored task.
  if (xTaskCreate(&WebSocketStop::stop_task_, "beszel_stop", 4096, this, 1, nullptr) != pdPASS) {
    this->pending_ = false;
    this->client_ = nullptr;
    return false;
  }
  return true;
}

bool WebSocketStop::poll() {
  if (!this->pending_)
    return true;
  if (!this->done_.load())
    return false;
  this->client_ = nullptr;
  this->pending_ = false;
  return true;
}

void WebSocketStop::stop_task_(void *arg) {
  auto *self = static_cast<WebSocketStop *>(arg);
  esp_websocket_client_stop(self->client_);
  // stop() joins the WebSocket task before its callback-owned state is freed.
  esp_websocket_client_destroy(self->client_);
  self->done_.store(true);
  // Do not access self after publishing completion: the main task may reuse it.
  vTaskDelete(nullptr);
}

}  // namespace esphome::beszel
