#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <string>

#include "esp_websocket_client.h"
#ifdef CONFIG_IDF_TARGET_ESP32S3
#include "driver/temperature_sensor.h"
#endif

#include "esphome/core/component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "cbor.h"
#include "websocket_message.h"

namespace esphome::beszel {

class Beszel : public Component {
 public:
  void setup() override;
  void loop() override;
  void on_shutdown() override;
  void set_hub(const char *hub) { this->hub_ = hub; }
  void set_token(const char *token) { this->token_ = token; }
  void set_public_key(const std::array<uint8_t, 32> &key) { this->public_key_ = key; }
  void set_temperature_sensor(sensor::Sensor *sensor) { this->temperature_sensor_source_ = sensor; }
  void set_status_sensor(text_sensor::TextSensor *sensor) { this->status_sensor_ = sensor; }

 protected:
  bool verify_signature_(const uint8_t signature[64], const uint8_t *message, size_t length) const;
  bool authenticate_(const uint8_t signature[64]);
  void clear_authentication_();
  bool is_authenticated_() const;
  bool factory_fingerprint_(std::string &fingerprint) const;
  bool setup_internal_temperature_();
  bool read_internal_temperature_(float &temperature) const;
  void shutdown_internal_temperature_();
  bool handle_check_fingerprint_(const HubRequest &request, uint8_t *output, size_t output_size,
                                 const char *node_name, size_t *written = nullptr);
  static void websocket_event_(void *arg, esp_event_base_t base, int32_t event_id, void *event_data);
  void handle_websocket_event_(int32_t event_id, const esp_websocket_event_data_t &event);
  void set_pending_status_(uint8_t status) { this->pending_status_.store(status); }
  void consume_message_(esp_websocket_client_handle_t client, const uint8_t *data, size_t length);

  std::string hub_;
  std::string token_;
  std::array<uint8_t, 32> public_key_{};
  std::atomic<bool> authenticated_{false};
  // Owned exclusively by the ESPHome main task. Callbacks use event.client.
  esp_websocket_client_handle_t client_{nullptr};
  std::atomic<bool> shutting_down_{false};
  // ESP-IDF forbids stopping its client from an event callback. Invalid input
  // requests a main-loop reconnect instead.
  std::atomic<bool> reconnect_requested_{false};
  // loop() detects network transitions, but the WebSocket callback owns the
  // fragment assembler. Hand reset requests across tasks instead of racing it.
  std::atomic<bool> reset_message_requested_{false};
  // Main-task-only snapshot used to publish each Wi-Fi transition once.
  bool network_available_{false};
  // Set only when the user configured ESPHome's internal_temperature sensor.
  // Reading its published state avoids installing the S3 hardware driver twice.
  sensor::Sensor *temperature_sensor_source_{nullptr};
  text_sensor::TextSensor *status_sensor_{nullptr};
#ifdef CONFIG_IDF_TARGET_ESP32S3
  temperature_sensor_handle_t temperature_sensor_{nullptr};
#endif
  bool temperature_available_{false};
  // Callbacks only publish the latest lifecycle state. loop() consumes it so
  // ESPHome entities and logs are never touched from the WebSocket task.
  std::atomic<uint8_t> pending_status_{0};
  WebSocketMessage message_;
};

}  // namespace esphome::beszel
