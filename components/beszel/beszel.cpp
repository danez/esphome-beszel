#include "beszel.h"

#include "crypto.h"

#include "esp_crt_bundle.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_image_format.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_websocket_client.h"
#include "esphome/components/network/util.h"
#include "esphome/core/application.h"
#include "esphome/core/log.h"
#include "esphome/core/version.h"
#include "freertos/task.h"

#include <cmath>
#include <cstring>

#ifdef CONFIG_IDF_TARGET_ESP32
// The original ESP32 exposes only this ROM API; ESP-IDF has no supported
// temperature-sensor driver for that chip.
extern "C" uint8_t temprature_sens_read();
#endif

static const char *const TAG = "beszel";

namespace esphome::beszel {

namespace {
enum Status : uint8_t { DISCONNECTED = 1, CONNECTING, AUTHENTICATING, CONNECTED };
}

bool Beszel::verify_signature_(const uint8_t signature[64], const uint8_t *message, size_t length) const {
  return verify_ed25519(signature, message, length, this->public_key_.data());
}

bool Beszel::authenticate_(const uint8_t signature[64]) {
  const bool authenticated = this->verify_signature_(
      signature, reinterpret_cast<const uint8_t *>(this->token_.data()), this->token_.size());
  this->authenticated_.store(authenticated);
  return authenticated;
}

void Beszel::clear_authentication_() { this->authenticated_.store(false); }

bool Beszel::is_authenticated_() const { return this->authenticated_.load(); }

bool Beszel::setup_internal_temperature_() {
  // A configured ESPHome internal_temperature sensor owns the hardware. Its
  // state is read below, so Beszel must not install a second S3 driver handle.
  if (this->temperature_sensor_source_ != nullptr)
    return true;
#ifdef CONFIG_IDF_TARGET_ESP32S3
  temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
  esp_err_t result = temperature_sensor_install(&config, &this->temperature_sensor_);
  if (result == ESP_OK)
    result = temperature_sensor_enable(this->temperature_sensor_);
  if (result != ESP_OK) {
    ESP_LOGW(TAG, "Internal temperature sensor unavailable (%d)", result);
    if (this->temperature_sensor_ != nullptr) {
      temperature_sensor_uninstall(this->temperature_sensor_);
      this->temperature_sensor_ = nullptr;
    }
    return false;
  }
#endif
  return true;
}

bool Beszel::read_internal_temperature_(float &temperature) const {
  if (this->temperature_sensor_source_ != nullptr) {
    if (!this->temperature_sensor_source_->has_state())
      return false;
    temperature = this->temperature_sensor_source_->state;
    return std::isfinite(temperature);
  }
#ifdef CONFIG_IDF_TARGET_ESP32S3
  if (this->temperature_sensor_ == nullptr ||
      temperature_sensor_get_celsius(this->temperature_sensor_, &temperature) != ESP_OK)
    return false;
#else
  const uint8_t raw = temprature_sens_read();
  if (raw == 128) return false;
  temperature = (raw - 32) / 1.8f;
#endif
  return std::isfinite(temperature);
}

void Beszel::shutdown_internal_temperature_() {
#ifdef CONFIG_IDF_TARGET_ESP32S3
  if (this->temperature_sensor_ != nullptr) {
    temperature_sensor_disable(this->temperature_sensor_);
    temperature_sensor_uninstall(this->temperature_sensor_);
    this->temperature_sensor_ = nullptr;
  }
#endif
  this->temperature_available_ = false;
}

bool Beszel::handle_check_fingerprint_(const HubRequest &request, uint8_t *output, size_t output_size,
                                       const char *node_name, size_t *written) {
  if (request.action != 1 || !request.has_signature || !this->authenticate_(request.signature.data())) {
    this->clear_authentication_();
    // A response cannot be correlated without an ID. Return false so the
    // caller neither reports successful encoding nor sends a zero-byte frame.
    return request.has_request_id && encode_error_response(
                                         output, output_size, request.request_id,
                                         "fingerprint verification failed", written);
  }
  std::string fingerprint;
  if (!this->factory_fingerprint_(fingerprint)) {
    // A missing hardware identity must not become the shared fingerprint of
    // an empty string or leave the session authenticated locally.
    this->clear_authentication_();
    return request.has_request_id && encode_error_response(
                                         output, output_size, request.request_id,
                                         "factory MAC unavailable", written);
  }
  const char *name = request.need_sys_info ? node_name : nullptr;
  return request.has_request_id && encode_fingerprint_response(
      output, output_size, request.request_id, fingerprint.c_str(),
      request.need_sys_info ? node_name : nullptr, name, written);
}

void Beszel::setup() {
  this->set_pending_status_(DISCONNECTED);
  if (this->hub_.rfind("wss://", 0) != 0) {
    ESP_LOGE(TAG, "Secure WebSocket transport is required");
    this->mark_failed();
    return;
  }
  // Host builds initialize the complete libsodium library. The ESPHome port
  // uses only deterministic primitives and intentionally skips its unusable
  // Unix random backend; initialize_crypto() documents that platform split.
  if (!initialize_crypto()) {
    // Authentication cannot be trusted when libsodium initialization fails.
    // Marking the component failed prevents loop() from starting the client.
    ESP_LOGE(TAG, "libsodium initialization failed");
    this->mark_failed();
    return;
  }
  // Reuse an explicitly configured ESPHome sensor when code generation found
  // one. Otherwise the hidden reader preserves Beszel's zero-config behavior.
  // Temperature is useful diagnostics but is not required for Hub operation.
  this->temperature_available_ = this->setup_internal_temperature_();
}

void Beszel::loop() {
  const auto status = this->pending_status_.exchange(0);
  if (status != 0) {
    const char *state = nullptr;
    if (status == DISCONNECTED) {
      state = "disconnected";
      ESP_LOGI(TAG, "WebSocket disconnected");
    } else if (status == CONNECTING) {
      state = "connecting";
      ESP_LOGI(TAG, "Starting WebSocket connection");
    } else if (status == AUTHENTICATING) {
      state = "authenticating";
      ESP_LOGI(TAG, "WebSocket opened; authentication pending");
    } else if (status == CONNECTED) {
      state = "connected";
      ESP_LOGI(TAG, "Hub authenticated");
    }
    if (state != nullptr && this->status_sensor_ != nullptr)
      this->status_sensor_->publish_state(state);
  }

  const bool network_available = network::is_connected();
  if (network_available != this->network_available_) {
    this->network_available_ = network_available;
    if (!network_available) {
      // ESP-IDF keeps its own reconnect loop alive. Only invalidate protocol
      // state here; stopping the client would add blocking work to loop().
      this->clear_authentication_();
      this->reset_message_requested_.store(true);
      this->set_pending_status_(DISCONNECTED);
    } else if (this->client_ != nullptr) {
      // An existing client will reconnect itself now that networking is back.
      this->set_pending_status_(CONNECTING);
    }
  }
  if (!network_available)
    return;
  if (this->reconnect_requested_.exchange(false) && this->client_ != nullptr) {
    // Run this outside the callback: stop waits for the WebSocket task, and
    // ESP-IDF explicitly disallows invoking it from that same task.
    this->clear_authentication_();
    this->set_pending_status_(CONNECTING);
    esp_websocket_client_stop(this->client_);
    if (esp_websocket_client_start(this->client_) != ESP_OK) {
      ESP_LOGE(TAG, "WebSocket restart failed");
      esp_websocket_client_destroy(this->client_);
      this->client_ = nullptr;
      this->set_pending_status_(DISCONNECTED);
    }
    return;
  }
  if (this->client_ != nullptr || this->shutting_down_.load())
    return;

  esp_websocket_client_config_t config{};
  config.uri = this->hub_.c_str();
  config.headers = nullptr;
  config.user_agent = "esphome-beszel/0.1.0";
  config.buffer_size = 2048;
  // Ed25519 verification overflowed the library's 4096-byte default on real
  // ESP32 hardware. Keep this margin until both supported chips are measured.
  config.task_stack = 8192;
  config.ping_interval_sec = 10;
  config.reconnect_timeout_ms = 10000;
  config.enable_close_reconnect = true;
  config.crt_bundle_attach = esp_crt_bundle_attach;

  this->client_ = esp_websocket_client_init(&config);
  if (this->client_ == nullptr) {
    ESP_LOGE(TAG, "WebSocket client initialization failed");
    this->set_pending_status_(DISCONNECTED);
    return;
  }
  // These calls allocate/copy client-owned configuration. Refuse to start a
  // partially configured client because missing authentication or callbacks
  // would otherwise create a live connection we cannot use safely.
  if (esp_websocket_client_append_header(this->client_, "X-Token", this->token_.c_str()) != ESP_OK ||
      esp_websocket_client_append_header(this->client_, "X-Beszel", "0.19.0") != ESP_OK ||
      esp_websocket_register_events(this->client_, WEBSOCKET_EVENT_ANY, &Beszel::websocket_event_, this) != ESP_OK) {
    ESP_LOGE(TAG, "WebSocket client configuration failed");
    esp_websocket_client_destroy(this->client_);
    this->client_ = nullptr;
    this->set_pending_status_(DISCONNECTED);
    return;
  }
  this->set_pending_status_(CONNECTING);
  if (esp_websocket_client_start(this->client_) != ESP_OK) {
    ESP_LOGE(TAG, "WebSocket start failed");
    esp_websocket_client_destroy(this->client_);
    this->client_ = nullptr;
    this->set_pending_status_(DISCONNECTED);
  }
}

void Beszel::on_shutdown() {
  this->shutting_down_.store(true);
  this->clear_authentication_();
  if (this->client_ != nullptr) {
    // stop() waits for the WebSocket task and its callbacks to exit, so the
    // main-task-owned handle cannot be freed while a callback is still using it.
    esp_websocket_client_stop(this->client_);
    esp_websocket_client_destroy(this->client_);
    this->client_ = nullptr;
  }
  this->shutdown_internal_temperature_();
}

void Beszel::websocket_event_(void *arg, esp_event_base_t, int32_t event_id, void *event_data) {
  auto *self = static_cast<Beszel *>(arg);
  if (self == nullptr || self->shutting_down_.load() || event_data == nullptr)
    return;
  self->handle_websocket_event_(event_id, *static_cast<esp_websocket_event_data_t *>(event_data));
}

void Beszel::handle_websocket_event_(int32_t event_id, const esp_websocket_event_data_t &event) {
  // The callback task is the sole owner of message_, including resets requested
  // by loop() after Wi-Fi loss.
  if (this->reset_message_requested_.exchange(false))
    this->message_.reset();

  if (event_id == WEBSOCKET_EVENT_ERROR) {
    // esp_websocket_client leaves TLS/socket members uninitialized unless it
    // has already classified the event as a TCP transport error. In particular,
    // a rejected HTTP upgrade reports type NONE with only the status populated.
    if (event.error_handle.error_type == WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT) {
      ESP_LOGW(TAG, "WebSocket transport error: tls=%d verify=0x%x handshake=%d socket=%d",
               event.error_handle.esp_tls_last_esp_err, event.error_handle.esp_tls_cert_verify_flags,
               event.error_handle.esp_ws_handshake_status_code, event.error_handle.esp_transport_sock_errno);
    } else {
      ESP_LOGW(TAG, "WebSocket error: type=%d handshake=%d", event.error_handle.error_type,
               event.error_handle.esp_ws_handshake_status_code);
    }
    return;
  }
  if (event_id == WEBSOCKET_EVENT_CONNECTED) {
    this->clear_authentication_();
    this->reconnect_requested_.store(false);
    this->message_.reset(true);
    this->set_pending_status_(AUTHENTICATING);
    return;
  }
  if (event_id == WEBSOCKET_EVENT_DISCONNECTED || event_id == WEBSOCKET_EVENT_CLOSED) {
    this->clear_authentication_();
    this->message_.reset();
    this->set_pending_status_(DISCONNECTED);
    return;
  }
  if (event_id != WEBSOCKET_EVENT_DATA)
    return;
  if (this->reconnect_requested_.load())
    return;
  ESP_LOGD(TAG, "RX frame: opcode=0x%02x len=%d payload=%d offset=%d fin=%d buffered=%u",
           event.op_code, event.data_len, event.payload_len, event.payload_offset, event.fin,
           static_cast<unsigned>(this->message_.size()));
  if (event.op_code == WS_TRANSPORT_OPCODES_TEXT) {
    ESP_LOGW(TAG, "Unexpected text WebSocket frame; reconnecting");
    this->clear_authentication_();
    this->message_.reset();
    this->reconnect_requested_.store(true);
    return;
  }
  if (event.op_code != WS_TRANSPORT_OPCODES_BINARY && event.op_code != WS_TRANSPORT_OPCODES_CONT)
    return;

  const MessageResult result = this->message_.push(event.op_code, event.fin, event.payload_len,
                                                   event.payload_offset, event.data_ptr, event.data_len);
  if (result == MessageResult::REJECTED) {
    ESP_LOGW(TAG, "Discarding inconsistent or oversized WebSocket message; reconnecting");
    this->clear_authentication_();
    this->reconnect_requested_.store(true);
    return;
  }
  ESP_LOGD(TAG, "RX buffered=%u message_complete=%d",
           static_cast<unsigned>(this->message_.size()), result == MessageResult::COMPLETE);
  if (result == MessageResult::COMPLETE) {
    this->consume_message_(event.client, this->message_.data(), this->message_.size());
  }
}

void Beszel::consume_message_(esp_websocket_client_handle_t client, const uint8_t *data, size_t length) {
  HubRequest request;
  if (!decode_hub_request(data, length, request)) {
    ESP_LOGW(TAG, "Ignoring malformed Hub request (%u bytes)", static_cast<unsigned>(length));
    return;
  }
  ESP_LOGD(TAG, "Hub request: action=%u id=%s%lu bytes=%u signature=%u authenticated=%d",
           static_cast<unsigned>(request.action), request.has_request_id ? "" : "none/",
           static_cast<unsigned long>(request.request_id),
           static_cast<unsigned>(length), request.has_signature ? 64U : 0U, this->is_authenticated_());

  // Beszel's deliberately small v1 response fits on the callback task stack;
  // a fixed buffer makes encoder exhaustion an error instead of a heap growth.
  std::array<uint8_t, 512> response{};
  size_t response_size = 0;
  bool encoded = false;
  if (request.action == 1) {
    ESP_LOGD(TAG, "Fingerprint verification starting: stack_free=%u",
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
    // Universal tokens use both response fields as the persistent Hub system
    // identity, so report the configured ESPHome node name instead of a label
    // shared by every device.
    encoded = this->handle_check_fingerprint_(request, response.data(), response.size(),
                                              App.get_name().c_str(), &response_size);
    ESP_LOGD(TAG, "Fingerprint verification: authenticated=%d encoded=%d response=%u stack_free=%u",
             this->is_authenticated_(), encoded, static_cast<unsigned>(response_size),
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
  } else if (request.has_request_id && !this->is_authenticated_()) {
    // Always answer correlated pre-authentication requests so the Hub gets a
    // definite protocol error instead of waiting for a response timeout.
    encoded = encode_error_response(response.data(), response.size(), request.request_id,
                                    "authentication required", &response_size);
  } else if (request.action == 0 && request.has_request_id && this->is_authenticated_()) {
    // Use one heap capability set for total and free values so subtraction and
    // the reported percentage describe the same internal-memory pool.
    const uint32_t caps = MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL;
    SystemMetrics metrics;
    metrics.total_heap = heap_caps_get_total_size(caps);
    metrics.free_heap = heap_caps_get_free_size(caps);
    uint32_t flash_size;
    if (esp_flash_get_size(nullptr, &flash_size) == ESP_OK)
      metrics.flash_size = flash_size;
    const esp_partition_t *running_partition = esp_ota_get_running_partition();
    if (running_partition != nullptr) {
      esp_partition_pos_t position{};
      position.offset = running_partition->address;
      position.size = running_partition->size;
      esp_image_metadata_t metadata{};
      if (esp_image_get_metadata(&position, &metadata) == ESP_OK)
        metrics.flash_used = metadata.image_len;
    }
    metrics.uptime_seconds = static_cast<uint64_t>(esp_timer_get_time()) / 1000000ULL;
    metrics.hostname = App.get_name().c_str();
    metrics.idf_version = esp_get_idf_version();
#ifdef CONFIG_IDF_TARGET_ESP32S3
    metrics.chip_model = "ESP32-S3";
#else
    metrics.chip_model = "ESP32";
#endif
    metrics.esphome_version = "ESPHome " ESPHOME_VERSION;
    metrics.cores = portNUM_PROCESSORS;
    float temperature;
    if (this->temperature_available_ && this->read_internal_temperature_(temperature)) {
      metrics.has_temperature = true;
      metrics.temperature = temperature;
    }
    encoded = encode_data_response(response.data(), response.size(), request.request_id, metrics, &response_size);
    ESP_LOGD(TAG, "Data response: encoded=%d response=%u", encoded, static_cast<unsigned>(response_size));
  } else if (request.has_request_id && this->is_authenticated_()) {
    encoded = encode_error_response(response.data(), response.size(), request.request_id, "request not supported", &response_size);
  } else {
    ESP_LOGW(TAG, "No response for action=%u: request_id=%d authenticated=%d",
             static_cast<unsigned>(request.action), request.has_request_id, this->is_authenticated_());
  }
  if (encoded && !this->shutting_down_.load()) {
    const int expected = static_cast<int>(response_size);
    const int sent = esp_websocket_client_send_bin(client, reinterpret_cast<const char *>(response.data()), expected,
                                                   pdMS_TO_TICKS(500));
    ESP_LOGD(TAG, "Hub response: requested=%u sent=%d", static_cast<unsigned>(response_size), sent);
    if (sent != expected) {
      // Retrying the remainder would create a second WebSocket message rather
      // than completing the first CBOR response. Reconnect and let the Hub
      // issue a fresh request on a known transport state.
      ESP_LOGW(TAG, "Incomplete Hub response send: requested=%d sent=%d; reconnecting", expected, sent);
      this->clear_authentication_();
      this->reconnect_requested_.store(true);
    } else if (request.action == 1 && this->is_authenticated_()) {
      // Do not publish connected until the authentication response itself has
      // reached the Hub in full.
      this->set_pending_status_(CONNECTED);
    }
  }
}

bool Beszel::factory_fingerprint_(std::string &fingerprint) const {
  uint8_t mac[6]{};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
    ESP_LOGE(TAG, "Unable to read factory Wi-Fi MAC");
    fingerprint.clear();
    return false;
  }
  fingerprint = factory_mac_fingerprint(mac);
  return true;
}

}  // namespace esphome::beszel
