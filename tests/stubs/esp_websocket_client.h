#pragma once

struct FakeWebSocketClient;
using esp_websocket_client_handle_t = FakeWebSocketClient *;
int esp_websocket_client_stop(esp_websocket_client_handle_t client);
int esp_websocket_client_destroy(esp_websocket_client_handle_t client);
