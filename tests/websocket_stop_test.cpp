#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "../components/beszel/websocket_stop.h"
#include "freertos/task.h"

struct FakeWebSocketClient {
  std::mutex mutex;
  std::condition_variable condition;
  bool stop_entered{false};
  bool release_stop{false};
  bool destroy_entered{false};
  bool release_destroy{false};
  std::atomic<bool> destroyed{false};
};

static const auto MAIN_TASK = std::this_thread::get_id();
static std::thread worker;
static bool fail_task_creation = false;
static unsigned task_count = 0;

int xTaskCreate(void (*entry)(void *), const char *, uint32_t, void *arg, unsigned, TaskHandle_t *) {
  if (fail_task_creation)
    return 0;
  task_count++;
  worker = std::thread(entry, arg);
  return pdPASS;
}

void vTaskDelete(TaskHandle_t) { assert(std::this_thread::get_id() != MAIN_TASK); }

int esp_websocket_client_stop(esp_websocket_client_handle_t client) {
  assert(std::this_thread::get_id() != MAIN_TASK);
  std::unique_lock<std::mutex> lock(client->mutex);
  client->stop_entered = true;
  client->condition.notify_one();
  // Model a transport handshake that cannot be interrupted by stop().
  client->condition.wait(lock, [&] { return client->release_stop; });
  return 0;
}

int esp_websocket_client_destroy(esp_websocket_client_handle_t client) {
  assert(std::this_thread::get_id() != MAIN_TASK);
  std::unique_lock<std::mutex> lock(client->mutex);
  assert(client->release_stop);
  client->destroy_entered = true;
  client->condition.notify_one();
  client->condition.wait(lock, [&] { return client->release_destroy; });
  assert(!client->destroyed.exchange(true));
  return 0;
}

static void stalled_stop_keeps_main_task_responsive(esphome::beszel::WebSocketStop &stop,
                                                    FakeWebSocketClient &client) {
  assert(stop.start(&client));
  assert(stop.pending());
  {
    std::unique_lock<std::mutex> lock(client.mutex);
    assert(client.condition.wait_for(lock, std::chrono::seconds(2), [&] { return client.stop_entered; }));
  }
  // Reconnect and shutdown polling must return while the worker is blocked.
  const auto tasks_before = task_count;
  for (unsigned i = 0; i < 1000; i++) {
    assert(!stop.poll());
    assert(!stop.start(&client));
    assert(!client.destroyed.load());
  }
  assert(task_count == tasks_before);
  {
    std::lock_guard<std::mutex> lock(client.mutex);
    client.release_stop = true;
  }
  client.condition.notify_one();
  {
    std::unique_lock<std::mutex> lock(client.mutex);
    assert(client.condition.wait_for(lock, std::chrono::seconds(2), [&] { return client.destroy_entered; }));
    // Completion must cover destruction too, before another client can start.
    assert(!stop.poll());
    assert(!stop.start(&client));
    assert(!client.destroyed.load());
    client.release_destroy = true;
  }
  client.condition.notify_one();
  worker.join();
  assert(client.destroyed.load());
  assert(stop.poll());
  assert(!stop.pending());
  assert(stop.poll());
}

int main() {
  esphome::beszel::WebSocketStop stop;
  assert(stop.poll());
  assert(!stop.start(nullptr));
  FakeWebSocketClient first_client;
  stalled_stop_keeps_main_task_responsive(stop, first_client);
  // Low memory must leave the caller's live client untouched and allow retry.
  FakeWebSocketClient client;
  fail_task_creation = true;
  assert(!stop.start(&client));
  assert(!stop.pending());
  assert(stop.poll());
  assert(!client.destroyed.load() && !client.stop_entered);
  fail_task_creation = false;
  stalled_stop_keeps_main_task_responsive(stop, client);
}
