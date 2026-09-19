# ESPHome Beszel

An ESPHome external component that connects an ESP32 directly to a Beszel Hub
as a lightweight outbound WebSocket agent. It does not require an inbound port
or a separate Beszel agent process.

## Requirements

- [Beszel Hub](https://beszel.dev/) 0.19.x or 0.20.x
- [ESPHome](https://github.com/esphome/esphome) 2026.9.0
- [ESP-IDF](https://github.com/espressif/esp-idf) framework
- ESP32 or ESP32-S3

Arduino and other ESP32 variants are rejected during configuration. The
component currently pins the ESPHome libsodium package used by ESPHome 2026.9,
so other ESPHome releases are not supported yet.

## Installation

Add this repository as an external component:

```yaml
external_components:
  - source: github://danez/esphome-beszel
    components: [beszel]
```

Then configure the Hub connection:

```yaml
beszel:
  hub: https://beszel.example.com
  token: !secret beszel_token
  key: !secret beszel_hub_public_key
```

`hub` may be the Hub base URL or the complete
`/api/beszel/agent-connect` endpoint. HTTPS is converted to secure WebSocket
transport automatically.

To register one device manually, open **Add System** in Beszel and copy its
token and Ed25519 public key. To let the device create its own system, enable a
universal token under **Settings → Tokens & fingerprints** and copy that token
and its public key instead. Keep tokens in ESPHome's `secrets.yaml`; neither
value needs to be committed.

## Optional status sensor

The connection state can be exposed to Home Assistant:

```yaml
text_sensor:
  - platform: beszel
    status:
      name: Beszel Status
```

It publishes only `disconnected`, `connecting`, `authenticating`, or
`connected`. State publication occurs from ESPHome's main loop, not from the
WebSocket callback task.

## Reported data

The component reports:

- internal heap total, usage, and percentage
- physical flash capacity and running firmware image size
- monotonic uptime
- built-in chip temperature as `SoC`, when available
- ESPHome and ESP-IDF versions, chip model, core count, and node name

CPU usage, network throughput, filesystem usage, containers, load, swap,
battery, and other unavailable metrics are deliberately not fabricated. Small
heap values may appear rounded incorrectly in current Beszel charts even though
the transmitted byte and GiB values are correct. Beszel 0.20 network monitoring
is not supported; the component advertises the 0.19 agent capability level so
the Hub does not expose or request that feature.

## Flash usage

On an `esp32dev` build with ESPHome 2026.9.0 and ESP-IDF 5.5.5, adding the
component increases the firmware image by approximately 139 KiB when ESPHome
API encryption is enabled, or 150 KiB without API encryption. The smaller
increase with API encryption is because libsodium is already linked into the
firmware. These figures include the component's secure WebSocket, TLS, and
cryptographic dependencies.

## TLS and security

Secure connections use ESP-IDF's built-in Common CA bundle and verify the Hub
certificate. This works with publicly trusted certificates such as Let's
Encrypt. Custom CA certificates are not supported in the first release, and
certificate verification cannot be disabled.

HTTPS is required. Plain `http://` URLs are rejected because they would expose
the token and WebSocket traffic without transport encryption.

The Hub authenticates by signing the configured token with Ed25519. The agent
uses the factory Wi-Fi MAC to derive a stable fingerprint for per-system and
universal-token registration.

## Local development

Point ESPHome at the repository's component directory:

```yaml
external_components:
  - source:
      type: local
      path: ../components
```

The complete development configurations are in `examples/`. Create
`examples/secrets.yaml` with `wifi_ssid`, `wifi_password`, `noise_key`,
`beszel_token`, and `beszel_hub_public_key`, then compile with:

```sh
esphome compile examples/esp32.yaml
esphome compile examples/esp32-s3.yaml
```

The ESP32-S3 example also demonstrates sharing ESPHome's
`internal_temperature` sensor. Without one, Beszel creates a hidden reader; it
never exposes a second Home Assistant temperature entity.

## License

MIT
