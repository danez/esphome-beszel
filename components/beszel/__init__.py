import base64
import struct
from urllib.parse import urlparse

import esphome.codegen as cg
import esphome.config_validation as cv
import esphome.final_validate as fv
from esphome.components import esp32
from esphome.const import CONF_ID, KEY_CORE, KEY_TARGET_FRAMEWORK, KEY_VARIANT
from esphome.core import CORE

DEPENDENCIES = ["network"]
AUTO_LOAD = ["sensor", "text_sensor"]
CONF_HUB = "hub"
CONF_TOKEN = "token"
CONF_KEY = "key"
AGENT_ENDPOINT = "/api/beszel/agent-connect"

beszel_ns = cg.esphome_ns.namespace("beszel")
Beszel = beszel_ns.class_("Beszel", cg.Component)


def validate_hub(value):
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise cv.Invalid("hub must be an absolute http:// or https:// URL")
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        parsed.port  # Validate bracket and port syntax even though netloc is preserved below.
    except ValueError as err:
        raise cv.Invalid("hub must be an absolute http:// or https:// URL") from err
    if parsed.scheme not in ("http", "https") or not hostname:
        raise cv.Invalid("hub must be an absolute http:// or https:// URL with a host")
    if parsed.username is not None or parsed.password is not None:
        raise cv.Invalid("hub must not contain credentials")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in hostname):
        raise cv.Invalid("hub contains an invalid host")
    if parsed.query or parsed.fragment:
        raise cv.Invalid("hub must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    # Accept either a Hub base URL or the full endpoint. This makes generated
    # configuration stable when a user copies the endpoint from another agent.
    if not path.endswith(AGENT_ENDPOINT):
        path += AGENT_ENDPOINT
    scheme = "ws" if parsed.scheme == "http" else "wss"
    return f"{scheme}://{parsed.netloc}{path}"


def validate_token(value):
    if not isinstance(value, str) or not value:
        raise cv.Invalid("token must be non-empty")
    if len(value.encode("utf-8")) > 64:
        raise cv.Invalid("token must be at most 64 UTF-8 bytes")
    # The token is inserted verbatim into an HTTP header. Reject both ASCII
    # controls and Unicode C1 controls so it cannot terminate or inject headers.
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise cv.Invalid("token must not contain control characters")
    return value


def _read_ssh_field(data, offset):
    if offset + 4 > len(data):
        raise cv.Invalid("key has truncated SSH wire fields")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    end = offset + length
    if end > len(data):
        raise cv.Invalid("key has truncated SSH wire fields")
    return data[offset:end], end


def validate_key(value):
    if not isinstance(value, str):
        raise cv.Invalid("key must be an ssh-ed25519 public-key line")
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise cv.Invalid("key must begin with ssh-ed25519 and may have a trailing comment")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except Exception as err:
        raise cv.Invalid("key has invalid base64 data") from err
    algorithm, offset = _read_ssh_field(blob, 0)
    public_key, offset = _read_ssh_field(blob, offset)
    if algorithm != b"ssh-ed25519" or len(public_key) != 32 or offset != len(blob):
        raise cv.Invalid("key has invalid ssh-ed25519 wire fields")
    return tuple(public_key)


def validate_target(config):
    if CORE.target_platform != "esp32":
        raise cv.Invalid("beszel supports only ESP32 and ESP32-S3 targets")
    core_data = CORE.data[KEY_CORE]
    if core_data.get(KEY_TARGET_FRAMEWORK) != "esp-idf":
        raise cv.Invalid("beszel requires the ESP-IDF framework")
    if CORE.data.get("esp32", {}).get(KEY_VARIANT) not in ("ESP32", "ESP32S3"):
        raise cv.Invalid("beszel supports only ESP32 and ESP32-S3 targets")
    return config


def _internal_temperature_sensors(full_config):
    return [
        sensor_config
        for sensor_config in full_config.get("sensor", [])
        if sensor_config.get("platform") == "internal_temperature"
    ]


def validate_internal_temperature_count(config):
    internal_temperature_sensors = _internal_temperature_sensors(fv.full_config.get())
    if len(internal_temperature_sensors) > 1:
        raise cv.Invalid(
            "beszel cannot choose between multiple internal_temperature sensors; "
            "configure at most one"
        )
    return config


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(Beszel),
            cv.Required(CONF_HUB): cv.All(cv.string_strict, validate_hub),
            cv.Required(CONF_TOKEN): validate_token,
            cv.Required(CONF_KEY): validate_key,
        }
    ),
    validate_target,
)

FINAL_VALIDATE_SCHEMA = validate_internal_temperature_count


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    esp32.require_certificate_bundle()
    esp32.add_idf_component(name="espressif/esp_websocket_client", ref="1.8.0")
    # Declare this directly even when API encryption also brings it through
    # noise-c; keep the exact version aligned with the supported ESPHome release.
    cg.add_library("esphome/libsodium", "1.10021.11")
    # ESPHome places external IDF archives before the generated source archive.
    # Keep the fingerprint hash symbol live so the static linker extracts it.
    cg.add_build_flag("-Wl,--undefined=crypto_hash_sha256")
    cg.add(var.set_hub(config[CONF_HUB]))
    cg.add(var.set_token(config[CONF_TOKEN]))
    key = ", ".join(f"0x{byte:02x}" for byte in config[CONF_KEY])
    cg.add(var.set_public_key(cg.RawExpression(f"std::array<uint8_t, 32>{{{key}}}")))

    internal_temperature_sensors = _internal_temperature_sensors(CORE.config)
    if internal_temperature_sensors:
        # Reuse the user's sensor so only one component owns the ESP32-S3
        # temperature driver. With no configured sensor, Beszel uses its own
        # hidden reader and remains zero-configuration.
        temperature_sensor = await cg.get_variable(
            internal_temperature_sensors[0][CONF_ID]
        )
        cg.add(var.set_temperature_sensor(temperature_sensor))
