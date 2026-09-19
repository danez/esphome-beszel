import importlib.util
from pathlib import Path

import esphome.config_validation as cv
import esphome.final_validate as fv


component_path = Path(__file__).parents[1] / "components" / "beszel" / "__init__.py"
spec = importlib.util.spec_from_file_location("beszel_component", component_path)
beszel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(beszel)


def rejects(validator, value):
    try:
        validator(value)
    except cv.Invalid:
        return True
    return False


assert beszel.validate_token("ordinary-token_123") == "ordinary-token_123"
assert rejects(beszel.validate_token, "header\r\nInjected: value")
assert rejects(beszel.validate_token, "nul\0byte")
assert rejects(beszel.validate_token, "tab\tbyte")
assert rejects(beszel.validate_token, "unicode-control\u0085byte")

endpoint = "/api/beszel/agent-connect"
assert rejects(beszel.validate_hub, "http://hub.local")
assert beszel.validate_hub("https://hub.example/base/") == f"wss://hub.example/base{endpoint}"
assert beszel.validate_hub(f"https://hub.example{endpoint}") == f"wss://hub.example{endpoint}"
assert beszel.validate_hub(f"https://hub.example{endpoint}/") == f"wss://hub.example{endpoint}"
assert beszel.validate_hub("https://[::1]:8090") == f"wss://[::1]:8090{endpoint}"
assert rejects(beszel.validate_hub, "ftp://hub.example")
assert rejects(beszel.validate_hub, "https:///missing-host")
assert rejects(beszel.validate_hub, "https://bad host")
assert rejects(beszel.validate_hub, "https://hub.example:bad")
assert rejects(beszel.validate_hub, "https://user:pass@hub.example")
assert rejects(beszel.validate_hub, "https://hub.example?query=yes")
assert rejects(beszel.validate_hub, "https://hub.example#fragment")
assert rejects(beszel.validate_hub, "https://hub.example\r\nInjected: value")

assert len(
    beszel._internal_temperature_sensors(
        {
            "sensor": [
                {"platform": "internal_temperature"},
                {"platform": "internal_temperature"},
            ]
        }
    )
) == 2

full_config_token = fv.full_config.set(
    {
        "sensor": [
            {"platform": "internal_temperature"},
            {"platform": "internal_temperature"},
        ]
    }
)
try:
    assert rejects(beszel.validate_internal_temperature_count, {})
finally:
    fv.full_config.reset(full_config_token)
