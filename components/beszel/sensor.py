import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import sensor
from esphome.const import (
    ENTITY_CATEGORY_DIAGNOSTIC,
    ICON_MEMORY,
    STATE_CLASS_MEASUREMENT,
    UNIT_BYTES,
)

from . import Beszel


DEPENDENCIES = ["beszel"]
CONF_BESZEL_ID = "beszel_id"
CONF_STACK_HEADROOM = "stack_headroom"

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_BESZEL_ID): cv.use_id(Beszel),
        cv.Required(CONF_STACK_HEADROOM): sensor.sensor_schema(
            accuracy_decimals=0,
            entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
            icon=ICON_MEMORY,
            state_class=STATE_CLASS_MEASUREMENT,
            unit_of_measurement=UNIT_BYTES,
        ),
    }
)


async def to_code(config):
    parent = await cg.get_variable(config[CONF_BESZEL_ID])
    stack_headroom = await sensor.new_sensor(config[CONF_STACK_HEADROOM])
    cg.add(parent.set_stack_headroom_sensor(stack_headroom))
