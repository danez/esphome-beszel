import esphome.codegen as cg
import esphome.config_validation as cv


DEPENDENCIES = ["beszel"]

beszel_crypto_test_ns = cg.esphome_ns.namespace("beszel_crypto_test")
BeszelCryptoTest = beszel_crypto_test_ns.class_("BeszelCryptoTest", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(BeszelCryptoTest),
    }
).extend(cv.COMPONENT_SCHEMA)


async def to_code(config):
    var = cg.new_Pvariable(config[cv.CONF_ID])
    await cg.register_component(var, config)
