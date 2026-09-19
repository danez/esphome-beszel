# Firmware Ed25519 verifier test

These configurations exercise the exact reduced-libsodium verifier compiled
into ESPHome firmware. They use fixed public test vectors, fake Beszel
credentials, and disabled Wi-Fi.

Flash the configuration matching the connected board:

```sh
esphome run tests/firmware/esp32-crypto.yaml
esphome run tests/firmware/esp32-s3-crypto.yaml
```

A successful boot prints:

```text
[beszel.crypto_test] PASS: embedded Ed25519 verifier accepted the RFC 8032 vector and rejected all invalid inputs
```

Any failure names the rejected case and marks the test component failed. Flash
the board's normal configuration again after testing.
