# MQTT `decode_varint` cast bug (no CVE assigned)

**Source:** [cesanta/mongoose@d44b9b9](https://github.com/cesanta/mongoose/commit/d44b9b9adfda77e7c46e6b0e6e20ef8c8303cf68) — "Fix casting issue in MQTT parsing", merged via PR #3527 ("mqtt-cast"), 2026-05-07.

## What was wrong

`decode_varint()` in `src/mqtt.c` decoded an MQTT variable-length integer
(used for property lengths in MQTT 5 property parsing) into a caller-
supplied output pointer:

```c
static size_t decode_varint(const uint8_t *buf, size_t len, size_t *value) {
  size_t multiplier = 1, offset;
  *value = 0;
  for (offset = 0; offset < 4 && offset < len; offset++) {
    uint8_t encoded_byte = buf[offset];
    *value += (encoded_byte & 0x7f) * multiplier;
    multiplier *= 128;
    if ((encoded_byte & 0x80) == 0) return offset + 1;
  }
  return 0;
}
```

Its only call site (`mg_mqtt_next_prop`) passed `(uint32_t *) &m->props_size`
— but `m->props_size` is declared as a 4-byte `uint32_t`, while
`decode_varint`'s parameter type is `size_t *` (8 bytes on a 64-bit host).
Every `*value = 0` / `*value += ...` inside the function wrote through an
8-byte pointer into a location the caller only allocated 4 bytes for —
corrupting whatever field sits immediately after `props_size` in
`struct mg_mqtt_message` on every property parsed.

## The fix

`decode_varint`'s signature changes to `uint32_t *value`, matching its
only real caller exactly, and the internal `multiplier`/`offset` locals
narrow to `uint32_t` to match.

## Why this matters

This is a parser-state corruption bug triggered by ordinary, valid-looking
MQTT 5 packets with properties (CONNECT, PUBLISH, SUBSCRIBE all carry MQTT
5 properties) — no malformed input is even required, just the type
mismatch firing on every property parsed. Adjacent struct fields getting
silently overwritten is exactly the kind of protocol-state defect an LLM
reviewer should flag from the diff alone: the signature change from
`size_t *` to `uint32_t *` combined with the single calling convention is
visible without needing to run the code.
