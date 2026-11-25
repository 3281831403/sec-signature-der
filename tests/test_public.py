import hashlib
import hmac

from engine.sig.der import (
    decode_int,
    decode_signature,
    encode_int,
    encode_signature,
    sig_batch,
    validate_encoding,
    verify_signature,
)

CONTEXT = b"ticket-signature:"
MESSAGE = b"ticket:order-42"
KEY = b"issuer-key-2026"


def _expected_values(message, key):
    digest = hmac.new(key, CONTEXT + message, hashlib.sha256).digest()
    mask = (1 << 127) - 1
    r = int.from_bytes(digest[:16], "big") & mask
    s = int.from_bytes(digest[16:], "big") & mask
    return (r or 1, s or 1)


def _tlv(tag, body):
    size = len(body)
    if size < 0x80:
        return bytes((tag, size)) + body
    width = (size.bit_length() + 7) // 8
    return bytes((tag, 0x80 | width)) + size.to_bytes(width, "big") + body


def _int_body(value):
    if value == 0:
        return b"\x00"
    if value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return b"\x00" + body if body[0] & 0x80 else body
    width = 1
    while value < -(1 << (8 * width - 1)):
        width += 1
    return value.to_bytes(width, "big", signed=True)


def _canonical_int(value):
    return _tlv(0x02, _int_body(value))


def _canonical_signature(r, s):
    return _tlv(0x30, _canonical_int(r) + _canonical_int(s))


def _padded_r_signature(r, s):
    return _tlv(0x30, _tlv(0x02, b"\x00" + _int_body(r)) + _canonical_int(s))


def _rejects(function, *args):
    try:
        function(*args)
    except (TypeError, ValueError):
        return True
    return False


def test_integer_roundtrip_is_minimal():
    assert encode_int(0) == b"\x02\x01\x00"
    assert encode_int(1) == b"\x02\x01\x01"
    assert encode_int(127) == b"\x02\x01\x7f"
    assert encode_int(128) == b"\x02\x02\x00\x80"
    for value in (0, 1, 127, 128, 255, 256, 32767):
        assert decode_int(encode_int(value)) == value


def test_signature_roundtrip_is_stable():
    signature = encode_signature(5, 300)
    decoded = decode_signature(signature)
    assert decoded["r"] == 5
    assert decoded["s"] == 300
    assert validate_encoding(signature) == []


def test_valid_signature_passes():
    r, s = _expected_values(MESSAGE, KEY)
    signature = encode_signature(r, s)
    assert validate_encoding(signature) == []
    assert verify_signature(signature, MESSAGE, KEY) is True


def test_leading_zero_signature_is_rejected():
    r, s = _expected_values(MESSAGE, KEY)
    signature = _padded_r_signature(r, s)
    assert _rejects(decode_signature, signature)
    assert verify_signature(signature, MESSAGE, KEY) is False


def test_batch_members_are_independent():
    message = b"ticket:batch"
    key = b"batch-key"
    good = _canonical_signature(*_expected_values(message, key))
    bad = _canonical_signature(1, 2)
    outcome = sig_batch(
        [
            {"sig": good, "message": message, "key": key},
            {"sig": bad, "message": message, "key": key},
        ]
    )
    assert outcome["results"] == [True, False]
    assert outcome["valid"] == 1
    assert outcome["invalid"] == 1
    assert outcome["total"] == 2