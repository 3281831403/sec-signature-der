"""DER encoding and signature verification for signed tickets.

The public API works with complete DER values.  ``parse_tlv`` returns one
tag-length-value record, ``decode_int`` and ``decode_signature`` consume
complete encoded values, and the ``encode_*`` functions return complete DER
values ready to be transmitted.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

_TAG_INTEGER = 0x02
_TAG_SEQUENCE = 0x30
_SIGNATURE_CONTEXT = b"ticket-signature:"


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("value must be bytes-like or text")


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("missing length field")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite length is not allowed")
    raw = data[offset : offset + count]
    if not raw:
        length = 0
    else:
        if raw[0] == 0:
            raise ValueError("length field has a leading zero")
        length = int.from_bytes(raw, "big")
        if length < 0x80:
            raise ValueError("length field is not minimally encoded")
    return length, offset + count


def _tlv(tag: int, body: bytes) -> bytes:
    if not 0 <= tag <= 0xFF:
        raise ValueError("tag must fit in one byte")
    size = len(body)
    if size < 0x80:
        header = bytes((tag, size))
    else:
        width = (size.bit_length() + 7) // 8
        if width > 126:
            raise ValueError("value is too large for DER")
        header = bytes((tag, 0x80 | width)) + size.to_bytes(width, "big")
    return header + body


def parse_tlv(data: bytes, offset: int) -> dict[str, Any]:
    """Parse the tag-length-value record starting at *offset*.

    The returned mapping contains ``tag``, ``length``, ``value``, ``start``,
    ``value_offset`` and ``end``.
    """
    data = _as_bytes(data)
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise TypeError("offset must be an integer")
    if offset < 0 or offset >= len(data):
        raise ValueError("offset is outside the input")

    tag = data[offset]
    length, value_offset = _read_length(data, offset + 1)
    value = data[value_offset : value_offset + length]
    return {
        "tag": tag,
        "length": length,
        "value": value,
        "start": offset,
        "value_offset": value_offset,
        "end": value_offset + length,
    }


def decode_int(data: bytes) -> int:
    """Decode one complete DER INTEGER value."""
    data = _as_bytes(data)
    item = parse_tlv(data, 0)
    if item["tag"] != _TAG_INTEGER:
        raise ValueError("expected an INTEGER")
    if item["end"] != len(data):
        raise ValueError("trailing data after INTEGER")

    body = item["value"]
    if not body:
        raise ValueError("INTEGER value is empty")
    if body[0] & 0x80:
        return -int.from_bytes(body, "big")
    return int.from_bytes(body, "big")


def decode_signature(data: bytes) -> dict[str, Any]:
    """Decode a DER SEQUENCE containing two INTEGER values."""
    data = _as_bytes(data)
    sequence = parse_tlv(data, 0)
    if sequence["tag"] != _TAG_SEQUENCE:
        raise ValueError("signature must be a SEQUENCE")

    payload = sequence["value"]
    first = parse_tlv(payload, 0)
    if first["tag"] != _TAG_INTEGER:
        raise ValueError("first signature element must be an INTEGER")
    r = decode_int(payload[first["start"] : first["end"]])

    second = parse_tlv(payload, first["end"])
    if second["tag"] != _TAG_INTEGER:
        raise ValueError("second signature element must be an INTEGER")
    s = decode_int(payload[second["start"] : second["end"]])

    return {"r": r, "s": s, "end": sequence["end"]}


def encode_int(value: int) -> bytes:
    """Encode an integer as a DER INTEGER value."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an integer")

    if value >= 0:
        width = max(1, (value.bit_length() + 7) // 8)
        body = b"\x00" + value.to_bytes(width, "big")
    else:
        magnitude = -value
        width = max(1, (magnitude.bit_length() + 7) // 8)
        body = b"\x80" + magnitude.to_bytes(width, "big")
    return _tlv(_TAG_INTEGER, body)


def encode_signature(r: int, s: int) -> bytes:
    """Encode the pair ``(r, s)`` as a DER SEQUENCE of two INTEGER values."""
    return _tlv(_TAG_SEQUENCE, encode_int(r) + encode_int(s))


def _signature_values(message: Any, key: Any) -> tuple[int, int]:
    message_bytes = _as_bytes(message)
    key_bytes = _as_bytes(key)
    digest = hmac.new(
        key_bytes, _SIGNATURE_CONTEXT + message_bytes, hashlib.sha256
    ).digest()
    mask = (1 << 127) - 1
    r = int.from_bytes(digest[:16], "big") & mask
    s = int.from_bytes(digest[16:], "big") & mask
    return (r or 1, s or 1)


def verify_signature(sig: bytes, message: Any, key: Any) -> bool:
    """Verify *sig* for *message* under *key*.

    The expected pair is derived from the keyed message digest and compared
    with the supplied signature.  Malformed input is reported as a failed
    verification rather than an exception.
    """
    try:
        data = _as_bytes(sig)
        decoded = decode_signature(data)
        if decoded["r"] == 0 and decoded["s"] == 0:
            return False
        normalized = decode_signature(encode_signature(decoded["r"], decoded["s"]))
        expected_r, expected_s = _signature_values(message, key)
        return normalized["r"] == expected_r and normalized["s"] == expected_s
    except (TypeError, ValueError, IndexError):
        return False


def _integer_issue(body: bytes) -> str | None:
    if not body:
        return "INTEGER value is empty"
    if len(body) > 1 and body[0] == 0x00 and body[1] < 0x80:
        return "INTEGER has leading zero padding"
    if len(body) > 1 and body[0] == 0xFF and body[1] >= 0x80:
        return "INTEGER has a non-minimal negative encoding"
    return None


def validate_encoding(sig: bytes) -> list[str]:
    """Return a list of DER encoding problems found in *sig*.

    A valid signature produces an empty list.  The function gathers as many
    independent observations as it can instead of stopping at the first one.
    """
    try:
        data = _as_bytes(sig)
    except TypeError as exc:
        return [str(exc)]
    if not data:
        return ["signature is empty"]

    try:
        sequence = parse_tlv(data, 0)
    except (TypeError, ValueError, IndexError) as exc:
        return [str(exc) or "invalid tag-length-value input"]

    problems: list[str] = []
    if sequence["tag"] != _TAG_SEQUENCE:
        return ["top-level value must be a SEQUENCE"]
    if sequence["end"] > len(data):
        problems.append("SEQUENCE length exceeds the available data")
    elif sequence["end"] < len(data):
        problems.append("trailing data after the SEQUENCE")

    payload = sequence["value"]
    offset = 0
    integer_count = 0
    while offset < len(payload):
        try:
            item = parse_tlv(payload, offset)
        except (TypeError, ValueError, IndexError) as exc:
            problems.append(f"invalid element at offset {offset}: {exc}")
            break
        if item["tag"] != _TAG_INTEGER:
            problems.append(f"element at offset {offset} is not an INTEGER")
        else:
            integer_count += 1
            issue = _integer_issue(item["value"])
            if issue is not None:
                problems.append(issue)
        if item["end"] <= offset:
            problems.append("element does not advance the parser")
            break
        offset = item["end"]

    if integer_count != 2:
        problems.append("SEQUENCE must contain exactly two INTEGER values")
    return problems


def _batch_item(item: Any) -> tuple[bytes, Any, Any]:
    if isinstance(item, Mapping):
        try:
            return item["sig"], item["message"], item["key"]
        except KeyError as exc:
            raise ValueError(f"batch item is missing {exc.args[0]}") from None
    if isinstance(item, (tuple, list)) and len(item) == 3:
        return item[0], item[1], item[2]
    raise TypeError("batch items must be mappings or three-item sequences")


def sig_batch(items: Any) -> dict[str, Any]:
    """Verify a batch of signatures and summarize the outcome.

    Each item is a mapping with ``sig``, ``message`` and ``key`` keys, or a
    three-item sequence in that order.  The result has ``results``, ``valid``,
    ``invalid`` and ``total`` keys.
    """
    results: list[bool] = []
    cached: dict[str, Any] | None = None

    for raw_item in items:
        try:
            sig, message, key = _batch_item(raw_item)
            if cached is None:
                cached = decode_signature(_as_bytes(sig))
            expected_r, expected_s = _signature_values(message, key)
            ok = cached["r"] == expected_r and cached["s"] == expected_s
        except (TypeError, ValueError, IndexError):
            ok = False
        results.append(bool(ok))

    valid = sum(1 for item in results if item)
    return {
        "results": results,
        "valid": valid,
        "invalid": len(results) - valid,
        "total": len(results),
    }