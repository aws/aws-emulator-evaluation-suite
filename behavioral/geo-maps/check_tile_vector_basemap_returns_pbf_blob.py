"""tile-vector-basemap-returns-pbf-blob."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-vector-basemap-returns-pbf-blob"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTile on vector.basemap tile 0/0/0 returns application/x-protobuf with a PricingBucket, and the blob
    decodes as Mapbox Vector Tile layers that each carry a name and version 1 or 2.
    """
    client = ctx.client("geo-maps")
    resp = client.get_tile(Tileset="vector.basemap", Z="0", X="0", Y="0")
    blob = resp["Blob"].read()
    assert len(blob) > 0, "expected a non-empty tile blob"
    assert resp["ContentType"] == "application/x-protobuf", (
        f"expected the MVT content type, got {resp['ContentType']!r}"
    )
    assert resp["PricingBucket"], "expected a non-empty PricingBucket header"

    layers = _mvt_layers(blob)
    assert layers, f"no decodable Tile.Layer submessages in blob of {len(blob)} bytes"
    for name, version in layers:
        assert name, "Layer.name (field 1) must be a non-empty string"
        assert version in (1, 2), f"unexpected Layer.version (field 15): {version}"


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _iter_fields(buf: bytes):
    pos = 0
    n = len(buf)
    while pos < n:
        tag, pos = _read_varint(buf, pos)
        field_no, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            value, pos = _read_varint(buf, pos)
        elif wire_type == 1:
            value, pos = buf[pos : pos + 8], pos + 8
        elif wire_type == 2:
            length, pos = _read_varint(buf, pos)
            value, pos = buf[pos : pos + length], pos + length
        elif wire_type == 5:
            value, pos = buf[pos : pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")
        if pos > n:
            raise ValueError("protobuf field overruns buffer")
        yield field_no, wire_type, value


def _mvt_layers(blob: bytes) -> list[tuple[str, int]]:
    """Decode the top-level Tile message's ``repeated Layer layers = 3`` field, and each
    Layer's required ``name`` (field 1) and ``version`` (field 15), per the Mapbox Vector
    Tile spec that the geo-maps ``mvt`` blob format follows. Raises ValueError -- turned
    into an assertion failure by the caller -- on anything that is not well-formed
    protobuf, which a stub returning arbitrary non-empty bytes will not produce."""
    try:
        layers = []
        for field_no, wire_type, value in _iter_fields(blob):
            if field_no == 3 and wire_type == 2:
                name = None
                version = None
                for sub_no, sub_wt, sub_val in _iter_fields(value):
                    if sub_no == 1 and sub_wt == 2:
                        name = sub_val.decode("utf-8")
                    elif sub_no == 15 and sub_wt == 0:
                        version = sub_val
                layers.append((name, version))
        return layers
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        raise AssertionError(f"blob is not well-formed MVT protobuf: {e}") from None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
