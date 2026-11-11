"""glyphs-returns-nonempty-glyph-blob."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glyphs-returns-nonempty-glyph-blob"
GROUP = "data-plane"
SERVICES = ["geo-maps"]

_FONT_STACK = "Noto Sans Regular"


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetGlyphs for a documented, supported font stack and a valid 256-wide unicode range
    must return real glyph bitmap/SDF data, not an empty stub blob."""
    client = ctx.client("geo-maps")
    resp = client.get_glyphs(FontStack=_FONT_STACK, FontUnicodeRange="0-255.pbf")
    blob = resp["Blob"].read()
    assert resp["ContentType"] == "binary/octet-stream", f"unexpected ContentType {resp.get('ContentType')!r}"
    assert resp["ETag"], f"expected a non-empty ETag header, got {resp.get('ETag')!r}"

    # The blob is a glyph PBF: glyphs { stacks (1) { name (1), range (2), glyphs (3) { id (1),
    # bitmap (2), width (3), height (4), ... } } }. Decode it and grade what it carries.
    stacks = [v for f, v in _fields(blob) if f == 1]
    assert len(stacks) == 1, f"expected exactly one font stack in the PBF, got {len(stacks)}"
    stack = _fields(stacks[0])
    names = [v.decode("utf-8") for f, v in stack if f == 1]
    ranges = [v.decode("utf-8") for f, v in stack if f == 2]
    assert names == [_FONT_STACK], f"expected stack name [{_FONT_STACK!r}], got {names!r}"
    assert ranges == ["0-255"], f"expected stack range ['0-255'], got {ranges!r}"
    glyphs = [dict(_fields(v)) for f, v in stack if f == 3]
    ids = sorted(g[1] for g in glyphs)
    assert ids, "the PBF carries no glyphs for the 0-255 range"
    assert all(0 <= i <= 255 for i in ids), f"glyph ids outside the requested 0-255 range: {ids!r}"
    assert ord("A") in ids, f"expected a glyph for 'A' (65) in the Latin range, got ids {ids!r}"
    glyph_a = next(g for g in glyphs if g[1] == ord("A"))
    assert glyph_a.get(2), f"glyph 'A' carries no SDF bitmap: {sorted(glyph_a)!r}"
    assert glyph_a.get(3, 0) > 0 and glyph_a.get(4, 0) > 0, (
        f"glyph 'A' has no extent: width={glyph_a.get(3)!r} height={glyph_a.get(4)!r}"
    )


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def _fields(buf: bytes) -> list[tuple[int, object]]:
    """Decode one protobuf message level: (field number, int or bytes) per field."""
    out: list[tuple[int, object]] = []
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        field, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, pos = _varint(buf, pos)
        elif wire_type == 2:
            length, pos = _varint(buf, pos)
            value, pos = buf[pos : pos + length], pos + length
        elif wire_type == 5:
            value, pos = int.from_bytes(buf[pos : pos + 4], "little"), pos + 4
        elif wire_type == 1:
            value, pos = int.from_bytes(buf[pos : pos + 8], "little"), pos + 8
        else:
            raise AssertionError(f"unsupported protobuf wire type {wire_type} at byte {pos}")
        out.append((field, value))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
