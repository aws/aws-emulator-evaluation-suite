"""static-map-pixel-dimensions-match-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-pixel-dimensions-match-request"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStaticMap at 1x resolution (FileName="map") returns a real image whose encoded
    pixel dimensions equal the requested Width/Height, not just a 200 with an opaque blob."""
    client = ctx.client("geo-maps")
    width, height = 320, 240
    resp = client.get_static_map(
        FileName="map",
        Width=width,
        Height=height,
        Style="Satellite",
        Center="-123.108,49.295",
        Zoom=10.0,
    )
    blob = resp["Blob"].read()
    assert len(blob) > 0, f"expected a non-empty image blob, got {len(blob)} bytes"
    actual_width, actual_height = _image_dimensions(blob)
    assert (actual_width, actual_height) == (width, height), (
        f"requested {width}x{height} but decoded image is {actual_width}x{actual_height}"
    )
    assert resp["ContentType"].startswith("image/"), (
        f"expected an image/* ContentType, got {resp['ContentType']!r}"
    )
    assert resp["PricingBucket"], f"expected a non-empty PricingBucket, got {resp['PricingBucket']!r}"
    # ETag is documented but not consistently populated by the live service for every
    # style/format combination; only assert non-emptiness when the header is present.
    if "ETag" in resp:
        assert resp["ETag"], f"ETag header present but empty: {resp['ETag']!r}"


def _image_dimensions(blob: bytes) -> tuple[int, int]:
    """Parse pixel (width, height) out of a PNG or JPEG byte blob without external deps."""
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        width = int.from_bytes(blob[16:20], "big")
        height = int.from_bytes(blob[20:24], "big")
        return width, height
    if blob[:2] == b"\xff\xd8":
        idx = 2
        n = len(blob)
        while idx + 4 <= n:
            if blob[idx] != 0xFF:
                idx += 1
                continue
            marker = blob[idx + 1]
            if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                idx += 2
                continue
            length = int.from_bytes(blob[idx + 2 : idx + 4], "big")
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                height = int.from_bytes(blob[idx + 5 : idx + 7], "big")
                width = int.from_bytes(blob[idx + 7 : idx + 9], "big")
                return width, height
            idx += 2 + length
        raise ValueError("no SOF marker found in JPEG blob")
    raise ValueError(f"unrecognized image format, magic bytes={blob[:8]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
