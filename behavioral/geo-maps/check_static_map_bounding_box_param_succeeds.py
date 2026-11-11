"""static-map-bounding-box-param-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-bounding-box-param-succeeds"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStaticMap with only BoundingBox returns a 300x300 image, and a distant BoundingBox renders different
    bytes.
    """
    client = ctx.client("geo-maps")
    common = dict(FileName="map", Width=300, Height=300, Style="Satellite")

    resp = client.get_static_map(
        BoundingBox="-123.17075,49.26959,-123.08125,49.31429", **common
    )
    blob = resp["Blob"].read()
    assert len(blob) > 0, "GetStaticMap with a standalone BoundingBox returned an empty blob"
    actual_width, actual_height = _image_dimensions(blob)
    assert (actual_width, actual_height) == (300, 300), (
        f"requested 300x300 but decoded image is {actual_width}x{actual_height}"
    )
    assert resp["ContentType"].startswith("image/"), (
        f"expected an image/* content type, got {resp['ContentType']!r}"
    )

    resp_other = client.get_static_map(
        BoundingBox="151.15,-33.95,151.35,-33.75", **common
    )
    blob_other = resp_other["Blob"].read()
    assert len(blob_other) > 0, "GetStaticMap for a second BoundingBox returned an empty blob"
    assert blob != blob_other, (
        "two geographically distant BoundingBox values produced identical image bytes"
    )


def _image_dimensions(blob: bytes) -> tuple[int, int]:
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
