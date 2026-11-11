"""static-map-2x-filename-higher-resolution."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-2x-filename-higher-resolution"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FileName="map@2x" is documented as a retina/high-density variant of "map"; for the
    same logical Width/Height it must decode to pixel dimensions exactly double the 1x
    file's, not identical, smaller, or merely larger by some other factor."""
    client = ctx.client("geo-maps")
    common = dict(Width=256, Height=256, Style="Satellite", Center="-123.108,49.295", Zoom=10.0)

    resp_1x = client.get_static_map(FileName="map", **common)
    resp_2x = client.get_static_map(FileName="map@2x", **common)

    blob_1x = resp_1x["Blob"].read()
    blob_2x = resp_2x["Blob"].read()
    assert len(blob_1x) > 0 and len(blob_2x) > 0, (
        f"expected non-empty image blobs, got {len(blob_1x)} (1x) and {len(blob_2x)} (2x) bytes"
    )

    width_1x, height_1x = _image_dimensions(blob_1x)
    width_2x, height_2x = _image_dimensions(blob_2x)

    assert width_2x == 2 * width_1x, (
        f"expected @2x width to be exactly 2x the 1x width, got {width_2x} vs 2*{width_1x}={2 * width_1x}"
    )
    assert height_2x == 2 * height_1x, (
        f"expected @2x height to be exactly 2x the 1x height, got {height_2x} vs 2*{height_1x}={2 * height_1x}"
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
