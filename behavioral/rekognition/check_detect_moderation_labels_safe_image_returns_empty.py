"""detect-moderation-labels-safe-image-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-moderation-labels-safe-image-returns-empty"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectModerationLabels on a plain, content-free image succeeds with an empty ModerationLabels list."""
    rek = ctx.client("rekognition")
    image_bytes = _solid_color_png_bytes(200, 200, (245, 245, 250))
    result = rek.detect_moderation_labels(Image={"Bytes": image_bytes})
    assert result["ModerationLabels"] == [], (
        f"expected no moderation labels on a content-free image, got {result['ModerationLabels']}"
    )
    assert result.get("ModerationModelVersion"), (
        "expected a non-empty ModerationModelVersion, proving the image was actually run through "
        f"the moderation model, got {result.get('ModerationModelVersion')!r}"
    )


def _solid_color_png_bytes(width: int, height: int, rgb: tuple) -> bytes:
    import struct
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = bytes([0]) + bytes(rgb) * width
    raw = row * height
    idat = zlib.compress(raw, 9)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
