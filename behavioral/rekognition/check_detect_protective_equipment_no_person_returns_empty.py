"""detect-protective-equipment-no-person-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-protective-equipment-no-person-returns-empty"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectProtectiveEquipment on an image with no person succeeds with an empty Persons list, and
    the same call against a real person's photo proves the endpoint actually detects a person rather
    than always returning empty."""
    rek = ctx.client("rekognition")

    person_bytes = _fetch_person_image_bytes()
    positive = rek.detect_protective_equipment(Image={"Bytes": person_bytes})
    assert len(positive["Persons"]) >= 1, (
        f"expected at least one detected person on a real photo, got Persons={positive['Persons']!r}"
    )

    empty_bytes = _solid_color_png_bytes(200, 200, (240, 240, 240))
    result = rek.detect_protective_equipment(Image={"Bytes": empty_bytes})
    assert result["Persons"] == [], f"expected no detected persons on a solid-color image, got {result['Persons']!r}"


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


#: A photograph of one person, shipped with the check so no run fetches media. It is the
#: Metropolitan Museum of Art's "Portrait of an Old Chinese Woman" (DP155400, face detail),
#: released CC0 under the Met's Open Access policy, scaled to 320 px wide.
_PERSON_IMAGE = "face.jpg"


def _fetch_person_image_bytes() -> bytes:
    from pathlib import Path

    return (Path(__file__).parent / "deployments" / _PERSON_IMAGE).read_bytes()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
