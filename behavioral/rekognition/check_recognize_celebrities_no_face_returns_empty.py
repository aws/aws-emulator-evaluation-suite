"""recognize-celebrities-no-face-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "recognize-celebrities-no-face-returns-empty"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RecognizeCelebrities on an image with no face succeeds with CelebrityFaces and UnrecognizedFaces both empty; a real face is detected (as an unrecognized face) when one is present."""
    rek = ctx.client("rekognition")

    # positive control: a real face is detected even though it is not a known celebrity, so the
    # empty result below is "no face found", not "this call always returns empty"
    face_bytes = _fetch_face_image_bytes()
    with_face = rek.recognize_celebrities(Image={"Bytes": face_bytes})
    detected = len(with_face["CelebrityFaces"]) + len(with_face["UnrecognizedFaces"])
    assert detected >= 1, f"expected a detected face for the real-face control image, got {with_face}"

    image_bytes = _solid_color_png_bytes(240, 240, (20, 200, 90))
    result = rek.recognize_celebrities(Image={"Bytes": image_bytes})
    assert result["CelebrityFaces"] == [], f"expected no celebrity faces, got {result['CelebrityFaces']}"
    assert result["UnrecognizedFaces"] == [], f"expected no unrecognized faces, got {result['UnrecognizedFaces']}"


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


#: A photograph of one person's face, shipped with the check so no run fetches media. It is the
#: Metropolitan Museum of Art's "Portrait of an Old Chinese Woman" (DP155400, face detail),
#: released CC0 under the Met's Open Access policy, scaled to 320 px wide.
_FACE_IMAGE = "face.jpg"


def _fetch_face_image_bytes() -> bytes:
    from pathlib import Path

    return (Path(__file__).parent / "deployments" / _FACE_IMAGE).read_bytes()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
