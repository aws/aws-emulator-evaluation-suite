"""detect-faces-no-face-image-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-faces-no-face-image-returns-empty"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectFaces finds a real face with a plausible confidence; an image with no detectable face succeeds with an empty FaceDetails list, not an error."""
    rek = ctx.client("rekognition")

    # positive control: a real face image is actually detected, so the negative below cannot
    # be satisfied merely by a target that never detects any face at all
    face_bytes = _fetch_face_image_bytes()
    found = rek.detect_faces(Image={"Bytes": face_bytes})
    assert len(found["FaceDetails"]) >= 1, f"expected >=1 FaceDetails for a real face image, got {found['FaceDetails']!r}"
    detail = found["FaceDetails"][0]
    assert detail["Confidence"] > 50, f"expected face Confidence > 50, got {detail['Confidence']!r}"

    # negative: an image with no detectable face succeeds with an empty list, not an error
    no_face_bytes = _solid_color_png_bytes(240, 240, (60, 90, 140))
    result = rek.detect_faces(Image={"Bytes": no_face_bytes})
    assert result["FaceDetails"] == [], f"expected empty FaceDetails for a no-face image, got {result['FaceDetails']!r}"


#: A photograph of one person's face, shipped with the check so no run fetches media. It is the
#: Metropolitan Museum of Art's "Portrait of an Old Chinese Woman" (DP155400, face detail),
#: released CC0 under the Met's Open Access policy, scaled to 320 px wide.
_FACE_IMAGE = "face.jpg"


def _fetch_face_image_bytes() -> bytes:
    from pathlib import Path

    return (Path(__file__).parent / "deployments" / _FACE_IMAGE).read_bytes()


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
