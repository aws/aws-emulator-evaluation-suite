"""compare-faces-match-then-no-face-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "compare-faces-match-then-no-face-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompareFaces matches a real face against itself; a source image with no face is rejected."""
    face_bytes = _fetch_face_image_bytes()
    rek = ctx.client("rekognition")

    # positive control: comparing a real face image against itself finds a match
    matched = rek.compare_faces(SourceImage={"Bytes": face_bytes}, TargetImage={"Bytes": face_bytes})
    face_matches = matched["FaceMatches"]
    assert len(face_matches) >= 1, f"expected >=1 FaceMatches comparing the face image to itself, got {len(face_matches)}"
    similarity = face_matches[0]["Similarity"]
    assert similarity > 90, f"expected Similarity > 90 for an identical face, got {similarity}"

    # negative: a source image with no detectable face is rejected
    no_face_bytes = _solid_color_png_bytes(240, 240, (100, 100, 220))
    code, message = _client_error(
        lambda: rek.compare_faces(SourceImage={"Bytes": no_face_bytes}, TargetImage={"Bytes": face_bytes})
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException for a faceless SourceImage, got {code!r}"
    assert message == "Request has invalid parameters", (
        f"expected the invalid-parameters message for a faceless SourceImage, got {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
