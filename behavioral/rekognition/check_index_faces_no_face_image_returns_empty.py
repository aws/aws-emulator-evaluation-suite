"""index-faces-no-face-image-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "index-faces-no-face-image-returns-empty"
GROUP = "data-plane"
SERVICES = ["rekognition"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """IndexFaces on an image with no detectable face succeeds with empty FaceRecords/UnindexedFaces, not an error."""
    rek = ctx.client("rekognition")
    collection_id = ctx.unique_name("sim2real-rek-noface-")
    rek.create_collection(CollectionId=collection_id)
    ctx.on_cleanup(lambda: rek.delete_collection(CollectionId=collection_id))

    image_bytes = _solid_color_png_bytes(240, 240, (180, 140, 90))
    result = rek.index_faces(CollectionId=collection_id, Image={"Bytes": image_bytes})

    assert result["FaceRecords"] == []
    assert result["UnindexedFaces"] == []

    described = rek.describe_collection(CollectionId=collection_id)
    assert described["FaceCount"] == 0


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
