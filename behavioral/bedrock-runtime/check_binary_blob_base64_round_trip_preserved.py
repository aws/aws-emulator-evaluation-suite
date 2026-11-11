"""binary-blob-base64-round-trip-preserved."""
from __future__ import annotations

import base64
import json
import struct
import zlib

from behavioral_harness import tags

CHECK = "binary-blob-base64-round-trip-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

EMBED_IMAGE_MODEL = "amazon.titan-embed-image-v1"
VISION_MODEL = "amazon.nova-lite-v1:0"


def _png_bytes(width: int, height: int, rgb: tuple[int, int, int]) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = bytes(rgb) * width
    raw = (b"\x00" + row) * height
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A base64 image blob sent to InvokeModel arrives intact: it embeds identically twice.

    A different image embeds differently, and Converse on the red image answers "red"."""
    bedrock = ctx.client("bedrock-runtime")

    red_png = base64.b64encode(_png_bytes(16, 16, (220, 20, 20))).decode("ascii")
    blue_png = base64.b64encode(_png_bytes(16, 16, (20, 20, 220))).decode("ascii")

    def _embed(image_b64: str) -> list[float]:
        body = json.dumps({"inputImage": image_b64}).encode("utf-8")
        resp = bedrock.invoke_model(modelId=EMBED_IMAGE_MODEL, body=body, contentType="application/json")
        return json.loads(resp["body"].read())["embedding"]

    embedding_red_1 = _embed(red_png)
    embedding_red_2 = _embed(red_png)
    assert embedding_red_1 == embedding_red_2, "identical base64 blob must yield identical embeddings"

    embedding_blue = _embed(blue_png)
    assert embedding_blue != embedding_red_1, "a genuinely different image must yield a different embedding"

    # Same blob, this time through a multimodal Converse call: the vision model must actually
    # perceive the transmitted pixels (a corrupted/truncated payload would not describe the
    # correct solid color).
    converse_resp = bedrock.converse(
        modelId=VISION_MODEL,
        messages=[
            {
                "role": "user",
                "content": [
                    {"image": {"format": "png", "source": {"bytes": base64.b64decode(red_png)}}},
                    {
                        "text": (
                            "This image is a single solid color square. Reply with only the color "
                            "family in English, one lowercase word (e.g. red, blue, green)."
                        )
                    },
                ],
            }
        ],
        inferenceConfig={"temperature": 0, "maxTokens": 10},
    )
    answer = converse_resp["output"]["message"]["content"][0]["text"].strip().lower()
    assert "red" in answer, f"expected the model to perceive red, got {answer!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
