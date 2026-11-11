"""glyphs-different-unicode-ranges-return-different-blobs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glyphs-different-unicode-ranges-return-different-blobs"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Fetching two distinct, non-overlapping 256-wide unicode ranges for the same font
    stack must yield different glyph payloads -- proof the service actually renders the
    requested range rather than returning a fixed/cached blob regardless of input."""
    client = ctx.client("geo-maps")
    font_stack = "Noto Sans Regular"

    resp_a = client.get_glyphs(FontStack=font_stack, FontUnicodeRange="0-255.pbf")
    resp_b = client.get_glyphs(FontStack=font_stack, FontUnicodeRange="256-511.pbf")

    blob_a = resp_a["Blob"].read()
    blob_b = resp_b["Blob"].read()

    assert len(blob_a) > 0, f"expected non-empty glyph blob for range 0-255, got {len(blob_a)} bytes"
    assert len(blob_b) > 0, f"expected non-empty glyph blob for range 256-511, got {len(blob_b)} bytes"
    assert blob_a != blob_b, "different unicode ranges returned identical glyph blobs"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
