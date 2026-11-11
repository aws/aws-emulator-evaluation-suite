"""detect-document-text-blank-image-returns-no-words."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "detect-document-text-blank-image-returns-no-words"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A genuinely blank white image yields zero WORD/LINE blocks: the response reflects the
    actual (empty) pixel content rather than a fixed sample OCR payload."""
    png_bytes = _render_blank_png()
    textract = ctx.client("textract")
    resp = textract.detect_document_text(Document={"Bytes": png_bytes})

    blocks = resp["Blocks"]
    word_blocks = [b for b in blocks if b["BlockType"] == "WORD"]
    line_blocks = [b for b in blocks if b["BlockType"] == "LINE"]
    assert word_blocks == [], f"expected no WORD blocks on a blank page, got {word_blocks!r}"
    assert line_blocks == [], f"expected no LINE blocks on a blank page, got {line_blocks!r}"

    page_blocks = [b for b in blocks if b["BlockType"] == "PAGE"]
    assert len(page_blocks) == 1, f"expected exactly one PAGE block, got {len(page_blocks)}: {page_blocks!r}"


def _render_blank_png() -> bytes:
    from PIL import Image

    img = Image.new("RGB", (800, 400), "white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
