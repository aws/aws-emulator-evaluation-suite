"""detect-document-text-reads-rendered-text."""
from __future__ import annotations

import io
import secrets

from behavioral_harness import tags

CHECK = "detect-document-text-reads-rendered-text"
GROUP = "sync-data-plane"
SERVICES = ["textract"]

# Excludes 0/O, 1/I/Q and other OCR-ambiguous glyphs.
_TOKEN_ALPHABET = "23456789ABCDEFGHJKLMNPRSTUVWXYZ"


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDocumentText actually OCRs the pixels supplied: the recognized LINE text matches
    a token generated fresh for this run, which no recording or canned/fixed response can carry."""
    token = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(8))
    png_bytes = _render_text_png([f"SIM2REAL     {token}", "TEXTRACT     CHECK"])
    textract = ctx.client("textract")
    resp = textract.detect_document_text(Document={"Bytes": png_bytes})

    blocks = resp["Blocks"]
    line_texts = [b["Text"].upper() for b in blocks if b["BlockType"] == "LINE"]
    joined = " ".join(line_texts)
    assert "SIM2REAL" in joined and token in joined, (
        f"expected run-specific token {token!r} in OCR output, got: {line_texts!r}"
    )
    assert "TEXTRACT" in joined and "CHECK" in joined, f"unexpected OCR output: {line_texts!r}"

    word_blocks = [b for b in blocks if b["BlockType"] == "WORD"]
    assert len(word_blocks) >= 4, f"got {len(word_blocks)} word blocks: {[b['Text'] for b in word_blocks]!r}"
    for wb in word_blocks:
        conf = wb["Confidence"]
        assert 0.0 <= conf <= 100.0, f"WORD {wb['Text']!r} confidence out of range: {conf!r}"
        bbox = wb["Geometry"]["BoundingBox"]
        assert 0.0 <= bbox["Left"] <= 1.0 and 0.0 <= bbox["Top"] <= 1.0, (
            f"WORD {wb['Text']!r} bounding box origin out of [0,1]: {bbox!r}"
        )
        assert 0.0 < bbox["Width"] <= 1.0 and 0.0 < bbox["Height"] <= 1.0, (
            f"WORD {wb['Text']!r} bounding box has non-positive extent: {bbox!r}"
        )

    assert resp["DetectDocumentTextModelVersion"], "DetectDocumentText did not report a model version"


def _render_text_png(lines, scale: int = 6) -> bytes:
    from PIL import Image, ImageDraw

    width = 420
    height = 40 * max(len(lines), 1) + 20
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    y = 10
    for line in lines:
        draw.text((10, y), line, fill="black")
        y += 40
    img = img.resize((width * scale, height * scale), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
