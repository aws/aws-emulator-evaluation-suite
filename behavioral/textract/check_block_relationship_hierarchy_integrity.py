"""block-relationship-hierarchy-integrity."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "block-relationship-hierarchy-integrity"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The PAGE -> LINE -> WORD Block graph returned by DetectDocumentText is a real hierarchy:
    the PAGE's CHILD relationship enumerates every LINE, and each LINE's CHILD words concatenate
    back to (approximately) the LINE's own recognized text."""
    png_bytes = _render_text_png(["HELLO WORLD", "SECOND LINE HERE"])
    textract = ctx.client("textract")
    resp = textract.detect_document_text(Document={"Bytes": png_bytes})
    blocks = resp["Blocks"]
    by_id = {b["Id"]: b for b in blocks}

    page_blocks = [b for b in blocks if b["BlockType"] == "PAGE"]
    line_blocks = [b for b in blocks if b["BlockType"] == "LINE"]
    assert len(page_blocks) == 1
    assert len(line_blocks) >= 2

    page = page_blocks[0]
    page_child_ids = set()
    for rel in page.get("Relationships", []):
        if rel["Type"] == "CHILD":
            page_child_ids.update(rel["Ids"])
    line_ids = {b["Id"] for b in line_blocks}
    assert line_ids.issubset(page_child_ids), "PAGE block's CHILD relationship omits some LINE blocks"

    checked_any = False
    for line in line_blocks:
        word_ids = []
        for rel in line.get("Relationships", []):
            if rel["Type"] == "CHILD":
                word_ids.extend(rel["Ids"])
        assert word_ids, f"LINE block {line['Id']} has no CHILD word relationship"
        words = [by_id[wid]["Text"] for wid in word_ids if by_id.get(wid, {}).get("BlockType") == "WORD"]
        assert words, f"LINE block {line['Id']} CHILD ids resolve to no WORD blocks"
        reconstructed = " ".join(words).upper().replace("  ", " ").strip()
        assert reconstructed == line["Text"].upper().strip(), (
            f"LINE text {line['Text']!r} does not match its own child WORD text {reconstructed!r}"
        )
        checked_any = True
    assert checked_any


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
