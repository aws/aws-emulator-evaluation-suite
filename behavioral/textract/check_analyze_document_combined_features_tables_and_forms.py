"""analyze-document-combined-features-tables-and-forms."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "analyze-document-combined-features-tables-and-forms"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single AnalyzeDocument call with FeatureTypes=[TABLES, FORMS] extracts both a TABLE (with
    CELL children) and a KEY_VALUE_SET pair from the same rendered page."""
    png_bytes = _render_table_and_form_png()
    textract = ctx.client("textract")
    resp = textract.analyze_document(Document={"Bytes": png_bytes}, FeatureTypes=["TABLES", "FORMS"])

    blocks = resp["Blocks"]
    by_id = {b["Id"]: b for b in blocks}

    def _child_words_text(block) -> str:
        words = []
        for rel in block.get("Relationships", []):
            if rel["Type"] == "CHILD":
                for cid in rel["Ids"]:
                    child = by_id.get(cid)
                    if child and child["BlockType"] == "WORD":
                        words.append(child["Text"])
        return " ".join(words).upper()

    table_blocks = [b for b in blocks if b["BlockType"] == "TABLE"]
    assert table_blocks, "no TABLE block detected in the rendered grid"

    cell_ids = []
    for rel in table_blocks[0].get("Relationships", []):
        if rel["Type"] == "CHILD":
            cell_ids.extend(rel["Ids"])
    cells = [by_id[cid] for cid in cell_ids if by_id.get(cid, {}).get("BlockType") == "CELL"]
    assert len(cells) >= 4, f"expected at least 4 table cells, got {len(cells)}"

    cell_texts = [_child_words_text(c) for c in cells]
    for expected in ("ITEM", "PRICE", "WIDGET", "10.00"):
        assert any(expected in t for t in cell_texts), (
            f"expected a table cell containing {expected!r} rendered into the grid, got {cell_texts!r}"
        )

    kv_blocks = [b for b in blocks if b["BlockType"] == "KEY_VALUE_SET"]
    key_blocks = [b for b in kv_blocks if "KEY" in b.get("EntityTypes", [])]
    value_blocks = [b for b in kv_blocks if "VALUE" in b.get("EntityTypes", [])]
    assert key_blocks, "no KEY_VALUE_SET block tagged as a KEY detected alongside the table"
    assert value_blocks, "no KEY_VALUE_SET block tagged as a VALUE detected alongside the table"

    key_texts = [_child_words_text(b) for b in key_blocks]
    assert any("NAME" in t for t in key_texts), (
        f"expected a NAME key rendered into the form region, got {key_texts!r}"
    )


def _render_table_and_form_png(scale: int = 6) -> bytes:
    from PIL import Image, ImageDraw

    width, height = 420, 260
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "Name: Test User", fill="black")

    x0, y0 = 10, 60
    cell_w, cell_h = 180, 50
    ncols, nrows = 2, 2
    for r in range(nrows + 1):
        y = y0 + r * cell_h
        draw.line([(x0, y), (x0 + ncols * cell_w, y)], fill="black", width=2)
    for c in range(ncols + 1):
        x = x0 + c * cell_w
        draw.line([(x, y0), (x, y0 + nrows * cell_h)], fill="black", width=2)

    headers = ["Item", "Price"]
    data_row = ["Widget", "10.00"]
    for c, text in enumerate(headers):
        draw.text((x0 + c * cell_w + 10, y0 + 15), text, fill="black")
    for c, text in enumerate(data_row):
        draw.text((x0 + c * cell_w + 10, y0 + cell_h + 15), text, fill="black")

    img = img.resize((width * scale, height * scale), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
