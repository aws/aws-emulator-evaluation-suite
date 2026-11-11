"""analyze-document-queries-feature-returns-query-block."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "analyze-document-queries-feature-returns-query-block"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """AnalyzeDocument with FeatureTypes=[QUERIES] echoes the submitted question/alias back on a
    QUERY block, and links it to a QUERY_RESULT via an ANSWER relationship."""
    png_bytes = _render_text_png(["Invoice Number: INV-99887"])
    textract = ctx.client("textract")
    resp = textract.analyze_document(
        Document={"Bytes": png_bytes},
        FeatureTypes=["QUERIES"],
        QueriesConfig={
            "Queries": [{"Text": "What is the invoice number?", "Alias": "INVOICE_NUMBER"}]
        },
    )

    blocks = resp["Blocks"]
    query_blocks = [b for b in blocks if b["BlockType"] == "QUERY"]
    assert len(query_blocks) == 1, f"expected exactly one QUERY block, got {len(query_blocks)}"
    query_block = query_blocks[0]
    assert query_block["Query"]["Text"] == "What is the invoice number?", (
        f"expected the QUERY block to echo the submitted question text, got {query_block['Query']!r}"
    )
    assert query_block["Query"]["Alias"] == "INVOICE_NUMBER", (
        f"expected the QUERY block to echo the submitted alias, got {query_block['Query']!r}"
    )

    answer_ids = []
    for rel in query_block.get("Relationships", []):
        if rel["Type"] == "ANSWER":
            answer_ids.extend(rel["Ids"])
    assert answer_ids, "QUERY block has no ANSWER relationship to a QUERY_RESULT block"

    by_id = {b["Id"]: b for b in blocks}
    answer_texts = []
    for aid in answer_ids:
        result_block = by_id[aid]
        assert result_block["BlockType"] == "QUERY_RESULT", (
            f"ANSWER relationship id {aid!r} resolves to a {result_block['BlockType']} block, "
            "not QUERY_RESULT"
        )
        answer_texts.append(result_block.get("Text", ""))
    assert any("99887" in text.replace(" ", "") for text in answer_texts), (
        "QUERY_RESULT text does not contain the invoice number rendered into the document "
        f"pixels ('INV-99887'); got {answer_texts!r}"
    )


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
