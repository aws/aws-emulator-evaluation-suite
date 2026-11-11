"""analyze-expense-extracts-summary-fields."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "analyze-expense-extracts-summary-fields"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AnalyzeExpense OCRs a rendered receipt and returns non-empty SummaryFields whose detected
    text reflects the actual rendered amount, not a canned sample receipt."""
    png_bytes = _render_text_png(["RECEIPT", "TOTAL $12.34", "DATE 01/02/2023"])
    textract = ctx.client("textract")
    resp = textract.analyze_expense(Document={"Bytes": png_bytes})

    docs = resp["ExpenseDocuments"]
    assert docs, "AnalyzeExpense returned no ExpenseDocuments"
    expense_doc = docs[0]
    assert expense_doc["SummaryFields"], "no SummaryFields extracted from the receipt"

    all_block_text = " ".join(b["Text"].upper() for b in expense_doc["Blocks"] if "Text" in b)
    assert "12.34" in all_block_text, f"expected the rendered amount in OCR text: {all_block_text!r}"
    assert "TOTAL" in all_block_text, f"expected TOTAL label in OCR text: {all_block_text!r}"


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
