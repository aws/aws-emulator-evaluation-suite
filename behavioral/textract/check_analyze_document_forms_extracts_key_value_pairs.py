"""analyze-document-forms-extracts-key-value-pairs."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "analyze-document-forms-extracts-key-value-pairs"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AnalyzeDocument with FeatureTypes=[FORMS] emits KEY_VALUE_SET blocks linking a detected
    'Name:' key to its value, driven by the actual rendered pixels."""
    png_bytes = _render_text_png(["Name: John Smith", "Date: 01/02/2024"])
    textract = ctx.client("textract")
    resp = textract.analyze_document(Document={"Bytes": png_bytes}, FeatureTypes=["FORMS"])

    blocks = resp["Blocks"]
    by_id = {b["Id"]: b for b in blocks}
    kv_blocks = [b for b in blocks if b["BlockType"] == "KEY_VALUE_SET"]
    assert kv_blocks, "no KEY_VALUE_SET blocks returned for a form-like document"

    key_blocks = [b for b in kv_blocks if "KEY" in b.get("EntityTypes", [])]
    value_blocks = [b for b in kv_blocks if "VALUE" in b.get("EntityTypes", [])]
    assert key_blocks, "no KEY_VALUE_SET block tagged as a KEY"
    assert value_blocks, "no KEY_VALUE_SET block tagged as a VALUE"

    def _child_words_text(block) -> str:
        words = []
        for rel in block.get("Relationships", []):
            if rel["Type"] == "CHILD":
                for cid in rel["Ids"]:
                    child = by_id.get(cid)
                    if child and child["BlockType"] == "WORD":
                        words.append(child["Text"])
        return " ".join(words).upper()

    def _linked_value_text(key_block) -> str:
        texts = []
        for rel in key_block.get("Relationships", []):
            if rel["Type"] == "VALUE":
                for vid in rel["Ids"]:
                    value_block = by_id.get(vid)
                    if value_block:
                        texts.append(_child_words_text(value_block))
        return " ".join(texts)

    key_texts = [_child_words_text(b) for b in key_blocks]
    assert any("NAME" in t for t in key_texts), f"expected a NAME key, got {key_texts!r}"

    name_key_blocks = [b for b, t in zip(key_blocks, key_texts) if "NAME" in t]
    linked_value_text = _linked_value_text(name_key_blocks[0])
    assert "JOHN" in linked_value_text and "SMITH" in linked_value_text, (
        f"the NAME key's VALUE relationship did not resolve to the rendered value, "
        f"got {linked_value_text!r}"
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
