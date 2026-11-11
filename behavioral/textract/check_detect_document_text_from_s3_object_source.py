"""detect-document-text-from-s3-object-source."""
from __future__ import annotations

import io
import time

from behavioral_harness import tags

CHECK = "detect-document-text-from-s3-object-source"
GROUP = "sync-data-plane"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectDocumentText accepts a Document.S3Object reference (not just inline Bytes) and OCRs
    the object's actual pixel content."""
    bucket = _create_doc_bucket(ctx)
    s3 = ctx.client("s3")
    key = "sim2real-doc.png"
    png_bytes = _render_text_png(["S3 SOURCED DOCUMENT"])
    s3.put_object(Bucket=bucket, Key=key, Body=png_bytes, ContentType="image/png")

    textract = ctx.client("textract")
    resp = textract.detect_document_text(Document={"S3Object": {"Bucket": bucket, "Name": key}})

    blocks = resp["Blocks"]
    line_texts = [b["Text"].upper() for b in blocks if b["BlockType"] == "LINE"]
    joined = " ".join(line_texts)
    assert "SOURCED" in joined and "DOCUMENT" in joined, f"unexpected OCR output: {line_texts!r}"

    word_blocks = [b for b in blocks if b["BlockType"] == "WORD"]
    assert len(word_blocks) >= 2, f"got {len(word_blocks)} word blocks: {[b['Text'] for b in word_blocks]!r}"
    for wb in word_blocks:
        assert 0.0 <= wb["Confidence"] <= 100.0, f"confidence out of range: {wb['Confidence']!r}"
        bbox = wb["Geometry"]["BoundingBox"]
        assert 0.0 <= bbox["Left"] <= 1.0 and 0.0 <= bbox["Top"] <= 1.0, f"bbox origin out of range: {bbox!r}"
        assert 0.0 < bbox["Width"] <= 1.0 and 0.0 < bbox["Height"] <= 1.0, f"bbox size out of range: {bbox!r}"
    assert resp["DetectDocumentTextModelVersion"], "S3-sourced call returned no model version"


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


def _create_doc_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-textract-")
    kwargs = {}
    # us-east-1 is CreateBucket's own default region and is the one region that must NOT be
    # passed as a LocationConstraint; every other region must be. Fixed API behavior, not a
    # region pin on this check.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    for _ in range(3):
        resp = s3.list_objects_v2(Bucket=name)
        objs = resp.get("Contents", [])
        if not objs:
            break
        for obj in objs:
            s3.delete_object(Bucket=name, Key=obj["Key"])
        time.sleep(0.2)
    s3.delete_bucket(Bucket=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
