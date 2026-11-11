"""start-document-analysis-async-tables-feature."""
from __future__ import annotations

import io
import time

from behavioral_harness import tags

CHECK = "start-document-analysis-async-tables-feature"
GROUP = "async-job-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDocumentAnalysis + GetDocumentAnalysis run the TABLES feature through the async job
    state machine and return a real TABLE block extracted from the S3-hosted document."""
    bucket = _create_doc_bucket(ctx)
    s3 = ctx.client("s3")
    key = "sim2real-async-table.png"
    png_bytes = _render_table_png()
    s3.put_object(Bucket=bucket, Key=key, Body=png_bytes, ContentType="image/png")

    textract = ctx.client("textract")
    job_id = textract.start_document_analysis(
        DocumentLocation={"S3Object": {"Bucket": bucket, "Name": key}},
        FeatureTypes=["TABLES"],
    )["JobId"]

    final = _poll_job_status(textract.get_document_analysis, job_id)
    assert final["JobStatus"] == "SUCCEEDED", f"unexpected terminal status: {final['JobStatus']!r}"

    blocks = list(final.get("Blocks", []))
    next_token = final.get("NextToken")
    while next_token:
        page = textract.get_document_analysis(JobId=job_id, NextToken=next_token)
        blocks.extend(page.get("Blocks", []))
        next_token = page.get("NextToken")

    table_blocks = [b for b in blocks if b["BlockType"] == "TABLE"]
    assert table_blocks, "no TABLE block detected in the async job's rendered grid"
    model_version = final.get("AnalyzeDocumentModelVersion")
    assert model_version, f"expected a non-empty AnalyzeDocumentModelVersion, got {model_version!r}"


def _render_table_png(scale: int = 6) -> bytes:
    from PIL import Image, ImageDraw

    width, height = 380, 160
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    x0, y0 = 10, 10
    cell_w, cell_h = 170, 60
    ncols, nrows = 2, 2
    for r in range(nrows + 1):
        y = y0 + r * cell_h
        draw.line([(x0, y), (x0 + ncols * cell_w, y)], fill="black", width=2)
    for c in range(ncols + 1):
        x = x0 + c * cell_w
        draw.line([(x, y0), (x, y0 + nrows * cell_h)], fill="black", width=2)
    for c, text in enumerate(["Item", "Price"]):
        draw.text((x0 + c * cell_w + 10, y0 + 15), text, fill="black")
    for c, text in enumerate(["Widget", "10.00"]):
        draw.text((x0 + c * cell_w + 10, y0 + cell_h + 15), text, fill="black")
    img = img.resize((width * scale, height * scale), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _create_doc_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-textract-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "textract"}]})
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


def _poll_job_status(get_fn, job_id: str, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = get_fn(JobId=job_id)
        if last["JobStatus"] in ("SUCCEEDED", "FAILED", "PARTIAL_SUCCESS"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job {job_id} never reached a terminal state, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
