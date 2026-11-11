"""start-document-text-detection-job-lifecycle."""
from __future__ import annotations

import io
import time

from behavioral_harness import tags

CHECK = "start-document-text-detection-job-lifecycle"
GROUP = "async-job-lifecycle"
SERVICES = ["textract"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDocumentTextDetection drives a real JobStatus state machine (IN_PROGRESS ->
    SUCCEEDED) and GetDocumentTextDetection returns Blocks that reflect the actual S3 document."""
    bucket = _create_doc_bucket(ctx)
    s3 = ctx.client("s3")
    key = "sim2real-async-doc.png"
    png_bytes = _render_text_png(["ASYNC TEXTRACT JOB LINE"])
    s3.put_object(Bucket=bucket, Key=key, Body=png_bytes, ContentType="image/png")

    textract = ctx.client("textract")
    job_id = textract.start_document_text_detection(
        DocumentLocation={"S3Object": {"Bucket": bucket, "Name": key}}
    )["JobId"]

    final = _poll_job_status(textract.get_document_text_detection, job_id)
    assert final["JobStatus"] == "SUCCEEDED", f"unexpected terminal status: {final['JobStatus']!r}"

    blocks = list(final.get("Blocks", []))
    next_token = final.get("NextToken")
    while next_token:
        page = textract.get_document_text_detection(JobId=job_id, NextToken=next_token)
        blocks.extend(page.get("Blocks", []))
        next_token = page.get("NextToken")

    line_texts = " ".join(b["Text"].upper() for b in blocks if b["BlockType"] == "LINE")
    assert "ASYNC" in line_texts and "TEXTRACT" in line_texts and "JOB" in line_texts, (
        f"unexpected async OCR output: {line_texts!r}"
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


def _create_doc_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-textract-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "start-document-text-detection-job-lifecycle"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
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
