"""get-document-text-detection-invalid-job-id-rejected."""
from __future__ import annotations

import io
import time

from behavioral_harness import tags

CHECK = "get-document-text-detection-invalid-job-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDocumentTextDetection with a JobId that was never issued is rejected with
    InvalidJobIdException, while a real JobId returned by StartDocumentTextDetection (positive
    control) is accepted and reaches a real SUCCEEDED terminal state."""
    textract = ctx.client("textract")

    bogus_job_id = "sim2real-" + ("0" * 40)
    err = _client_error(lambda: textract.get_document_text_detection(JobId=bogus_job_id))
    assert err["Code"] == "InvalidJobIdException", (
        f"expected InvalidJobIdException, got {err['Code']!r}"
    )
    expected_message = "Request has invalid Job Id"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    bucket = _create_doc_bucket(ctx)
    s3 = ctx.client("s3")
    key = "sim2real-jobid-doc.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_render_text_png(["JOB ID CONTROL"]), ContentType="image/png")

    real_job_id = textract.start_document_text_detection(
        DocumentLocation={"S3Object": {"Bucket": bucket, "Name": key}}
    )["JobId"]
    final = _poll_job_status(textract.get_document_text_detection, real_job_id)
    assert final["JobStatus"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['JobStatus']!r}"


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
