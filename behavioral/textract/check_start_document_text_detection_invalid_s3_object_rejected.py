"""start-document-text-detection-invalid-s3-object-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-document-text-detection-invalid-s3-object-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartDocumentTextDetection rejects a DocumentLocation pointing at a nonexistent S3 key with
    InvalidS3ObjectException (no JobId/job is created), while pointing at the real, just-uploaded
    object (positive control) succeeds and returns a JobId."""
    bucket = _create_doc_bucket(ctx)
    s3 = ctx.client("s3")
    real_key = "sim2real-real-doc.png"
    s3.put_object(Bucket=bucket, Key=real_key, Body=_tiny_png(), ContentType="image/png")

    textract = ctx.client("textract")
    missing_key = "sim2real-does-not-exist.png"
    err = _client_error(
        lambda: textract.start_document_text_detection(
            DocumentLocation={"S3Object": {"Bucket": bucket, "Name": missing_key}}
        )
    )
    assert err["Code"] == "InvalidS3ObjectException", (
        f"expected InvalidS3ObjectException, got {err['Code']!r}"
    )
    expected_message = (
        "Unable to get object metadata from S3. Check object key, region and/or access permissions."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: the real object starts a job successfully, and the job is real —
    # confirmed by an independent GetDocumentTextDetection read, not just the Start response.
    resp = textract.start_document_text_detection(
        DocumentLocation={"S3Object": {"Bucket": bucket, "Name": real_key}}
    )
    job_id = resp["JobId"]
    assert job_id, "positive control StartDocumentTextDetection returned no JobId"

    final = _poll_job_status(textract.get_document_text_detection, job_id)
    assert final["JobStatus"] == "SUCCEEDED", (
        f"unexpected terminal status for positive control job: {final['JobStatus']!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _tiny_png() -> bytes:
    import io

    from PIL import Image

    img = Image.new("RGB", (200, 100), "white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _poll_job_status(get_fn, job_id: str, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = get_fn(JobId=job_id)
        if last["JobStatus"] in ("SUCCEEDED", "FAILED", "PARTIAL_SUCCESS"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"job {job_id} never reached a terminal state, last={last}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
