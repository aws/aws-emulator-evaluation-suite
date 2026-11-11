"""concurrent-multipart-completion-race."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-multipart-completion-race"
GROUP = 'concurrency'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), then delete it."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _run_concurrent(fns, *, timeout_s=60):
    """Run fns concurrently (inlined concurrency capability); return per-fn result-or-exception."""
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_errors(results):
    """(code, message) of every racer that raised; a non-AWS exception reports its type name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get("Error", {})
            errors.append((err.get("Code"), err.get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


_UPLOAD_CONSUMED = (
    "NoSuchUpload",
    "The specified upload does not exist. The upload ID may be invalid, or the upload may have "
    "been aborted or completed.",
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two identical CompleteMultipartUpload calls racing on one UploadId never both fail: either both
    succeed with one ETag or one succeeds and the other gets NoSuchUpload; the object holds the
    uploaded bytes and ListMultipartUploads omits the upload."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mpu-race-obj.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]

    # A single part is both the first and the last part of this upload, so the 5MiB minimum
    # part-size floor (which only applies to non-final parts) does not apply here.
    part_resp = s3.upload_part(
        Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=b"race-part-payload"
    )
    parts = [{"PartNumber": 1, "ETag": part_resp["ETag"]}]

    def _complete():
        return s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id, MultipartUpload={"Parts": parts}
        )

    results = _run_concurrent([_complete, _complete])
    successes = _concurrent_successes(results)
    errors = _concurrent_errors(results)

    # The race decides which outcome AWS gives; each outcome is graded exactly.
    if successes == 2:
        etags = {r.get("ETag") for r in results}
        assert len(etags) == 1, (
            f"expected both racers' successful completions to agree on the same ETag, got {etags}"
        )
    else:
        assert successes == 1 and errors == [_UPLOAD_CONSUMED], (
            f"expected one racer to complete the upload and the other to get {_UPLOAD_CONSUMED!r}, "
            f"got {successes} successes and errors {errors!r}"
        )

    # Regardless of how many racers "won", the assembled object must be readable exactly once
    # with the uploaded content -- no double-completion content artifacts.
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == b"race-part-payload", "expected the successful completion's content"

    # And regardless of how many racers won, the upload id is consumed -- it must not still be
    # listed as pending, or the race left a billed, orphaned multipart upload behind the object.
    open_upload_ids = [
        u["UploadId"]
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket)
        for u in page.get("Uploads", [])
    ]
    assert upload_id not in open_upload_ids, (
        f"upload {upload_id!r} is still listed as pending after the race resolved "
        f"(open uploads: {open_upload_ids!r}) -- a completed upload must not remain open"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
