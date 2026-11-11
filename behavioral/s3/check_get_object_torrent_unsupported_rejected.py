"""get-object-torrent-unsupported-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-object-torrent-unsupported-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectTorrent on a regular object must error (BitTorrent distribution is
    unsupported / discontinued), not fabricate a torrent payload."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    key = "torrent-target.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload-for-torrent-check")

    code = message = None
    body_returned = False
    try:
        resp = s3.get_object_torrent(Bucket=bucket, Key=key)
        # If the call didn't raise, make sure we don't silently treat a bogus
        # body as acceptable -- drain it so we can report what happened.
        raw = resp.get("Body")
        if raw is not None:
            data = raw.read()
            body_returned = bool(data)
    except ClientError as exc:
        code = _error_code(exc)
        message = exc.response.get("Error", {}).get("Message")

    assert code is not None, (
        "GetObjectTorrent unexpectedly succeeded and returned a torrent body "
        f"(body_returned={body_returned}); real AWS must reject this operation"
    )
    assert code == "MethodNotAllowed", f"expected MethodNotAllowed, got {code!r}"
    assert message == "The specified method is not allowed against this resource.", (
        f"expected the exact MethodNotAllowed message, got {message!r}"
    )

    # Independent read through a different operation: the rejected call must have
    # had no side effect on the object it targeted.
    readback = s3.get_object(Bucket=bucket, Key=key)
    assert readback["Body"].read() == b"payload-for-torrent-check", (
        "object content changed after a rejected GetObjectTorrent call"
    )


def _error_code(exc: ClientError) -> str | None:
    try:
        return exc.response["Error"]["Code"]
    except Exception:  # noqa: BLE001
        return None


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3-")
    kwargs: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
