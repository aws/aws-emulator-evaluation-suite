"""put-object-encryption-type-mismatch."""

from __future__ import annotations

import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-encryption-type-mismatch"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """On a bucket whose default encryption blocks SSE-C, CreateMultipartUpload with SSE-C headers is
    refused with AccessDenied and the exact SSE-C-blocked message and leaves no pending upload, while a
    plain multipart upload on the same bucket works."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "ssec-multipart-object.bin"
    sse_key = os.urandom(32)

    # Positive control: an ordinary (non-SSE-C) multipart upload against this bucket succeeds.
    control = s3.create_multipart_upload(Bucket=bucket, Key=key)
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=control["UploadId"])

    # Break exactly one thing: add SSE-C headers to the identical call. `_client_error` raises on
    # unexpected success.
    error = _client_error(
        lambda: s3.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            SSECustomerAlgorithm="AES256",
            SSECustomerKey=sse_key,
        )
    )
    code = error.get("Code")
    message = error.get("Message", "")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    assert (code, message) == ("AccessDenied", (
        f"User: {caller_arn} is not authorized to perform: s3:PutObject on resource: "
        f"\"arn:aws:s3:::{bucket}/{key}\" because this bucket has blocked upload requests that "
        f"specify Server Side Encryption with Customer provided keys (SSE-C). Please specify a "
        f"different server-side encryption type."
    )), (
        "AccessDenied on CreateMultipartUpload must name the SSE-C block specifically, so this "
        f"check cannot be satisfied by a target that denies every request; got {code!r} ({message!r})"
    )

    # Effect absent: the denied attempt left no multipart upload registered on this key.
    pending = [
        u["UploadId"]
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket)
        for u in page.get("Uploads", [])
        if u["Key"] == key
    ]
    assert pending == [], (
        f"the SSE-C CreateMultipartUpload was denied but left upload id(s) {pending} registered "
        f"on {key!r}"
    )


def _create_bucket(ctx):
    """Create a general-purpose S3 bucket and register full cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        try:
            resp = s3.list_object_versions(Bucket=name)
            for v in resp.get("Versions", []):
                s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
            for m in resp.get("DeleteMarkers", []):
                s3.delete_object(Bucket=name, Key=m["Key"], VersionId=m["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            for page in s3.get_paginator("list_multipart_uploads").paginate(
                Bucket=name
            ):
                for u in page.get("Uploads", []):
                    s3.abort_multipart_upload(
                        Bucket=name, Key=u["Key"], UploadId=u["UploadId"]
                    )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
