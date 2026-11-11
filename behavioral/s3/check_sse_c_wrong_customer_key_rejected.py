"""sse-c-wrong-customer-key-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-c-wrong-customer-key-rejected"
GROUP = 'server_side_encryption'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a new bucket, PutObject and CreateMultipartUpload with SSE-C headers fail with AccessDenied and
    the exact SSE-C-blocked message naming the caller and leave no object, while a plain PutObject and
    GetObject on the same bucket work."""
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()["Arn"]
    bucket = _new_bucket(ctx, s3)
    key = "sse-c-object.bin"
    body = b"customer-encrypted-payload"
    good = bytes(range(32))

    # --- Positive control: the account and credentials are otherwise healthy for S3 — a plain
    # (non-SSE-C) PUT/GET round-trip on the same bucket succeeds.
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Body"].read() == body, (
        "a plain PutObject/GetObject round-trip must succeed before asserting the SSE-C block"
    )
    s3.delete_object(Bucket=bucket, Key=key)

    # --- The specific refusal: PutObject with SSE-C headers is denied, not silently accepted.
    exc = _client_error(
        lambda: s3.put_object(
            Bucket=bucket, Key=key, Body=body, SSECustomerAlgorithm="AES256", SSECustomerKey=good
        )
    )
    assert exc is not None, (
        "PutObject with SSE-C headers succeeded; this account/region is expected to block SSE-C "
        "uploads account-wide"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    message = exc.response.get("Error", {}).get("Message", "")
    assert code == "AccessDenied", f"expected AccessDenied for a blocked SSE-C PutObject, got {code!r}"
    assert status == 403, f"expected HTTP 403 for a blocked SSE-C PutObject, got {status!r}"
    blocked = (
        f"User: {caller} is not authorized to perform: s3:PutObject on resource: \"arn:aws:s3:::{bucket}/{key}\" "
        "because this bucket has blocked upload requests that specify Server Side Encryption with "
        "Customer provided keys (SSE-C). Please specify a different server-side encryption type."
    )
    assert message == blocked, f"expected {blocked!r}, got {message!r}"

    # --- Same refusal on the multipart path.
    exc = _client_error(
        lambda: s3.create_multipart_upload(
            Bucket=bucket, Key=key, SSECustomerAlgorithm="AES256", SSECustomerKey=good
        )
    )
    assert exc is not None, (
        "CreateMultipartUpload with SSE-C headers succeeded; expected the same account-wide block"
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "AccessDenied", (
        f"expected AccessDenied for a blocked SSE-C CreateMultipartUpload, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message", "")
    assert message == blocked, f"expected {blocked!r}, got {message!r}"

    # --- Effect absent: neither refused SSE-C attempt left an object behind.
    listed = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert listed == set(), f"expected no objects after both SSE-C attempts were refused, got {sorted(listed)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
