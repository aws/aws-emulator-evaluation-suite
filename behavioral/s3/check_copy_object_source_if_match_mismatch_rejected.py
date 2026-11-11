"""copy-object-source-if-match-mismatch-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "copy-object-source-if-match-mismatch-rejected"
GROUP = 'copy'
SERVICES = ['s3']

_PRECONDITION_FAILED = ("PreconditionFailed", 'At least one of the pre-conditions you specified did not hold')
_HEAD_ABSENT = ("404", 'Not Found')

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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject with a CopySourceIfMatch that differs from the source's current ETag is refused with
    PreconditionFailed and its exact message and creates no destination; naming the current ETag copies
    the source byte for byte."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src_body = b"source-body"
    source_etag = s3.put_object(Bucket=bucket, Key="cond-src.txt", Body=src_body)["ETag"]

    refusal = _error(lambda: s3.copy_object(
        Bucket=bucket, Key="cond-dst.txt",
        CopySource={"Bucket": bucket, "Key": "cond-src.txt"},
        CopySourceIfMatch='"00000000000000000000000000000000"',
    ))
    assert refusal == _PRECONDITION_FAILED, f"expected {_PRECONDITION_FAILED!r}, got {refusal!r}"

    absent = _error(lambda: s3.head_object(Bucket=bucket, Key="cond-dst.txt"))
    assert absent == _HEAD_ABSENT, (
        f"a failed conditional copy must not create the destination object: HeadObject gave "
        f"{absent!r}, want {_HEAD_ABSENT!r}"
    )

    # --- POSITIVE CONTROL: the identical call with the source's CURRENT ETag must land the copy.
    s3.copy_object(
        Bucket=bucket, Key="cond-dst.txt",
        CopySource={"Bucket": bucket, "Key": "cond-src.txt"},
        CopySourceIfMatch=source_etag,
    )
    dst_body = s3.get_object(Bucket=bucket, Key="cond-dst.txt")["Body"].read()
    assert dst_body == src_body, (
        f"the correctly-conditioned copy landed {dst_body!r}, want the source bytes {src_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
