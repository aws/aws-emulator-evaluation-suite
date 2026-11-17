"""object-inline-tagging-value-length-limit-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-inline-tagging-value-length-limit-boundary"
GROUP = "tagging"
SERVICES = ["s3"]

_VALUE_TOO_LONG = ("InvalidTag", "The TagValue you have provided is invalid")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with a 257-character inline tag value is rejected with its exact code and
    message and leaves no object, while a 256-character value is stored and read back."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    if ctx.region != "us-east-1":
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    at_limit_value = "v" * 256
    at_limit_key = "at-limit.txt"
    s3.put_object(
        Bucket=bucket, Key=at_limit_key, Body=b"content", Tagging=f"env={at_limit_value}"
    )
    tagset = s3.get_object_tagging(Bucket=bucket, Key=at_limit_key).get("TagSet", [])
    got = {t["Key"]: t["Value"] for t in tagset}
    assert got == {"env": at_limit_value}, "expected the 256-character tag value to be stored"

    over_limit_value = "v" * 257
    rejected_key = "over-limit.txt"
    expect_error(
        lambda: s3.put_object(
            Bucket=bucket, Key=rejected_key, Body=b"content", Tagging=f"env={over_limit_value}"
        ),
        *_VALUE_TOO_LONG,
    )

    listed = s3.list_objects_v2(Bucket=bucket, Prefix=rejected_key).get("Contents", [])
    assert listed == [], f"rejected PutObject unexpectedly created {rejected_key!r}: {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
