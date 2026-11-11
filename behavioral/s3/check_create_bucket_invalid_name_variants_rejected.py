"""create-bucket-invalid-name-variants-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bucket-invalid-name-variants-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]

_INVALID_NAME = "InvalidBucketName"
_EXPECTED_MESSAGE = "The specified bucket is not valid."


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket(client, bucket):
    """Teardown: empty then delete. Only a bucket that never existed is tolerated."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket", "InvalidBucketName"):
            raise


def _bucket_params(ctx, name: str) -> dict:
    params: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return params


def _assert_rejected(ctx, s3, name: str, reason: str) -> None:
    # Only does anything if the create below unexpectedly lands.
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    code, message = _error(lambda: s3.create_bucket(**_bucket_params(ctx, name)))
    assert code == _INVALID_NAME, f"{reason}: expected {_INVALID_NAME!r}, got {code!r} for {name!r}"
    assert message == _EXPECTED_MESSAGE, f"{reason}: expected the exact message, got {message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBucket rejects uppercase, underscore, adjacent-dot, IP-shaped and 2-character names with
    InvalidBucketName and its exact message, while a valid name is created and is the only bucket
    listed under its prefix."""
    s3 = ctx.client("s3")

    good_name = ctx.unique_name("sim2real-behav-s3bn-")
    s3.create_bucket(**_bucket_params(ctx, good_name))
    ctx.on_cleanup(lambda: _delete_bucket(s3, good_name))
    s3.head_bucket(Bucket=good_name)  # independent read: the control bucket really exists

    _assert_rejected(ctx, s3, good_name.upper(), "uppercase letters")
    _assert_rejected(ctx, s3, good_name + "_x", "an underscore")
    _assert_rejected(ctx, s3, good_name + "..x", "two adjacent dots")
    _assert_rejected(ctx, s3, "192.168.1.1", "an IP-address-shaped name")
    _assert_rejected(ctx, s3, "ab", "a name under 3 characters")

    # Effect absent: the underscore and dots variants share the control's prefix, so a listing
    # under it holds the control alone.
    names = [
        b["Name"]
        for page in s3.get_paginator("list_buckets").paginate(Prefix=good_name)
        for b in page.get("Buckets", [])
    ]
    assert names == [good_name], f"ListBuckets under the control's prefix read {names!r}, expected only it"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
