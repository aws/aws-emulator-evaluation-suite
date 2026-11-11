"""op-contract-putBucketVersioning."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putBucketVersioning"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutBucketVersioning drives Unversioned -> Enabled -> Suspended; errors NoSuchBucket when missing."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    resp0 = s3.get_bucket_versioning(Bucket=bucket)
    assert "Status" not in resp0, f"expected no Status on fresh bucket, got {resp0}"

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    status1 = s3.get_bucket_versioning(Bucket=bucket)["Status"]
    assert status1 == "Enabled", f"expected Enabled, got {status1}"

    # while enabled, writes actually produce distinct object versions
    key = "versioning-state.txt"
    v1 = s3.put_object(Bucket=bucket, Key=key, Body=b"first")["VersionId"]
    v2 = s3.put_object(Bucket=bucket, Key=key, Body=b"second")["VersionId"]
    assert v1 and v2 and v1 != v2, f"expected two distinct non-empty version ids, got {v1!r} and {v2!r}"

    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
    status2 = s3.get_bucket_versioning(Bucket=bucket)["Status"]
    assert status2 == "Suspended", f"expected Suspended, got {status2}"

    # while suspended, new writes to the same key do not create a new distinct version id
    s3.put_object(Bucket=bucket, Key=key, Body=b"third")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head.get("VersionId") in (None, "null"), f"expected null version id while suspended, got {head.get('VersionId')}"

    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v1))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v2))

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(
        lambda: s3.put_bucket_versioning(Bucket=missing, VersioningConfiguration={"Status": "Enabled"})
    )
    assert code == _NO_SUCH_BUCKET, f"expected NoSuchBucket, got {code}"


_BUCKET_PREFIX = "sim2real-behav-"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
