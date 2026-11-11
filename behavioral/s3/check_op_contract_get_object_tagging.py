"""op-contract-getObjectTagging."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getObjectTagging"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a key that does not exist, as real S3 returns it.
_NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetObjectTagging returns the tag set put on an object; errors NoSuchKey for a missing key."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    # GetObjectTagging only returns a VersionId when the bucket is versioned;
    # enable versioning so the VersionId contract can be asserted.
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    key = "tagged-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # a fresh object has an empty tag set, not an error
    resp0 = s3.get_object_tagging(Bucket=bucket, Key=key)
    assert resp0["TagSet"] == [], f"expected empty TagSet, got {resp0['TagSet']}"

    tag_set = [{"Key": "classification", "Value": "internal"}]
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": tag_set})

    resp1 = s3.get_object_tagging(Bucket=bucket, Key=key)
    got = {t["Key"]: t["Value"] for t in resp1["TagSet"]}
    assert got == {"classification": "internal"}, f"unexpected tag set: {got}"
    assert "VersionId" in resp1, f"expected a VersionId on a versioned bucket, got keys {list(resp1)}"

    # distinct error boundary: nonexistent key
    code = _error(lambda: s3.get_object_tagging(Bucket=bucket, Key="does-not-exist.txt"))
    assert code == _NO_SUCH_KEY, f"expected NoSuchKey, got {code}"


_BUCKET_PREFIX = "sim2real-behav-"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
