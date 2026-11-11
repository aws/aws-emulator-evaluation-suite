"""op-contract-getBucketTagging."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getBucketTagging"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket with no tag set, as real S3 returns it.
_NO_SUCH_TAG_SET = ("NoSuchTagSet", "The TagSet does not exist")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBucketTagging returns the exact tag set that was put; errors NoSuchTagSet when none set."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # success path: no tags yet -> NoSuchTagSet
    code = _error(lambda: s3.get_bucket_tagging(Bucket=bucket))
    assert code == _NO_SUCH_TAG_SET, f"expected NoSuchTagSet before any tags set, got {code}"

    tag_set = [{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "data"}]
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})

    resp = s3.get_bucket_tagging(Bucket=bucket)
    got = {t["Key"]: t["Value"] for t in resp["TagSet"]}
    assert got == {"env": "prod", "team": "data"}, f"unexpected tag set: {got}"

    # distinct error boundary: after DeleteBucketTagging, GetBucketTagging fails again
    s3.delete_bucket_tagging(Bucket=bucket)
    code2 = _error(lambda: s3.get_bucket_tagging(Bucket=bucket))
    assert code2 == _NO_SUCH_TAG_SET, f"expected NoSuchTagSet after delete, got {code2}"


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
