"""bucket-tagging-over-fifty-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-tagging-over-fifty-rejected"
GROUP = "tagging"
SERVICES = ["s3"]

_BUCKET_PREFIX = "sim2real-behav-"

#: S3's refusal of a bucket tag set past the fixed, non-adjustable 50-tag cap.
_TOO_MANY_BUCKET_TAGS = ("BadRequest", "Bucket tag count cannot be greater than 50")


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketTagging accepts exactly 50 tags, its fixed non-adjustable per-bucket cap, and
    rejects a 51st tag without applying any part of the rejected write.
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)

    fifty = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(50)]
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": fifty})
    ctx.on_cleanup(lambda: s3.delete_bucket_tagging(Bucket=bucket))
    at_cap = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert at_cap == {t["Key"]: t["Value"] for t in fifty}, (
        f"50 tags, the documented cap, did not round-trip: {at_cap!r}"
    )

    fifty_one = fifty + [{"Key": "k50", "Value": "v50"}]
    got = _error(lambda: s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": fifty_one}))
    assert got == _TOO_MANY_BUCKET_TAGS, f"expected {_TOO_MANY_BUCKET_TAGS!r} for 51 tags, got {got!r}"

    survived = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert survived == {t["Key"]: t["Value"] for t in fifty}, (
        f"the rejected 51-tag write must not have mutated the existing tag set, got {survived!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
