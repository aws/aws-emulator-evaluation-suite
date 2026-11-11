"""op-contract-put-bucket-tagging-invalid-tag-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-put-bucket-tagging-invalid-tag-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a tag set with a duplicate key, as real S3 returns it.
_DUPLICATE_TAG_KEY = ("InvalidTag", "Cannot provide multiple Tags with the same key")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketTagging replaces the tag set wholesale and rejects a duplicate key with InvalidTag.

    The rejected write leaves the existing tag set unchanged.
    """
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "owner", "Value": "teamA"}, {"Key": "cost-center", "Value": "123"}]},
    )
    ctx.on_cleanup(lambda: s3.delete_bucket_tagging(Bucket=bucket))
    got = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert got == {"owner": "teamA", "cost-center": "123"}, f"expected initial tag set, got {got}"

    # PutBucketTagging fully replaces (not merges) the tag set
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "owner", "Value": "teamB"}]})
    got2 = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert got2 == {"owner": "teamB"}, f"expected replace-not-merge semantics, got {got2}"

    # A duplicate tag key is rejected.
    code = _error(
        lambda: s3.put_bucket_tagging(
            Bucket=bucket,
            Tagging={"TagSet": [{"Key": "dup", "Value": "one"}, {"Key": "dup", "Value": "two"}]},
        )
    )
    assert code == _DUPLICATE_TAG_KEY, f"expected InvalidTag for duplicate tag key, got {code}"

    # the rejected write must not have mutated the previously-valid tag set
    got3 = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    assert got3 == {"owner": "teamB"}, f"rejected PutBucketTagging must not partially apply, got {got3}"


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
