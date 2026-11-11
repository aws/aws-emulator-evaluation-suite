"""op-contract-put-object-tagging-invalid-tag-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-put-object-tagging-invalid-tag-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a tag set with a duplicate key, as real S3 returns it.
_DUPLICATE_TAG_KEY = ("InvalidTag", "Cannot provide multiple Tags with the same key")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectTagging replaces an object's tag set; rejects a duplicate tag key with InvalidTag."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    key = "obj-tags.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"payload")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    put_resp = s3.put_object_tagging(
        Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "phase", "Value": "dev"}]}
    )
    status = put_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert "VersionId" in put_resp or status == 200, f"expected a successful PutObjectTagging, got HTTP {status}"

    got = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert got == {"phase": "dev"}, f"expected {{'phase': 'dev'}} after PutObjectTagging, got {got}"

    # PutObjectTagging fully replaces (not merges) the object's tag set
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "phase", "Value": "prod"}]})
    got2 = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert got2 == {"phase": "prod"}, f"expected replace-not-merge semantics, got {got2}"

    # overly-permissive boundary: a duplicate tag key is not accepted
    code = _error(
        lambda: s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={"TagSet": [{"Key": "dup", "Value": "one"}, {"Key": "dup", "Value": "two"}]},
        )
    )
    assert code == _DUPLICATE_TAG_KEY, f"expected InvalidTag for duplicate tag key, got {code}"

    # the rejected write must not have mutated the previously-valid tag set
    got3 = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
    assert got3 == {"phase": "prod"}, f"rejected PutObjectTagging must not partially apply, got {got3}"


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
