"""op-contract-listObjectsV2."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listObjectsV2"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2 honors Delimiter/Prefix grouping, KeyCount, and pagination; errors NoSuchBucket when missing."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    keys = ["a/1.txt", "a/2.txt", "b/1.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"x")
        ctx.on_cleanup(lambda k=k: s3.delete_object(Bucket=bucket, Key=k))

    # with a delimiter, top-level "directories" surface as CommonPrefixes, not Contents
    resp = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    prefixes = sorted(p["Prefix"] for p in resp.get("CommonPrefixes", []))
    assert prefixes == ["a/", "b/"], f"expected ['a/','b/'], got {prefixes}"
    assert resp.get("Contents", []) == [], f"expected no top-level Contents, got {resp.get('Contents')}"
    assert resp["KeyCount"] == 2, f"expected KeyCount 2 (2 common prefixes), got {resp['KeyCount']}"

    # without a delimiter, every key is flattened into Contents
    resp2 = s3.list_objects_v2(Bucket=bucket)
    got_keys = sorted(o["Key"] for o in resp2["Contents"])
    assert got_keys == sorted(keys), f"expected {sorted(keys)}, got {got_keys}"
    assert resp2["KeyCount"] == 3, f"expected KeyCount 3, got {resp2['KeyCount']}"
    assert resp2["IsTruncated"] is False, f"expected IsTruncated False, got {resp2['IsTruncated']}"

    # pagination: MaxKeys=1 must truncate and provide a usable continuation token
    resp3 = s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
    assert resp3["IsTruncated"] is True, f"expected IsTruncated True, got {resp3['IsTruncated']}"
    assert len(resp3["Contents"]) == 1, f"expected 1 item under MaxKeys=1, got {len(resp3['Contents'])}"
    token = resp3["NextContinuationToken"]
    resp4 = s3.list_objects_v2(Bucket=bucket, MaxKeys=1, ContinuationToken=token)
    assert resp4["Contents"][0]["Key"] != resp3["Contents"][0]["Key"], "pagination returned a repeated key"

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(lambda: s3.list_objects_v2(Bucket=missing))
    assert code == _NO_SUCH_BUCKET, f"expected NoSuchBucket, got {code}"


_BUCKET_PREFIX = "sim2real-behav-"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's region-pinned default: CreateBucket rejects an explicit
        # LocationConstraint there, so the literal names that quirk, not a target region.
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
