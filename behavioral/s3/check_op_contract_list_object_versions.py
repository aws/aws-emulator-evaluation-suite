"""op-contract-listObjectVersions."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listObjectVersions"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectVersions reports version history and delete markers with correct IsLatest flags."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "versioned.txt"
    v1 = s3.put_object(Bucket=bucket, Key=key, Body=b"one")["VersionId"]
    v2 = s3.put_object(Bucket=bucket, Key=key, Body=b"two")["VersionId"]
    assert v1 != v2, "expected two distinct version ids"

    resp = s3.list_object_versions(Bucket=bucket, Prefix=key)
    versions = {v["VersionId"]: v for v in resp["Versions"]}
    assert set(versions.keys()) == {v1, v2}, f"expected versions {v1},{v2} got {list(versions)}"
    assert versions[v2]["IsLatest"] is True, "newest put should be IsLatest"
    assert versions[v1]["IsLatest"] is False, "older version should not be IsLatest"
    assert resp.get("DeleteMarkers", []) == [], (
        f"expected no delete markers before any delete, got {resp.get('DeleteMarkers')}"
    )

    # deleting the key (versioned bucket) creates a delete marker instead of removing history
    del_resp = s3.delete_object(Bucket=bucket, Key=key)
    marker_id = del_resp["VersionId"]
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=marker_id))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v1))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key, VersionId=v2))

    resp2 = s3.list_object_versions(Bucket=bucket, Prefix=key)
    assert len(resp2["DeleteMarkers"]) == 1, f"expected one delete marker, got {resp2['DeleteMarkers']}"
    assert resp2["DeleteMarkers"][0]["IsLatest"] is True, (
        f"the delete marker must be IsLatest, got {resp2['DeleteMarkers'][0]}"
    )
    assert resp2["DeleteMarkers"][0]["VersionId"] == marker_id, (
        f"expected delete marker VersionId {marker_id}, got {resp2['DeleteMarkers'][0]['VersionId']}"
    )
    still_versions = {v["VersionId"] for v in resp2["Versions"]}
    assert still_versions == {v1, v2}, "prior object versions must remain listed after delete marker creation"

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(lambda: s3.list_object_versions(Bucket=missing))
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
