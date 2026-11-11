"""op-contract-headBucket."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-headBucket"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """HeadBucket succeeds (200) for an existing bucket; returns a 404 for a nonexistent one."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    resp = s3.head_bucket(Bucket=bucket)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, f"expected 200, got {resp['ResponseMetadata']}"
    # HeadBucket surfaces the resolved region for the bucket; must match where it was created
    assert resp.get("BucketRegion") == ctx.region, (
        f"BucketRegion {resp.get('BucketRegion')!r} != harness region {ctx.region!r}"
    )

    # distinct error boundary: nonexistent bucket -> 404
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    from botocore.exceptions import ClientError

    try:
        s3.head_bucket(Bucket=missing)
        raise AssertionError("expected head_bucket on missing bucket to raise")
    except ClientError as e:
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 404, f"expected HTTP 404, got {status}"
        assert e.response["Error"]["Code"] == "404", f"expected error code '404', got {e.response['Error']['Code']}"


_BUCKET_PREFIX = "sim2real-behav-"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint on CreateBucket
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
