"""op-contract-listBucketMetricsConfigurations."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-listBucketMetricsConfigurations"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBucketMetricsConfigurations enumerates configured metrics filters; errors NoSuchBucket when missing."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # no configurations yet
    resp0 = s3.list_bucket_metrics_configurations(Bucket=bucket)
    assert resp0.get("MetricsConfigurationList", []) == [], f"expected empty list, got {resp0}"
    assert resp0["IsTruncated"] is False, f"expected IsTruncated False, got {resp0['IsTruncated']}"

    ids = ["metrics-a", "metrics-b"]
    for mid in ids:
        s3.put_bucket_metrics_configuration(
            Bucket=bucket,
            Id=mid,
            MetricsConfiguration={"Id": mid, "Filter": {"Prefix": f"{mid}/"}},
        )
        ctx.on_cleanup(lambda b=bucket, m=mid: s3.delete_bucket_metrics_configuration(Bucket=b, Id=m))

    resp1 = s3.list_bucket_metrics_configurations(Bucket=bucket)
    got_ids = sorted(c["Id"] for c in resp1["MetricsConfigurationList"])
    assert got_ids == sorted(ids), f"expected {ids}, got {got_ids}"

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(lambda: s3.list_bucket_metrics_configurations(Bucket=missing))
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
