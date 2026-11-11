"""op-contract-putBucketMetricsConfiguration."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putBucketMetricsConfiguration"
GROUP = "error-semantics"
SERVICES = ["s3"]

#: S3's refusal of a bucket that does not exist, as real S3 returns it.
_NO_SUCH_BUCKET = ("NoSuchBucket", "The specified bucket does not exist")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketMetricsConfiguration stores the filter under Id; errors NoSuchBucket for a missing bucket."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    metrics_id = "prod-only"

    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=metrics_id,
        MetricsConfiguration={
            "Id": metrics_id,
            # combining a Prefix with Tags requires the "And" wrapper (MetricsAndOperator);
            # the top-level Filter only accepts one of Prefix / Tag / And.
            "Filter": {"And": {"Prefix": "prod/", "Tags": [{"Key": "env", "Value": "prod"}]}},
        },
    )
    ctx.on_cleanup(lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id))

    resp = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id)
    cfg = resp["MetricsConfiguration"]
    assert cfg["Id"] == metrics_id, f"expected Id {metrics_id!r}, got {cfg['Id']!r}"
    got_prefix = cfg["Filter"]["And"]["Prefix"]
    assert got_prefix == "prod/", f"expected And.Prefix 'prod/', got {got_prefix!r}"
    filter_tags = cfg["Filter"]["And"]["Tags"]
    assert filter_tags == [{"Key": "env", "Value": "prod"}], f"unexpected filter tags: {filter_tags}"

    # replacing the same Id overwrites the filter in place
    s3.put_bucket_metrics_configuration(
        Bucket=bucket,
        Id=metrics_id,
        MetricsConfiguration={"Id": metrics_id, "Filter": {"Prefix": "staging/"}},
    )
    resp2 = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=metrics_id)
    got_prefix2 = resp2["MetricsConfiguration"]["Filter"]["Prefix"]
    assert got_prefix2 == "staging/", f"expected overwritten Filter.Prefix 'staging/', got {got_prefix2!r}"

    # distinct error boundary: nonexistent bucket
    missing = ctx.unique_name(_BUCKET_PREFIX + "missing-")
    code = _error(
        lambda: s3.put_bucket_metrics_configuration(
            Bucket=missing, Id=metrics_id, MetricsConfiguration={"Id": metrics_id}
        )
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
