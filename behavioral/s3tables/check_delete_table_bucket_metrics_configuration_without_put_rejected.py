"""delete-table-bucket-metrics-configuration-without-put-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-metrics-configuration-without-put-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketMetricsConfiguration succeeds on a bucket with no metrics configuration but is
    NotFoundException "The specified bucket does not exist." for a bucket ARN that does not exist, and
    after a put the delete removes the configuration (the get answers NotFoundException again)."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    # ground truth: deleting a metrics config that was never put does NOT raise — it is a
    # no-op delete against an existing bucket, like idempotent DELETE operations across S3.
    # There is still no config to read back afterwards.
    # Any error on the idempotent delete raises here.
    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    get_code, get_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "No such metric configuration exists", get_message

    # a table bucket ARN that was never created must be rejected outright, not treated as
    # "nothing to delete".
    nonexistent_arn = bucket_arn.rsplit("/", 1)[0] + "/" + ctx.unique_name("sim2real-s3t-ghost")
    ghost_code, ghost_message = _error(
        lambda: s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=nonexistent_arn)
    )
    assert ghost_code == "NotFoundException", f"expected NotFoundException, got {ghost_code}"
    assert ghost_message == "The specified bucket does not exist.", ghost_message

    # positive control: delete succeeds once a metrics configuration genuinely exists
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    created = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert created["tableBucketARN"] == bucket_arn, (
        f"expected tableBucketARN {bucket_arn}, got {created.get('tableBucketARN')}"
    )
    assert created["id"], f"expected a non-empty configuration id, got {created.get('id')!r}"

    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    after_code, after_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert after_code == "NotFoundException", f"expected NotFoundException, got {after_code}"
    assert after_message == "No such metric configuration exists", after_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_table_bucket(ctx, s3tables):
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
