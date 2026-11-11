"""put-and-get-table-bucket-metrics-configuration-reflects-settings."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-get-table-bucket-metrics-configuration-reflects-settings"
GROUP = "telemetry"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketMetricsConfiguration is exactly reflected by the next
    GetTableBucketMetricsConfiguration, and DeleteTableBucketMetricsConfiguration
    removes it for good."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    # Before any Put, no metrics configuration exists for the bucket.
    pre_code, pre_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert pre_code == "NotFoundException", f"expected NotFoundException before Put, got {pre_code}"
    assert pre_message == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {pre_message!r}"
    )

    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_metrics(s3tables, bucket_arn))

    got = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert got["tableBucketARN"] == bucket_arn, f"expected {bucket_arn}, got {got.get('tableBucketARN')}"
    assert isinstance(got["id"], str) and len(got["id"]) > 0, f"expected a non-empty id, got {got.get('id')!r}"
    first_id = got["id"]

    # Re-enabling (idempotent Put) must keep resolving to the same bucket with a stable id.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    got2 = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert got2["tableBucketARN"] == bucket_arn, f"expected {bucket_arn}, got {got2.get('tableBucketARN')}"
    assert got2["id"] == first_id, f"expected stable id {first_id}, got {got2['id']}"

    # Delete must prove gone: an independent read now refuses. DeleteTableBucketMetricsConfiguration
    # is itself idempotent -- a repeat delete of an already-absent configuration succeeds rather
    # than raising NotFoundException (measured against real AWS; do not assume otherwise).
    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    post_delete_code, post_delete_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert post_delete_code == "NotFoundException", (
        f"expected NotFoundException after Delete, got {post_delete_code}"
    )
    assert post_delete_message == "No such metric configuration exists", (
        f"expected the exact not-found message for the deleted metrics configuration, got {post_delete_message!r}"
    )
    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    # The identifier is reusable: re-enabling after delete produces a fresh, working
    # configuration rather than leaving the bucket permanently unable to re-enable.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    got3 = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert got3["tableBucketARN"] == bucket_arn, f"expected {bucket_arn}, got {got3.get('tableBucketARN')}"
    assert isinstance(got3["id"], str) and len(got3["id"]) > 0, (
        f"expected a non-empty id after re-enabling, got {got3.get('id')!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_metrics(s3tables, bucket_arn):
    try:
        s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_table_bucket(ctx, s3tables):
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
