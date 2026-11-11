"""put-and-get-table-bucket-metrics-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-get-table-bucket-metrics-configuration"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketMetricsConfiguration answers NotFoundException "No such metric configuration exists"
    on a new bucket, and after PutTableBucketMetricsConfiguration two reads return the bucket's ARN
    with the same non-empty id."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-metrics-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    pre_code, pre_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert pre_code == "NotFoundException", f"expected NotFoundException before Put, got {pre_code}"
    assert pre_message == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {pre_message!r}"
    )

    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(
        lambda: s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )

    first = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert first["tableBucketARN"] == bucket_arn
    assert first["id"]

    second = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert second["tableBucketARN"] == bucket_arn
    assert second["id"] == first["id"], "metrics configuration id changed across reads"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
