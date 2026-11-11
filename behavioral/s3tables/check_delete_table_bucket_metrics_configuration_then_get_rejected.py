"""delete-table-bucket-metrics-configuration-then-get-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-table-bucket-metrics-configuration-then-get-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        err = response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteTableBucketMetricsConfiguration, GetTableBucketMetricsConfiguration answers
    NotFoundException "No such metric configuration exists", and a new put and get in the same bucket
    return the bucket's ARN again."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-metrics-del-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name, tags={"sim2real": CHECK})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    configured = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert configured["tableBucketARN"] == bucket_arn, (
        f"expected configured get to echo {bucket_arn}, got {configured.get('tableBucketARN')}"
    )

    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    code, message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", code
    assert message == "No such metric configuration exists", message

    # Positive control in the same file: re-enabling metrics on the same bucket must
    # still work -- the rejection above is about the missing configuration, not the
    # bucket or the operation being broken.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(
        lambda: s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    revived = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert revived["tableBucketARN"] == bucket_arn, (
        f"expected revived get to echo {bucket_arn}, got {revived.get('tableBucketARN')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
