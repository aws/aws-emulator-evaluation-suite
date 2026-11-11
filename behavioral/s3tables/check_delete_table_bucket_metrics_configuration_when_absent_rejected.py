"""delete-table-bucket-metrics-configuration-when-absent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-metrics-configuration-when-absent-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketMetricsConfiguration on a bucket that never had a metrics configuration succeeds
    (the delete is idempotent) and a get still answers NotFoundException "No such metric configuration
    exists"; after a put, the same delete removes the configuration and the get answers the same."""
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-metrics-")
    bucket_arn = s3t.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-metrics"}
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn))

    # The idempotent delete must succeed: any error raises here.
    s3t.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    # effect absent: still no metrics configuration exists after the no-op delete
    absent_code, absent_message = _error(
        lambda: s3t.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert absent_code == "NotFoundException", f"expected NotFoundException, got {absent_code!r}"
    assert absent_message == "No such metric configuration exists", absent_message

    # positive control: the very same delete operation succeeds once a configuration exists
    s3t.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    s3t.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)  # must not raise
    s3t.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    final_code, final_message = _error(
        lambda: s3t.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert final_code == "NotFoundException", f"expected NotFoundException, got {final_code!r}"
    assert final_message == "No such metric configuration exists", final_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
