"""delete-table-bucket-metrics-configuration-conflict-allowed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-metrics-configuration-conflict-allowed"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second DeleteTableBucketMetricsConfiguration on a bucket whose configuration is already deleted
    succeeds (the delete is idempotent), GetTableBucketMetricsConfiguration then answers NotFoundException
    "No such metric configuration exists", and a new put and get return the bucket's ARN."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)

    s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn)
    s3t.delete_table_bucket_metrics_configuration(tableBucketARN=arn)

    # The idempotent double-delete must succeed: any error raises here.
    s3t.delete_table_bucket_metrics_configuration(tableBucketARN=arn)

    # Effect absent: no configuration exists after the second delete.
    get_code, get_message = _error(lambda: s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn))
    assert get_code == "NotFoundException", f"get-code={get_code}"
    assert get_message == "No such metric configuration exists", get_message

    # Positive control: the bucket is not stuck -- it can still be (re-)configured successfully.
    s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn)
    cfg = s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn)
    assert cfg["tableBucketARN"] == arn


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(name=name)["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))

    def _cleanup():
        _ignore_not_found(lambda: s3t.delete_table_bucket_metrics_configuration(tableBucketARN=arn))
        _ignore_not_found(lambda: s3t.delete_table_bucket(tableBucketARN=arn))

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
