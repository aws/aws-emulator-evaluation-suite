"""get-table-bucket-metrics-configuration-not-configured-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-bucket-metrics-configuration-not-configured-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketMetricsConfiguration answers NotFoundException "No such metric configuration exists"
    on a bucket that never had a metrics configuration and again after the configuration is deleted,
    while after each put it returns the bucket's ARN: no default configuration is invented."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)

    code_before, message_before = _error(lambda: s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn))
    assert code_before == "NotFoundException", f"expected NotFoundException, got {code_before}"
    assert message_before == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {message_before!r}"
    )

    # Positive control: after actually configuring metrics, the Get succeeds.
    s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn)
    cfg = s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn)
    assert cfg["tableBucketARN"] == arn, f"expected tableBucketARN {arn}, got {cfg.get('tableBucketARN')}"

    # Deleting it returns to the same not-configured NotFoundException, confirming the effect
    # (the config) is genuinely absent again, not merely hidden.
    s3t.delete_table_bucket_metrics_configuration(tableBucketARN=arn)
    code_after, message_after = _error(lambda: s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn))
    assert code_after == "NotFoundException", f"expected NotFoundException after delete, got {code_after}"
    assert message_after == "No such metric configuration exists", (
        f"expected the exact not-found message for the deleted metrics configuration, got {message_after!r}"
    )

    # Restore: the rejection above is specific to the missing configuration, not a blanket
    # breakage of the bucket or the operation -- an identical Put/Get on the same bucket must
    # still succeed.
    s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn)
    revived = s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn)
    assert revived["tableBucketARN"] == arn, (
        f"expected tableBucketARN {arn} after restore, got {revived.get('tableBucketARN')}"
    )


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(
                name=name,
                tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-bkt-"},
            )["arn"]
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
