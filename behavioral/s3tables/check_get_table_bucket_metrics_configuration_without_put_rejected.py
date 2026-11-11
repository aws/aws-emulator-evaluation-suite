"""get-table-bucket-metrics-configuration-without-put-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-bucket-metrics-configuration-without-put-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketMetricsConfiguration answers NotFoundException "No such metric configuration exists"
    before any put, returns the bucket's ARN and a non-empty id after PutTableBucketMetricsConfiguration,
    and answers the same NotFoundException after the configuration is deleted."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    code, message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {message!r}"
    )

    # Positive control: after enabling metrics, Get succeeds with a real id.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(
        lambda: s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    got = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert got["tableBucketARN"] == bucket_arn, (
        f"expected tableBucketARN {bucket_arn}, got {got.get('tableBucketARN')}"
    )
    assert got.get("id"), f"expected a non-empty configuration id, got {got.get('id')!r}"

    # The delete above is otherwise unasserted: prove the config is genuinely gone
    # again, not merely hidden, by getting the identical NotFoundException back.
    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    after_code, after_message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert after_code == "NotFoundException", (
        f"expected NotFoundException after delete, got {after_code}"
    )
    assert after_message == "No such metric configuration exists", (
        f"expected the exact not-found message for the deleted metrics configuration, got {after_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name, tags={"sim2real-check": CHECK})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
