"""telemetry-metrics-configuration-put-get-delete."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "telemetry-metrics-configuration-put-get-delete"
GROUP = "telemetry"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After PutTableBucketMetricsConfiguration, GetTableBucketMetricsConfiguration returns the bucket's ARN
    and a non-empty id; after the delete it answers NotFoundException "No such metric configuration
    exists", and a second delete returns 204 (the delete is idempotent)."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    got = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert got["tableBucketARN"] == bucket_arn, f"expected {bucket_arn}, got {got['tableBucketARN']}"
    assert isinstance(got["id"], str) and len(got["id"]) > 0, f"expected a non-empty id, got {got['id']!r}"

    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    code, message = _error_of(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "No such metric configuration exists", message

    # A further delete against the deleted configuration does not error either --
    # DeleteTableBucketMetricsConfiguration is idempotent regardless of whether the
    # configuration was ever put.
    redeleted = s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert redeleted["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"expected idempotent no-op re-deleting an already-removed configuration, got {redeleted!r}"
    )


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-metrics-")
    arn = s3tables.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-metrics"}
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _error_of(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
