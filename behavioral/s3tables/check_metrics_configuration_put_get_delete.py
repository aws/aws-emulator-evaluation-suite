"""metrics-configuration-put-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-configuration-put-get-delete"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketMetricsConfiguration on a never-enabled bucket is a no-op success; once enabled the
    config id is stable across reads, and Delete then makes Get return NotFoundException again.
    """
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-metrics-cfg-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, bucket_arn))

    # Delete on a never-enabled configuration is an idempotent no-op, not a rejection.
    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    # Effect absent: still no configuration to retrieve.
    code, message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {message!r}"
    )

    # Positive control: enable, retrieve, then fully disable.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    cfg = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert cfg["tableBucketARN"] == bucket_arn, f"expected {bucket_arn}, got {cfg['tableBucketARN']}"
    assert cfg["id"], "expected a non-empty configuration id, got none"

    cfg_again = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert cfg_again["id"] == cfg["id"], (
        f"metrics configuration id changed across independent reads: {cfg['id']!r} -> {cfg_again['id']!r}"
    )

    s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)

    code, message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "No such metric configuration exists", (
        f"expected the exact not-found message for the deleted metrics configuration, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket_quiet(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
