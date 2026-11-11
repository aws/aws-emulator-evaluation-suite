"""metrics-configuration-disabled-by-default."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-configuration-disabled-by-default"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A new table bucket has no metrics configuration: Get returns NotFoundException, not an empty object.
    Explicitly enabling metrics makes the same Get succeed (positive control), so the absence is real.
    """
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-metrics-default-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, bucket_arn))

    code, message = _error(
        lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException by default, got {code}"
    assert message == "No such metric configuration exists", (
        f"expected the exact not-found message for the missing metrics configuration, got {message!r}"
    )

    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(
        lambda: _delete_metrics_config_quiet(s3tables, bucket_arn)
    )
    cfg = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert cfg["tableBucketARN"] == bucket_arn, (
        f"expected {bucket_arn} after explicit enable, got {cfg.get('tableBucketARN')}"
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


def _delete_metrics_config_quiet(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
