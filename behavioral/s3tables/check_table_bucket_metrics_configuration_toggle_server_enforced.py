"""table-bucket-metrics-configuration-toggle-server-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-bucket-metrics-configuration-toggle-server-enforced"
GROUP = "server-side"
SERVICES = ["s3tables"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Over three put/delete cycles, GetTableBucketMetricsConfiguration returns the bucket's ARN after each
    put and NotFoundException "No such metric configuration exists" after each delete, and a final put
    returns the same configuration id as the last cycle."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-metrics-toggle-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    last_id = None
    for cycle in range(3):
        s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
        enabled = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
        assert enabled["tableBucketARN"] == bucket_arn, f"cycle {cycle}: {enabled}"
        last_id = enabled["id"]

        s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
        code, message = _error(
            lambda: s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
        )
        assert code == "NotFoundException", f"cycle {cycle}: {code}"
        assert message == "No such metric configuration exists", f"cycle {cycle}: {message!r}"

    # Leave it enabled at the end and register the matching cleanup.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    ctx.on_cleanup(
        lambda: s3tables.delete_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    )
    final = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert final["tableBucketARN"] == bucket_arn
    assert final["id"], f"expected a non-empty id, got {final['id']!r}"
    assert last_id is not None
    assert final["id"] == last_id, (
        f"re-enabling after a delete produced a different id ({final['id']!r}) than the "
        f"prior cycle's ({last_id!r}) -- the metrics configuration id is expected to be a "
        f"stable property of the bucket, not re-minted per Put"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
