"""record-expiration-days-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "record-expiration-days-precision-preserved"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created table, PutTableRecordExpirationConfiguration with days 1, 36500 and 2147483647
    is MethodNotAllowedException each time, as is the get after each attempt, so no days value reaches
    a different code path; GetTable still returns the table's name and ARN."""
    s3tables = ctx.client("s3tables")
    bucket_arn = s3tables.create_table_bucket(name=ctx.unique_name("sim2real-recexp-"))["arn"]
    ctx.on_cleanup(lambda: _delete_bucket(s3tables, bucket_arn))

    namespace = _safe_name(ctx, "sim2real-recexp-ns-")
    table_name = _safe_name(ctx, "sim2real-recexp-tbl-")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: _delete_namespace(s3tables, bucket_arn, namespace))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: _delete_table(s3tables, bucket_arn, namespace, table_name))

    for days in (1, 36500, 2147483647):
        put_code, put_message = _error(
            lambda: s3tables.put_table_record_expiration_configuration(
                tableArn=table_arn, value={"settings": {"days": days}, "status": "enabled"}
            )
        )
        assert put_code == "MethodNotAllowedException", (
            f"days={days}: expected MethodNotAllowedException, got {put_code!r}"
        )
        assert put_message == MSG_NOT_ALLOWED, f"days={days}: put_message={put_message!r}"

        get_code, get_message = _error(
            lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn)
        )
        assert get_code == "MethodNotAllowedException", (
            f"days={days}: expected the rejected Put to leave Get rejecting too, got {get_code!r}"
        )
        assert get_message == MSG_NOT_ALLOWED, f"days={days}: get_message={get_message!r}"

    # Positive control: the table itself remains fully usable -- only record
    # expiration is unsupported for a customer-created table.
    described = s3tables.get_table(tableArn=table_arn)
    assert described["name"] == table_name, f"expected {table_name}, got {described['name']}"
    assert described["tableARN"] == table_arn, f"expected {table_arn}, got {described['tableARN']}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _delete_bucket(s3tables, bucket_arn: str) -> None:
    """Delete the bucket; NotFoundException means it is already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_namespace(s3tables, bucket_arn: str, namespace: str) -> None:
    """Delete the namespace; NotFoundException means it is already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_table(s3tables, bucket_arn: str, namespace: str, name: str) -> None:
    """Delete the table; NotFoundException means it is already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
