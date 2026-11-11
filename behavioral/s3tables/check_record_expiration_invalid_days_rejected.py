"""record-expiration-invalid-days-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "record-expiration-invalid-days-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableRecordExpirationConfiguration with days=0 on a customer-created table is ValidationException
    with the exact range message, not MethodNotAllowedException: the range is checked before table
    eligibility; the get still answers MethodNotAllowedException and GetTable returns the table."""
    s3tables = ctx.client("s3tables")
    bucket_arn = s3tables.create_table_bucket(
        name=ctx.unique_name("sim2real-recexp-bad-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-recexp-bad"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_bucket(s3tables, bucket_arn))

    namespace = _safe_name(ctx, "sim2real-recexp-bad-ns-")
    table_name = _safe_name(ctx, "sim2real-recexp-bad-tbl-")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: _delete_namespace(s3tables, bucket_arn, namespace))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: _delete_table(s3tables, bucket_arn, namespace, table_name))

    # Positive control: the table itself is healthy and reachable.
    described = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["name"] == table_name, f"expected {table_name}, got {described}"

    # botocore enforces days>=1 client-side, so param validation is disabled to
    # let the out-of-range value actually reach the service.
    s3tables_raw = ctx.client("s3tables", config=Config(parameter_validation=False))

    # Negative: an out-of-range days value (0) draws ValidationException, not the
    # table-eligibility MethodNotAllowedException a well-formed Put on a customer
    # table draws -- range validation happens before the table-eligibility check.
    code, message = _error(
        lambda: s3tables_raw.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"settings": {"days": 0}, "status": "enabled"}
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'value.settings.days' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1"
    )
    assert message == expected, f"message={message!r}"

    # Effect absent: no configuration was created; Get reports the same gate.
    get_code, get_message = _error(
        lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_code == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {get_code}"
    assert get_message == MSG_NOT_ALLOWED, f"get_message={get_message!r}"


def _safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


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
