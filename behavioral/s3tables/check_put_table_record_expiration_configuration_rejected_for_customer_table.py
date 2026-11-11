"""put-table-record-expiration-configuration-rejected-for-customer-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-record-expiration-configuration-rejected-for-customer-table"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created ICEBERG table, GetTableRecordExpirationConfiguration, then
    PutTableRecordExpirationConfiguration, then the get again all answer MethodNotAllowedException
    (record expiration is for AWS managed tables only), and GetTable still returns the table."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    namespace = _create_namespace(ctx, bucket_arn)
    table_arn, table_name = _create_table(ctx, bucket_arn, namespace)

    # the feature is rejected on read before any write is attempted
    get_code, get_message = _error(lambda: s3t.get_table_record_expiration_configuration(tableArn=table_arn))
    assert get_code == "MethodNotAllowedException", f"get_code={get_code}"
    assert get_message == MSG_NOT_ALLOWED, f"get_message={get_message!r}"

    put_code, put_message = _error(
        lambda: s3t.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert put_code == "MethodNotAllowedException", f"put_code={put_code}"
    assert put_message == MSG_NOT_ALLOWED, f"put_message={put_message!r}"

    # effect absent: the rejected Put did not silently persist a configuration
    get_code_after, get_message_after = _error(
        lambda: s3t.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_code_after == "MethodNotAllowedException", f"get_code_after={get_code_after}"
    assert get_message_after == MSG_NOT_ALLOWED, f"get_message_after={get_message_after!r}"

    # positive control: the table itself is otherwise fully functional -- only this
    # specific unsupported-on-customer-tables feature is rejected
    described = s3t.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["name"] == table_name


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn):
    s3t = ctx.client("s3tables")
    namespace = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))
    return namespace


def _create_table(ctx, bucket_arn, namespace):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    resp = s3t.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
