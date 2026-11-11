"""table-record-expiration-rejected-for-user-created-table."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-record-expiration-rejected-for-user-created-table"
GROUP = "representation"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a user-created table, GetTableRecordExpirationConfiguration, then PutTableRecordExpirationConfiguration,
    then the get again all answer MethodNotAllowedException (record expiration is for AWS managed tables
    only), while GetTable returns the table's name and ARN."""
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-s3t-exp-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    namespace_name = _sanitize(ctx.unique_name("sim2real_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name))

    table_name = _sanitize(ctx.unique_name("sim2real_tbl_"))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    )

    # Effect: user-created tables aren't eligible for record expiration management at
    # all - the read path itself is rejected with MethodNotAllowedException, not just
    # the write path.
    get_code, get_message = _error(lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn))
    assert get_code == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {get_code!r}"
    assert get_message == MSG_NOT_ALLOWED, f"get_message={get_message!r}"

    # Break exactly one thing: attempting to enable it via Put on the same ineligible
    # table is likewise rejected, regardless of the days value supplied.
    put_code, put_message = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 733}}
        )
    )
    assert put_code == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {put_code!r}"
    assert put_message == MSG_NOT_ALLOWED, f"put_message={put_message!r}"

    # Effect absent: the read path is still consistently rejected the same way after
    # the failed write attempt - no partial state was created.
    get_code_after, get_message_after = _error(lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn))
    assert get_code_after == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {get_code_after!r}"
    assert get_message_after == MSG_NOT_ALLOWED, f"get_message_after={get_message_after!r}"

    # Positive control: the rejection is specific to record expiration, not a broken
    # or unreachable table - GetTable on the same table still succeeds normally.
    described = s3tables.get_table(tableArn=table_arn)
    assert described["name"] == table_name, f"expected {table_name!r}, got {described['name']!r}"
    assert described["tableARN"] == table_arn, f"expected {table_arn!r}, got {described['tableARN']!r}"


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


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
