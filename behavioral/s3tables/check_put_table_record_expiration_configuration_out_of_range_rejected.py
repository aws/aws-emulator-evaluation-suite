"""put-table-record-expiration-configuration-out-of-range-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-record-expiration-configuration-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTableRecordExpirationConfiguration on a customer-created table is MethodNotAllowedException
    (the feature is for AWS managed tables only), GetTableRecordExpirationConfiguration answers the same
    afterwards, and GetTable still returns the table's name and ARN."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)
    namespace = _create_namespace(ctx, s3tables, bucket_arn)
    table_name, table_arn = _create_table(ctx, s3tables, bucket_arn, namespace)

    code, message = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn,
            value={"status": "enabled", "settings": {"days": 30}},
        )
    )
    assert code == "MethodNotAllowedException", f"expected MethodNotAllowedException, got {code}"
    assert message == MSG_NOT_ALLOWED, f"message={message!r}"

    still_unsupported, still_message = _error(
        lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert still_unsupported == "MethodNotAllowedException", (
        f"expected the customer table to remain unsupported for record expiration, got {still_unsupported}"
    )
    assert still_message == MSG_NOT_ALLOWED, f"message={still_message!r}"

    described = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["name"] == table_name, (
        f"expected the table to remain otherwise functional (positive control), "
        f"got name={described.get('name')!r}"
    )
    assert described["tableARN"] == table_arn, (
        f"expected GetTable to report the same tableARN, got {described.get('tableARN')!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _ident_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    return re.sub(r"[^0-9a-z_]", "_", raw)[:255]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, s3tables, bucket_arn: str) -> str:
    ns = _ident_name(ctx, "sim2real_ns_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))
    return ns


def _create_table(ctx, s3tables, bucket_arn: str, namespace: str, fmt: str = "ICEBERG"):
    name = _ident_name(ctx, "sim2real_tbl_")
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format=fmt
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return name, resp["tableARN"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
