"""table-record-expiration-configuration-round-trip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "table-record-expiration-configuration-round-trip"
GROUP = "representation"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a customer-created ICEBERG table, PutTableRecordExpirationConfiguration and
    GetTableRecordExpirationConfiguration both answer MethodNotAllowedException (record expiration is for
    AWS managed tables only), while GetTable returns the table's name and ARN."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real-purpose": "recexp-round-trip"})

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    )
    table_name = ctx.unique_name("tbl_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )
    table_arn = created["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
        )
    )
    s3tables.tag_resource(resourceArn=table_arn, tags={"sim2real-purpose": "recexp-round-trip"})

    # break: try to configure record expiration on an ordinary customer table
    put_code, put_message = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"settings": {"days": 30}, "status": "enabled"}
        )
    )
    assert put_code == "MethodNotAllowedException", (
        f"expected PutTableRecordExpirationConfiguration on a customer-created table to be "
        f"rejected with MethodNotAllowedException, got {put_code!r}"
    )
    assert put_message == MSG_NOT_ALLOWED, f"put_message={put_message!r}"

    # effect absent: no configuration was persisted -- reading it back reports the
    # same unsupported-operation rejection rather than a stale/default config
    get_code, get_message = _error(
        lambda: s3tables.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_code == "MethodNotAllowedException", (
        f"expected GetTableRecordExpirationConfiguration to keep reporting "
        f"MethodNotAllowedException after the rejected Put, got {get_code!r}"
    )
    assert get_message == MSG_NOT_ALLOWED, f"get_message={get_message!r}"

    # positive control: the table itself is otherwise fully functional -- the
    # rejection is specific to record expiration, not a broken/missing table
    got = s3tables.get_table(tableArn=table_arn)
    assert got["name"] == table_name, f"expected table name {table_name!r}, got {got.get('name')!r}"
    assert got["tableARN"] == table_arn, f"expected tableARN {table_arn!r}, got {got.get('tableARN')!r}"


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-recexp-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises -- a
    target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
