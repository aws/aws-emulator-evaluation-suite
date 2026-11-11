"""record-expiration-configuration-rejected-for-standard-table."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "record-expiration-configuration-rejected-for-standard-table"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a user-created ICEBERG table, PutTableRecordExpirationConfiguration and then
    GetTableRecordExpirationConfiguration answer MethodNotAllowedException (record expiration is for AWS
    managed tables only), while GetTable returns the table's name 'tbl' and ARN."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    _create_namespace(ctx, bucket_arn, "ns")
    table_arn = _create_table(ctx, bucket_arn, "ns", "tbl")

    put_code, put_message = _error(
        lambda: s3t.put_table_record_expiration_configuration(
            tableArn=table_arn,
            value={"status": "enabled", "settings": {"days": 365}},
        )
    )
    assert put_code == "MethodNotAllowedException", (
        f"PutTableRecordExpirationConfiguration on a user-created ICEBERG table "
        f"returned {put_code!r}, expected 'MethodNotAllowedException'"
    )
    assert put_message == MSG_NOT_ALLOWED, f"put_message={put_message!r}"

    # Effect absent: no record expiration configuration exists for this table.
    get_code, get_message = _error(
        lambda: s3t.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_code == "MethodNotAllowedException", (
        f"GetTableRecordExpirationConfiguration after the rejected Put returned "
        f"{get_code!r}, expected 'MethodNotAllowedException' -- a different code here "
        f"would mean the rejected Put silently persisted a configuration"
    )
    assert get_message == MSG_NOT_ALLOWED, f"get_message={get_message!r}"

    # Positive control: the table itself is unaffected and fully functional for
    # operations that ARE supported on user-created tables.
    desc = s3t.get_table(tableBucketARN=bucket_arn, namespace="ns", name="tbl")
    assert desc["name"] == "tbl", f"GetTable returned name {desc['name']!r}, expected 'tbl'"
    assert desc["tableARN"] == table_arn, (
        f"GetTable returned tableARN {desc['tableARN']!r}, expected {table_arn!r} -- the "
        f"rejected record-expiration calls must not have disturbed the table identity"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected with MethodNotAllowedException, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn: str, ns: str) -> None:
    s3t = ctx.client("s3tables")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))


def _create_table(ctx, bucket_arn: str, ns: str, name: str) -> str:
    s3t = ctx.client("s3tables")
    arn = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=ns,
        name=name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["tableARN"]
    ctx.on_cleanup(lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=ns, name=name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
