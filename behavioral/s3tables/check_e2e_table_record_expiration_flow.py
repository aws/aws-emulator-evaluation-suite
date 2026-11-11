"""e2e-table-record-expiration-flow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-table-record-expiration-flow"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created ICEBERG table, PutTableRecordExpirationConfiguration and
    GetTableRecordExpirationJobStatus both answer MethodNotAllowedException (record expiration is for
    AWS managed tables only), while GetTable returns the table's name and ARN."""
    s3tables = ctx.client("s3tables")

    bucket_name = ctx.unique_name("sim2real-s3t-ttl-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))
    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real-purpose": "e2e-recexp-flow"})

    ns_name = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns_name))

    table_name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=ns_name, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    )
    s3tables.tag_resource(resourceArn=table_arn, tags={"sim2real-purpose": "e2e-recexp-flow"})

    # Attempting to enable record expiration on a customer table is rejected outright --
    # the managed expiration job pipeline is not reachable for this table class.
    try:
        result = s3tables.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 30}}
        )
        raise AssertionError(
            "expected PutTableRecordExpirationConfiguration to reject a customer table "
            f"with MethodNotAllowedException, but it succeeded and returned {result!r}"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "MethodNotAllowedException", (
            f"expected MethodNotAllowedException, got {code!r}: {e.response['Error']}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Table record expiration configuration API calls to this table are not allowed", (
            f"expected the exact refusal message, got {message!r}"
        )

    # The rejected Put must not silently flip the job-status endpoint into reporting a
    # fabricated scheduled/running job -- it stays rejected too.
    try:
        result = s3tables.get_table_record_expiration_job_status(tableArn=table_arn)
        raise AssertionError(
            "expected GetTableRecordExpirationJobStatus to reject a customer table "
            f"with MethodNotAllowedException, but it succeeded and returned {result!r}"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "MethodNotAllowedException", (
            f"expected MethodNotAllowedException, got {code!r}: {e.response['Error']}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Table record expiration configuration API calls to this table are not allowed", (
            f"expected the exact refusal message, got {message!r}"
        )

    # Positive control: the table itself is otherwise fully functional -- only the
    # unsupported record-expiration feature is rejected, not the whole account/table.
    described = s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    assert described["name"] == table_name, (
        f"expected table name {table_name!r}, got {described.get('name')!r}"
    )
    assert described["tableARN"] == table_arn, (
        f"expected tableARN {table_arn!r}, got {described.get('tableARN')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
