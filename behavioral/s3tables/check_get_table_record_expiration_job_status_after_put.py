"""get-table-record-expiration-job-status-after-put."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-record-expiration-job-status-after-put"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created ICEBERG table, GetTableRecordExpirationJobStatus answers MethodNotAllowedException
    before and after a PutTableRecordExpirationConfiguration that is refused the same way (record
    expiration is for AWS managed tables only), while GetTable returns the table's name and ARN."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    namespace = _create_namespace(ctx, bucket_arn)
    table_arn, table_name = _create_table(ctx, bucket_arn, namespace)

    before_code, before_message = _error(
        lambda: s3t.get_table_record_expiration_job_status(tableArn=table_arn)
    )
    assert before_code == "MethodNotAllowedException", (
        f"GetTableRecordExpirationJobStatus on a freshly created customer table returned "
        f"{before_code!r}, expected 'MethodNotAllowedException'"
    )
    assert before_message == "Table record expiration configuration API calls to this table are not allowed", (
        f"expected the exact refusal message before Put, got {before_message!r}"
    )

    # attempting to enable expiration on a customer table is itself rejected
    put_code, put_message = _error(
        lambda: s3t.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert put_code == "MethodNotAllowedException", (
        f"PutTableRecordExpirationConfiguration on a customer table returned {put_code!r}, "
        f"expected 'MethodNotAllowedException'"
    )
    assert put_message == "Table record expiration configuration API calls to this table are not allowed", (
        f"expected the exact refusal message for Put, got {put_message!r}"
    )

    # effect absent: the rejected Put did not flip the job-status endpoint into
    # reporting a scheduled/running job
    after_code, after_message = _error(
        lambda: s3t.get_table_record_expiration_job_status(tableArn=table_arn)
    )
    assert after_code == "MethodNotAllowedException", (
        f"GetTableRecordExpirationJobStatus after a rejected Put returned {after_code!r}, "
        f"expected the unchanged 'MethodNotAllowedException' -- the rejected Put must not "
        f"flip the job-status endpoint into reporting a scheduled/running job"
    )
    assert after_message == "Table record expiration configuration API calls to this table are not allowed", (
        f"expected the exact refusal message after a rejected Put, got {after_message!r}"
    )

    # positive control: the table itself is otherwise fully functional -- only this
    # specific unsupported-on-customer-tables feature is rejected
    described = s3t.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["name"] == table_name, (
        f"positive control GetTable returned name {described['name']!r}, expected "
        f"{table_name!r}"
    )
    assert described["tableARN"] == table_arn, (
        f"positive control GetTable returned tableARN {described['tableARN']!r}, expected "
        f"{table_arn!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name, tags={"sim2real": "true"})["arn"]
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
        tableBucketARN=bucket_arn,
        namespace=namespace,
        name=name,
        format="ICEBERG",
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
