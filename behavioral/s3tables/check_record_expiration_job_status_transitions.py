"""record-expiration-job-status-transitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "record-expiration-job-status-transitions"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

MSG_NOT_ALLOWED = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a user-created ICEBERG table, GetTableRecordExpirationJobStatus, PutTableRecordExpirationConfiguration
    and GetTableRecordExpirationConfiguration all answer MethodNotAllowedException instead of a job status
    (record expiration is for AWS managed tables only), while GetTable returns the table 'tbl'."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    _create_namespace(ctx, bucket_arn, "ns")
    table_arn = _create_table(ctx, bucket_arn, "ns", "tbl")

    code, message = _error(
        lambda: s3t.get_table_record_expiration_job_status(tableArn=table_arn)
    )
    assert code == "MethodNotAllowedException", (
        f"expected GetTableRecordExpirationJobStatus on a user-created ICEBERG table to be "
        f"categorically rejected with MethodNotAllowedException, got {code!r}"
    )
    assert message == MSG_NOT_ALLOWED, f"message={message!r}"

    # The Put side agrees: expiration can't even be turned on for this table, so there is
    # no configuration and thus no job that could ever be scheduled or run.
    put_code, put_message = _error(
        lambda: s3t.put_table_record_expiration_configuration(
            tableArn=table_arn, value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert put_code == "MethodNotAllowedException", (
        f"expected PutTableRecordExpirationConfiguration on a user-created ICEBERG table to be "
        f"categorically rejected with MethodNotAllowedException, got {put_code!r}"
    )
    assert put_message == MSG_NOT_ALLOWED, f"put_message={put_message!r}"

    # Effect absent: no record-expiration configuration exists for this table, not merely
    # an empty one.
    get_config_code, get_config_message = _error(
        lambda: s3t.get_table_record_expiration_configuration(tableArn=table_arn)
    )
    assert get_config_code == "MethodNotAllowedException", (
        f"expected the record-expiration configuration to be categorically "
        f"absent/unavailable for this table, got {get_config_code!r}"
    )
    assert get_config_message == MSG_NOT_ALLOWED, f"get_config_message={get_config_message!r}"

    # Positive control: the table remains fully usable for operations that ARE
    # supported on user-created tables, proving the rejections above are specific to
    # the unsupported record-expiration feature.
    desc = s3t.get_table(tableBucketARN=bucket_arn, namespace="ns", name="tbl")
    assert desc["name"] == "tbl", f"expected table name 'tbl', got {desc['name']!r}"
    assert desc["tableARN"] == table_arn, (
        f"expected GetTable to report the same ARN this check created "
        f"({table_arn!r}), got {desc['tableARN']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


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
        tableBucketARN=bucket_arn, namespace=ns, name=name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=ns, name=name))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
