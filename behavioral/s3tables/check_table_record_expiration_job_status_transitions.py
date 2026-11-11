"""table-record-expiration-job-status-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-record-expiration-job-status-transitions"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

NOT_ALLOWED_MSG = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created table, GetTableRecordExpirationJobStatus, PutTableRecordExpirationConfiguration
    and GetTableRecordExpirationConfiguration all answer MethodNotAllowedException instead of an invented
    job status (record expiration is for AWS managed tables only); GetTable still returns the table."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)
    ns = _create_namespace(ctx, bucket_arn)
    table = _create_table(ctx, bucket_arn, ns)

    status_code, status_msg = _error(lambda: s3t.get_table_record_expiration_job_status(tableArn=table["arn"]))
    assert status_code == "MethodNotAllowedException", (
        f"expected GetTableRecordExpirationJobStatus on a customer-created table to be "
        f"categorically rejected with MethodNotAllowedException, got {status_code!r}"
    )
    assert status_msg == NOT_ALLOWED_MSG, status_msg

    # The Put side agrees: expiration can't even be turned on for this table, so there is no
    # configuration and thus no job that could ever be scheduled or run.
    put_code, put_msg = _error(
        lambda: s3t.put_table_record_expiration_configuration(
            tableArn=table["arn"], value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert put_code == "MethodNotAllowedException", (
        f"expected PutTableRecordExpirationConfiguration on a customer-created table to be "
        f"categorically rejected with MethodNotAllowedException, got {put_code!r}"
    )
    assert put_msg == NOT_ALLOWED_MSG, put_msg

    # Effect absent: no record-expiration configuration exists for this table.
    get_config_code, get_config_msg = _error(
        lambda: s3t.get_table_record_expiration_configuration(tableArn=table["arn"])
    )
    assert get_config_code == "MethodNotAllowedException", (
        f"expected the record-expiration configuration to be categorically absent/unavailable "
        f"for this table, got {get_config_code!r}"
    )
    assert get_config_msg == NOT_ALLOWED_MSG, get_config_msg

    # Positive control: the table itself is healthy -- only the record-expiration job-status
    # feature is gated for this table type, not the table as a whole.
    described = s3t.get_table(tableArn=table["arn"])
    assert described["name"] == table["name"], (
        f"expected the table itself to remain fully usable (only the record-expiration "
        f"job-status feature is gated), got name {described['name']!r} vs {table['name']!r}"
    )


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(name=name)["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3t.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_namespace(ctx, bucket_arn: str) -> str:
    s3t = ctx.client("s3tables")
    ns = ctx.unique_name("ns_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns)))
    return ns


def _create_table(ctx, bucket_arn: str, namespace: str) -> dict:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("tbl_").replace("-", "_")
    resp = s3t.create_table(tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG")
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name))
    )
    return {"arn": resp["tableARN"], "name": name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
