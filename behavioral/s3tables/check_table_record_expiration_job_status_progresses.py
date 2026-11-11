"""table-record-expiration-job-status-progresses."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-record-expiration-job-status-progresses"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]

NOT_ALLOWED_MSG = "Table record expiration configuration API calls to this table are not allowed"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a customer-created table that accepts a maintenance configuration put, GetTableRecordExpirationJobStatus
    answers MethodNotAllowedException before and after a PutTableRecordExpirationConfiguration that is
    refused the same way: record expiration is for AWS managed tables only."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, "rexp")
    table = _create_table(ctx, bucket_arn, "rexp")

    # positive control: a comparably-shaped PUT (also a table-level configuration
    # write) succeeds on this same table, so the rejections below are specific to
    # record expiration rather than a broadly broken table or credential set.
    s3tables.put_table_maintenance_configuration(
        tableBucketARN=bucket_arn,
        namespace=table["namespace"],
        name=table["name"],
        type="icebergCompaction",
        value={"status": "enabled"},
    )

    before_code, before_msg = _error(
        lambda: s3tables.get_table_record_expiration_job_status(tableArn=table["arn"])
    )
    assert before_code == "MethodNotAllowedException", (
        "expected GetTableRecordExpirationJobStatus to reject a customer-created table "
        f"with MethodNotAllowedException, got {before_code!r}"
    )
    assert before_msg == NOT_ALLOWED_MSG, before_msg

    put_code, put_msg = _error(
        lambda: s3tables.put_table_record_expiration_configuration(
            tableArn=table["arn"], value={"status": "enabled", "settings": {"days": 30}}
        )
    )
    assert put_code == "MethodNotAllowedException", (
        "expected PutTableRecordExpirationConfiguration to reject a customer-created "
        f"table with MethodNotAllowedException, got {put_code!r}"
    )
    assert put_msg == NOT_ALLOWED_MSG, put_msg

    # effect absent: the rejected Put did not flip the job-status endpoint into
    # reporting a scheduled/running job -- the same independent read, re-issued.
    after_code, after_msg = _error(
        lambda: s3tables.get_table_record_expiration_job_status(tableArn=table["arn"])
    )
    assert after_code == "MethodNotAllowedException", (
        "expected GetTableRecordExpirationJobStatus to still reject after a failed "
        f"Put, got {after_code!r}"
    )
    assert after_msg == NOT_ALLOWED_MSG, after_msg


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_table(ctx, bucket_arn: str, prefix: str) -> dict[str, str]:
    s3tables = ctx.client("s3tables")
    namespace = _sanitize(ctx.unique_name(f"sim2real_{prefix}_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        )
    )
    name = _sanitize(ctx.unique_name(f"sim2real_{prefix}_tbl_"))
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    table_arn = resp["tableARN"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
        )
    )
    return {"arn": table_arn, "namespace": namespace, "name": name}


def _error(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
