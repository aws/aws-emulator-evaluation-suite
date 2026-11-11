"""column-statistics-task-settings-duplicate-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-task-settings-duplicate-rejected"
GROUP = "ordering"
SERVICES = ["glue"]

# A schedule far in the future so CreateColumnStatisticsTaskSettings does not
# auto-trigger an immediate run (ScheduleType becomes CRON, not AUTO); an active
# run would mask the AlreadyExistsException this check targets with
# ColumnStatisticsTaskRunningException instead.
_FUTURE_SCHEDULE = "cron(0 12 1 1 ? 2099)"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Recreating settings for a table that already has them is rejected, the original
    settings are left untouched, and creating settings for a different table still works."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)

    db_name = ctx.unique_name("sim2real_glue_colstats_neg_db_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_a = _create_table(ctx, glue, db_name, bucket, "a")
    table_b = _create_table(ctx, glue, db_name, bucket, "b")

    original_role = _ensure_glue_role(ctx, "orig")
    _retry_until_role_usable(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_a, Role=original_role, Schedule=_FUTURE_SCHEDULE,
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(
        lambda: glue.delete_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_a
        )
    )

    other_role = _ensure_glue_role(ctx, "other")
    code, message = _error_code_after_role_propagates(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_a, Role=other_role, Schedule=_FUTURE_SCHEDULE
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}: {message}"
    assert message == f"{ctx.account}:{db_name}-{table_a} already exists", message

    # effect absent: the original settings must be unchanged, not overwritten
    settings = glue.get_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_a
    )["ColumnStatisticsTaskSettings"]
    assert settings["Role"] == original_role, "duplicate create must not overwrite the Role"

    # positive control: creating settings for a different, untouched table still succeeds
    glue.create_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_b, Role=original_role, Schedule=_FUTURE_SCHEDULE,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: glue.delete_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_b
        )
    )
    control = glue.get_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_b
    )["ColumnStatisticsTaskSettings"]
    assert control["Role"] == original_role, (
        f"positive control: expected Role {original_role!r} on the untouched table, got {control['Role']!r}"
    )


def _ensure_glue_role(ctx, suffix: str):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-glue-role-{suffix}-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Role"]["Arn"]
    policy_arns = (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_table(ctx, glue, db_name: str, bucket: str, suffix: str) -> str:
    s3 = ctx.client("s3")
    table_name = ctx.unique_name(f"sim2real_glue_colstats_neg_tbl_{suffix}_")
    key_prefix = f"data-{suffix}/"
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}sample.csv", Body=b"id,value\n1,10\n2,20\n")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "bigint"}, {"Name": "value", "Type": "bigint"}],
                "Location": f"s3://{bucket}/{key_prefix}",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return table_name


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-glue-cs-neg-").lower()
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on CreateBucket.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _error_code_after_role_propagates(fn, timeout_s=60.0, interval_s=5.0):
    """Retry while the freshly-created IAM role is still propagating; return the first
    non-transient (code, message).

    Glue surfaces an unpropagated role two different ways: AccessDeniedException, or
    InvalidInputException with a "Service is unable to assume provided
    role. Please verify role's TrustPolicy" message. Only that specific message is treated as
    transient -- any other InvalidInputException is a real rejection and returned immediately.
    """
    deadline = time.monotonic() + timeout_s
    last_code, last_message = None, None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            last_code, last_message = code, message
            if code == "AccessDeniedException" or (
                code == "InvalidInputException" and "unable to assume provided role" in message
            ):
                time.sleep(interval_s)
                continue
            return code, message
        else:
            raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")
    return last_code, last_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
