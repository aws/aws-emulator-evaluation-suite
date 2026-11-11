"""column-statistics-task-settings-schedule-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-task-settings-schedule-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cron schedule expression set on CreateColumnStatisticsTaskSettings is
    preserved verbatim (not reformatted/normalized) on GetColumnStatisticsTaskSettings."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    bucket = _create_bucket(ctx)
    database_name, table_name = _create_glue_table(ctx, bucket)
    role_arn = _create_glue_role(ctx, iam, bucket)

    schedule_expression = "cron(15 12 * * ? *)"

    _retrying_call(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=database_name,
            TableName=table_name,
            Role=role_arn,
            Schedule=schedule_expression,
            ColumnNameList=["id", "amount"],
            SampleSize=20.0,
        ),
        retry_codes=("InvalidInputException",),
    )
    ctx.on_cleanup(
        lambda: _cleanup_col_stats_settings(glue, database_name, table_name)
    )

    fetched = glue.get_column_statistics_task_settings(
        DatabaseName=database_name, TableName=table_name
    )["ColumnStatisticsTaskSettings"]

    assert fetched["Role"] == role_arn, f"role mismatch: {fetched['Role']!r} != {role_arn!r}"
    assert fetched["Schedule"]["ScheduleExpression"] == schedule_expression, (
        f"schedule mismatch: {fetched['Schedule']['ScheduleExpression']!r} "
        f"!= {schedule_expression!r}"
    )
    assert sorted(fetched["ColumnNameList"]) == sorted(["id", "amount"]), (
        f"column list mismatch: {sorted(fetched['ColumnNameList'])!r} != {sorted(['id', 'amount'])!r}"
    )


def _retrying_call(fn, attempts: int = 8, base_delay: float = 3.0, retry_codes=("InternalServiceException", "ThrottlingException")):
    """Newly-created IAM roles/policies take time to propagate; Glue's AssumeRole check
    against a brand-new role commonly fails for a few seconds after creation."""
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in retry_codes and i < attempts - 1:
                last_exc = exc
                time.sleep(base_delay)
                continue
            raise
    raise last_exc


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cst-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_glue_table(ctx, bucket: str) -> tuple[str, str]:
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    database_name = ctx.unique_name("sim2real_behav_cst_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": database_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _cleanup_database(glue, database_name))

    table_name = ctx.unique_name("sim2real_behav_cst_tbl_").replace("-", "_").lower()
    location = f"s3://{bucket}/{database_name}/{table_name}/"
    s3.put_object(
        Bucket=bucket,
        Key=f"{database_name}/{table_name}/data.csv",
        Body=b"id,amount\n1,10.0\n2,20.0\n",
    )
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "amount", "Type": "double"},
                ],
                "Location": location,
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _cleanup_table(glue, database_name, table_name))
    return database_name, table_name


def _create_glue_role(ctx, iam, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-behav-cst-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _cleanup_role(iam, role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: _detach_role_policy(iam, role_name, managed_policy_arn))

    # AWSGlueServiceRole only grants S3 access to "aws-glue-*" buckets, so this table's
    # bucket needs an explicit inline grant for Glue to read/sample it for column statistics.
    s3_policy_name = "sim2real-behav-cst-s3-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=s3_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, s3_policy_name))

    _wait_for_role_visible(iam, role_name)
    return role_arn


def _wait_for_role_visible(iam, role_name, attempts: int = 10, delay: float = 2.0) -> None:
    for i in range(attempts):
        try:
            iam.get_role(RoleName=role_name)
            time.sleep(delay)
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _detach_role_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _cleanup_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _cleanup_col_stats_settings(glue, database_name: str, table_name: str) -> None:
    try:
        glue.delete_column_statistics_task_settings(DatabaseName=database_name, TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_table(glue, database_name: str, table_name: str) -> None:
    try:
        glue.delete_table(DatabaseName=database_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_database(glue, database_name: str) -> None:
    try:
        glue.delete_database(Name=database_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
