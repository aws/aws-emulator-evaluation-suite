"""column-statistics-task-settings-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-task-settings-lifecycle"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateColumnStatisticsTaskSettings -> GetColumnStatisticsTaskSettings reflects the
    schedule/role -> DeleteColumnStatisticsTaskSettings removes it and a subsequent get 404s."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    db_name = _create_database(ctx, glue)
    bucket = _create_bucket(ctx)
    table_name = _create_table(ctx, glue, db_name, bucket)
    role_arn = _create_glue_role(ctx, iam, bucket)
    schedule = "cron(0 1 * * ? *)"

    _retrying_call(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role_arn,
            Schedule=schedule,
            SampleSize=50.0,
        ),
        retry_codes=("InvalidInputException",),
    )
    ctx.on_cleanup(lambda: _cleanup_col_stats_settings(glue, db_name, table_name))

    got = glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    settings = got["ColumnStatisticsTaskSettings"]
    assert settings["DatabaseName"] == db_name, f"expected DatabaseName {db_name!r}, got {settings['DatabaseName']!r}"
    assert settings["TableName"] == table_name, f"expected TableName {table_name!r}, got {settings['TableName']!r}"
    assert settings["Role"] == role_arn, f"expected Role {role_arn!r}, got {settings['Role']!r}"
    assert settings["Schedule"]["ScheduleExpression"] == schedule, (
        f"expected schedule {schedule!r}, got {settings['Schedule']['ScheduleExpression']!r}"
    )

    glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)

    code, message = _error(
        lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException on get-after-delete, got {code!r}"
    assert message == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", message

    # a mutation on the dead identifier also fails with the same specific not-found code
    code, message = _error(
        lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    )
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException on double-delete, got {code!r}"
    assert message == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", message

    # the identifier is reusable: create-after-delete against the same table must succeed again
    _retrying_call(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role_arn,
            Schedule=schedule,
            SampleSize=50.0,
        ),
        retry_codes=("InvalidInputException",),
    )
    recreated = glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    recreated_settings = recreated["ColumnStatisticsTaskSettings"]
    assert recreated_settings["Schedule"]["ScheduleExpression"] == schedule, (
        f"expected recreated schedule {schedule!r}, got {recreated_settings['Schedule']['ScheduleExpression']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


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


def _create_glue_role(ctx, iam, bucket: str):
    role_name = ctx.unique_name("sim2real-behav-colstats-role-")
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
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    role_arn = created["Role"]["Arn"]
    ctx.on_cleanup(lambda: _cleanup_role(iam, role_name))

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    ctx.on_cleanup(lambda: _detach_role_policy(iam, role_name))

    # AWSGlueServiceRole only grants S3 access to "aws-glue-*" buckets, so this table's bucket
    # needs an explicit inline grant for Glue to be able to read/sample it for column statistics.
    s3_policy_name = "sim2real-behav-colstats-s3-access"
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

    # bounded wait for IAM eventual consistency before Glue tries to assume it
    _wait_for_role_visible(iam, role_name)
    return role_arn


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise



def _wait_for_role_visible(iam, role_name, attempts: int = 10, delay: float = 2.0) -> None:
    for i in range(attempts):
        try:
            iam.get_role(RoleName=role_name)
            time.sleep(delay)  # extra buffer for cross-service propagation to Glue's assume-role path
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _detach_role_policy(iam, role_name: str) -> None:
    try:
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _cleanup_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_database(ctx, glue) -> str:
    db_name = ctx.unique_name("sim2real_behav_colstats_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _cleanup_database(glue, db_name))
    return db_name


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-colstats-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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


def _create_table(ctx, glue, db_name: str, bucket: str) -> str:
    table_name = ctx.unique_name("sim2real_behav_colstats_tbl_")
    location = f"s3://{bucket}/{db_name}/{table_name}/"
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=f"{db_name}/{table_name}/data.csv", Body=b"id,value\n1,a\n2,b\n")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "value", "Type": "string"},
                ],
                "Location": location,
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _cleanup_table(glue, db_name, table_name))
    return table_name




def _cleanup_col_stats_settings(glue, db_name: str, table_name: str) -> None:
    try:
        glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_table(glue, db_name: str, table_name: str) -> None:
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_database(glue, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

