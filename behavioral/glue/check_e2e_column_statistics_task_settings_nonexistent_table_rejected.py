"""e2e-column-statistics-task-settings-nonexistent-table-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-column-statistics-task-settings-nonexistent-table-rejected"
GROUP = "e2e"
SERVICES = ["glue"]

# A far-future CRON schedule avoids an immediate AUTO run; the AUTO path (no Schedule) leaves
# GetColumnStatisticsTaskSettings 404ing for 60s+ after Create, while CRON is visible at once.
_FUTURE_SCHEDULE = "cron(0 12 1 1 ? 2099)"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateColumnStatisticsTaskSettings on a nonexistent table raises EntityNotFoundException and
    persists nothing, while the same call on an existing table in the same database succeeds and
    is readable via GetColumnStatisticsTaskSettings."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_glue_role(ctx)
    bucket = _create_bucket(ctx)

    database_name = ctx.unique_name("sim2real_cs_neg_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database_name))
    glue.tag_resource(
        ResourceArn=f"arn:aws:glue:{ctx.region}:{account_id}:database/{database_name}",
        TagsToAdd={"sim2real": CHECK},
    )

    real_table_name = ctx.unique_name("sim2real_cs_neg_tbl_").replace("-", "_")
    table_prefix = "data/"
    s3.put_object(Bucket=bucket, Key=f"{table_prefix}part-0000.csv", Body=b"1\n2\n3\n")
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": real_table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}],
                "Location": f"s3://{bucket}/{table_prefix}",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"},
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database_name, Name=real_table_name))

    missing_table_name = real_table_name + "-does-not-exist"

    # The role must be assumable and its table access live first, or the refusal is about the
    # role, not the missing table.
    code = _error_code(
        lambda: _retry_role_propagation(
            lambda: glue.create_column_statistics_task_settings(
                DatabaseName=database_name, TableName=missing_table_name, Role=role_arn
            )
        )
    )
    assert code == (
        "EntityNotFoundException",
        "Table passed as input within input database not found.",
    ), repr(code)

    # Effect absent: no settings were persisted for the nonexistent table.
    code2 = _error_code(
        lambda: glue.get_column_statistics_task_settings(
            DatabaseName=database_name, TableName=missing_table_name
        )
    )
    assert code2 == (
        "EntityNotFoundException",
        "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist",
    ), repr(code2)

    # Positive control on the real table; IAM propagation can briefly fail the role assumption.
    _retry_role_propagation(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=database_name,
            TableName=real_table_name,
            Role=role_arn,
            Schedule=_FUTURE_SCHEDULE,
        )
    )
    ctx.on_cleanup(
        lambda: glue.delete_column_statistics_task_settings(
            DatabaseName=database_name, TableName=real_table_name
        )
    )

    # GetColumnStatisticsTaskSettings lags the Create by a few seconds, so this read is retried.
    persisted = _wait_for_settings_visible(glue, database_name, real_table_name)
    assert persisted["Role"] == role_arn, repr(persisted)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-cs-neg-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and (
                "assume" in message.lower()
                or "s3 location" in message.lower()
                or "role has access" in message.lower()
            ):
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("retry_role_propagation exhausted without an error to raise")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_for_settings_visible(glue, database_name, table_name, *, timeout_s=90.0, interval_s=5.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return glue.get_column_statistics_task_settings(
                DatabaseName=database_name, TableName=table_name
            )["ColumnStatisticsTaskSettings"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFoundException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateColumnStatisticsTaskSettings succeeded but GetColumnStatisticsTaskSettings "
        f"still 404ed after {timeout_s}s: {last_err}"
    )


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-cs-neg-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn))
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

