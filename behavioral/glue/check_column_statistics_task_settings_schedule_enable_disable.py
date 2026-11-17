"""column-statistics-task-settings-schedule-enable-disable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-task-settings-schedule-enable-disable"
GROUP = "column-statistics"
SERVICES = ["glue"]


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _retry_iam_propagation(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """A role Glue just assumed for the first time can still 400 for a few seconds
    while the new role/policy attachment propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "InvalidInputException") \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _settings(glue, database_name: str, table_name: str) -> dict:
    return glue.get_column_statistics_task_settings(
        DatabaseName=database_name, TableName=table_name
    )["ColumnStatisticsTaskSettings"]


def _schedule_state(glue, database_name: str, table_name: str) -> str:
    return _settings(glue, database_name, table_name)["Schedule"]["State"]


def _poll_schedule_state(glue, database_name: str, table_name: str, want: str,
                         *, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = _schedule_state(glue, database_name, table_name)
    while state != want:
        if time.monotonic() >= deadline:
            return state
        time.sleep(interval_s)
        state = _schedule_state(glue, database_name, table_name)
    return state


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-cst2-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _create_table(ctx, glue, s3, bucket: str) -> tuple[str, str]:
    database_name = ctx.unique_name("sim2real_behav_cst2_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": database_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(_teardown(lambda: glue.delete_database(Name=database_name), "EntityNotFoundException"))

    table_name = ctx.unique_name("sim2real_behav_cst2_tbl_").replace("-", "_")
    key = f"{database_name}/{table_name}/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=b"id,amount\n1,10.0\n2,20.0\n")
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "amount", "Type": "double"},
                ],
                "Location": f"s3://{bucket}/{database_name}/{table_name}/",
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(_teardown(lambda: glue.delete_table(DatabaseName=database_name, Name=table_name),
                              "EntityNotFoundException"))
    return database_name, table_name


def _create_glue_role(ctx, iam, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-behav-cst2-role-")
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
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(_teardown(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        ),
        "NoSuchEntity",
    ))
    # AWSGlueServiceRole only grants S3 access to "aws-glue-*" buckets, so this check's own
    # bucket needs an explicit inline grant for Glue to read it for column statistics.
    policy_name = "sim2real-behav-cst2-s3-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
                {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            ],
        }),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
    ))
    _wait_for_role_visible(iam, role_name)
    return role_arn


def _wait_for_role_visible(iam, role_name: str, *, attempts: int = 10, delay: float = 2.0) -> None:
    for i in range(attempts):
        try:
            iam.get_role(RoleName=role_name)
            time.sleep(delay)
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartColumnStatisticsTaskRunSchedule and StopColumnStatisticsTaskRunSchedule toggle
    a column statistics task's Schedule.State, and UpdateColumnStatisticsTaskSettings
    replaces its role, schedule and sampled columns in place.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    database_name, table_name = _create_table(ctx, glue, s3, bucket)
    role_arn = _create_glue_role(ctx, iam, bucket)

    schedule_1 = "cron(0 2 * * ? *)"
    _retry_iam_propagation(lambda: glue.create_column_statistics_task_settings(
        DatabaseName=database_name,
        TableName=table_name,
        Role=role_arn,
        Schedule=schedule_1,
        ColumnNameList=["id"],
        SampleSize=10.0,
    ))
    ctx.on_cleanup(_teardown(
        lambda: glue.delete_column_statistics_task_settings(DatabaseName=database_name, TableName=table_name),
        "EntityNotFoundException",
    ))

    created = _settings(glue, database_name, table_name)
    assert created["Schedule"]["ScheduleExpression"] == schedule_1, (
        f"schedule mismatch at creation: {created['Schedule']['ScheduleExpression']!r} != {schedule_1!r}"
    )

    # StartColumnStatisticsTaskRunSchedule moves Schedule.State to SCHEDULED
    glue.start_column_statistics_task_run_schedule(DatabaseName=database_name, TableName=table_name)
    scheduled = _poll_schedule_state(glue, database_name, table_name, "SCHEDULED")
    assert scheduled == "SCHEDULED", f"StartColumnStatisticsTaskRunSchedule left state {scheduled!r}"

    # StopColumnStatisticsTaskRunSchedule moves it back to NOT_SCHEDULED
    glue.stop_column_statistics_task_run_schedule(DatabaseName=database_name, TableName=table_name)
    not_scheduled = _poll_schedule_state(glue, database_name, table_name, "NOT_SCHEDULED")
    assert not_scheduled == "NOT_SCHEDULED", f"StopColumnStatisticsTaskRunSchedule left state {not_scheduled!r}"

    # UpdateColumnStatisticsTaskSettings replaces the role, schedule and column list
    role_arn_2 = _create_glue_role(ctx, iam, bucket)
    schedule_2 = "cron(0 4 * * ? *)"
    _retry_iam_propagation(lambda: glue.update_column_statistics_task_settings(
        DatabaseName=database_name,
        TableName=table_name,
        Role=role_arn_2,
        Schedule=schedule_2,
        ColumnNameList=["id", "amount"],
        SampleSize=50.0,
    ))
    updated = _settings(glue, database_name, table_name)
    assert updated["Role"] == role_arn_2, f"UpdateColumnStatisticsTaskSettings did not replace Role: {updated['Role']!r}"
    assert updated["Schedule"]["ScheduleExpression"] == schedule_2, (
        f"UpdateColumnStatisticsTaskSettings did not replace Schedule: "
        f"{updated['Schedule']['ScheduleExpression']!r} != {schedule_2!r}"
    )
    assert sorted(updated["ColumnNameList"]) == ["amount", "id"], (
        f"UpdateColumnStatisticsTaskSettings did not replace ColumnNameList: {sorted(updated['ColumnNameList'])!r}"
    )
    assert updated["SampleSize"] == 50.0, f"UpdateColumnStatisticsTaskSettings did not replace SampleSize: {updated['SampleSize']!r}"

    # negative: StartColumnStatisticsTaskRunSchedule on a table with no settings at all is rejected
    other_table = ctx.unique_name("sim2real_behav_cst2_other_").replace("-", "_")
    code, msg = _error(lambda: glue.start_column_statistics_task_run_schedule(
        DatabaseName=database_name, TableName=other_table
    ))
    assert code == "EntityNotFoundException", (
        f"starting a schedule for a table with no column statistics settings gave {code!r}"
    )
    assert msg == (
        f"ColumnStatisticsTaskSettings {ctx.account}:{ctx.account}:{database_name}-{other_table} not found."
    ), f"unexpected message: {msg!r}"

    # delete proves gone: a dropped settings object no longer answers Get or Start
    glue.delete_column_statistics_task_settings(DatabaseName=database_name, TableName=table_name)
    code_get, msg_get = _error(lambda: glue.get_column_statistics_task_settings(
        DatabaseName=database_name, TableName=table_name
    ))
    assert code_get == "EntityNotFoundException", f"reading deleted settings gave {code_get!r}"
    assert msg_get == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", (
        f"unexpected message: {msg_get!r}"
    )
    code_start, msg_start = _error(lambda: glue.start_column_statistics_task_run_schedule(
        DatabaseName=database_name, TableName=table_name
    ))
    assert code_start == "EntityNotFoundException", f"starting a deleted settings' schedule gave {code_start!r}"
    assert msg_start == (
        f"ColumnStatisticsTaskSettings {ctx.account}:{ctx.account}:{database_name}-{table_name} not found."
    ), (
        f"unexpected message: {msg_start!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
