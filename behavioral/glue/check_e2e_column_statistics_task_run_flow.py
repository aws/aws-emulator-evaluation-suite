"""e2e-column-statistics-task-run-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-column-statistics-task-run-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Configure column statistics task settings, start a run, poll to SUCCEEDED, and
    confirm the computed statistics reflect the actual underlying data (min/max of a
    known integer column) -- not just that the run reached a terminal state."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    prefix = "colstats-data"
    s3.put_object(Bucket=bucket, Key=f"{prefix}/data.csv", Body=b"id,value\n1,10\n2,20\n3,30\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=f"{prefix}/data.csv"))

    role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real-behav-csdb-")
    table_name = ctx.unique_name("sim2real-behav-cstbl-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}, {"Name": "value", "Type": "int"}],
                "Location": f"s3://{bucket}/{prefix}/",
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

    _create_settings_with_retry(ctx, db_name, table_name, role_arn)
    ctx.on_cleanup(lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name))

    run_id = _start_run_with_retry(ctx, db_name, table_name, role_arn)

    final_status = _poll_until(
        lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)["ColumnStatisticsTaskRun"][
            "Status"
        ],
        lambda s: s in {"SUCCEEDED", "FAILED", "STOPPED"},
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final_status == "SUCCEEDED", f"column statistics task run ended in {final_status}"

    stats = glue.get_column_statistics_for_table(DatabaseName=db_name, TableName=table_name, ColumnNames=["value"])
    stats_list = stats["ColumnStatisticsList"]
    assert len(stats_list) == 1, f"expected stats for exactly 1 column, got {len(stats_list)}: {stats_list}"
    col_stats = stats_list[0]
    assert col_stats["ColumnName"] == "value", f"expected column 'value', got {col_stats['ColumnName']!r}"
    long_stats = col_stats["StatisticsData"]["LongColumnStatisticsData"]
    assert long_stats["MinimumValue"] == 10, f"expected min=10, got {long_stats['MinimumValue']}"
    assert long_stats["MaximumValue"] == 30, f"expected max=30, got {long_stats['MaximumValue']}"
    assert long_stats["NumberOfNulls"] == 0, f"expected 0 nulls, got {long_stats['NumberOfNulls']}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cs-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-csrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _create_settings_with_retry(ctx, db_name, table_name, role_arn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            glue.create_column_statistics_task_settings(
                DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["value"]
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"could not create column statistics task settings after retries: {last_err}")


def _start_run_with_retry(ctx, db_name, table_name, role_arn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return glue.start_column_statistics_task_run(
                DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["value"]
            )["ColumnStatisticsTaskRunId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ColumnStatisticsTaskRunningException":
                # a prior attempt's request landed on the server despite the client seeing a transient
                # error (e.g. a read timeout after send) -- recover that run instead of retrying start
                return _most_recent_task_run_id(glue, db_name, table_name)
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"could not start column statistics task run after retries: {last_err}")


def _most_recent_task_run_id(glue, db_name, table_name):
    runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)["ColumnStatisticsTaskRuns"]
    if not runs:
        raise AssertionError(
            f"ColumnStatisticsTaskRunningException reported for {db_name}.{table_name} but "
            "GetColumnStatisticsTaskRuns returned none"
        )
    return max(runs, key=lambda r: r["CreationTime"])["ColumnStatisticsTaskRunId"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
