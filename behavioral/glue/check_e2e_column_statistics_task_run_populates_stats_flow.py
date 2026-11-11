"""e2e-column-statistics-task-run-populates-stats-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-column-statistics-task-run-populates-stats-flow"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Running a column statistics task to completion on a real table causes
    GetColumnStatisticsForTable to reflect newly computed statistics matching the
    actual data (exact distinct-value counts), not placeholder zeros."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    database_name = ctx.unique_name("sim2real_cs_db_").replace("-", "_")
    table_name = ctx.unique_name("sim2real_cs_tbl_").replace("-", "_")
    distinct_ids = 20
    rows = [(i, f"cat{i % 4}") for i in range(1, distinct_ids + 1)]
    _create_csv_table(ctx, database_name, table_name, bucket, "data", [("id", "int"), ("category", "string")], rows)
    role_arn = _create_glue_role(ctx, bucket)

    _retry_role_propagation(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=database_name, TableName=table_name, Role=role_arn
        )
    )
    ctx.on_cleanup(
        lambda: glue.delete_column_statistics_task_settings(DatabaseName=database_name, TableName=table_name)
    )

    # CreateColumnStatisticsTaskSettings with no Schedule starts a run immediately on real
    # AWS, so an explicit StartColumnStatisticsTaskRun right after it races the auto-started
    # one and gets ColumnStatisticsTaskRunningException; adopt the auto-started run instead.
    existing_runs = glue.get_column_statistics_task_runs(DatabaseName=database_name, TableName=table_name)[
        "ColumnStatisticsTaskRuns"
    ]
    if existing_runs:
        task_run_id = existing_runs[0]["ColumnStatisticsTaskRunId"]
    else:
        task_run_id = glue.start_column_statistics_task_run(
            DatabaseName=database_name,
            TableName=table_name,
            ColumnNameList=["id", "category"],
            Role=role_arn,
        )["ColumnStatisticsTaskRunId"]
    ctx.on_cleanup(lambda: _safe_stop_column_stats(ctx, database_name, table_name))

    task_run = _poll_until(
        lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=task_run_id)[
            "ColumnStatisticsTaskRun"
        ],
        lambda r: r["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert task_run["Status"] == "SUCCEEDED", f"column statistics task run failed: {task_run}"

    stats = glue.get_column_statistics_for_table(
        DatabaseName=database_name, TableName=table_name, ColumnNames=["id", "category"]
    )
    assert stats["Errors"] == []
    by_column = {s["ColumnName"]: s for s in stats["ColumnStatisticsList"]}
    assert set(by_column) == {"id", "category"}

    id_stats = by_column["id"]["StatisticsData"]["LongColumnStatisticsData"]
    assert id_stats["NumberOfDistinctValues"] == distinct_ids
    assert id_stats["NumberOfNulls"] == 0

    category_stats = by_column["category"]["StatisticsData"]["StringColumnStatisticsData"]
    assert category_stats["NumberOfDistinctValues"] == 4
    assert category_stats["NumberOfNulls"] == 0


# ===== helpers =====
def _safe_stop_column_stats(ctx, database_name, table_name):
    from botocore.exceptions import ClientError

    try:
        ctx.client("glue").stop_column_statistics_task_run(DatabaseName=database_name, TableName=table_name)
    except ClientError as exc:
        # A finished, stopping or already-deleted run has nothing left to stop.
        if exc.response["Error"]["Code"] not in (
            "ColumnStatisticsTaskNotRunningException",
            "ColumnStatisticsTaskStoppingException",
            "EntityNotFoundException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


def _retry_role_propagation(fn, *, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException"):
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("retry_role_propagation exhausted without an error to raise")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-cs-").lower()
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


def _create_csv_table(ctx, database_name, table_name, bucket, key_prefix, columns, rows):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    body = "\n".join(",".join(str(v) for v in row) for row in rows) + "\n"
    s3.put_object(Bucket=bucket, Key=f"{key_prefix}/data.csv", Body=body.encode())
    glue.create_database(DatabaseInput={"Name": database_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database_name))
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": c, "Type": t} for c, t in columns],
                "Location": f"s3://{bucket}/{key_prefix}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database_name, Name=table_name))


def _create_glue_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-cs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access", PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3-access"))
    return role["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
