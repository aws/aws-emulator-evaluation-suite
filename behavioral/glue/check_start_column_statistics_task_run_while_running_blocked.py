"""start-column-statistics-task-run-while-running-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-column-statistics-task-run-while-running-blocked"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second StartColumnStatisticsTaskRun while one runs for the table raises
    ColumnStatisticsTaskRunningException with the exact message and records no second run; once
    the first ends, a new run gets a new id.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-colstats-")
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    s3.put_object(Bucket=bucket_name, Key="data/sample.csv", Body=b"col1\nvalue1\nvalue2\n")

    role_arn = _create_glue_assumable_role(ctx, s3_bucket=bucket_name)

    db_name = ctx.unique_name("sim2real-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://{bucket_name}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    first = _retry_role_not_ready(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn
        )
    )
    first_run_id = first["ColumnStatisticsTaskRunId"]

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn
        )["ColumnStatisticsTaskRunId"]

    def _run_ids():
        runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)
        return {r["ColumnStatisticsTaskRunId"] for r in runs["ColumnStatisticsTaskRuns"]}

    def _wait_terminal(run_id):
        return _poll_until(
            lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
                "ColumnStatisticsTaskRun"
            ]["Status"],
            lambda status: status in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"),
            timeout_s=600,
            interval_s=5,
        )

    ids_before = _run_ids()
    first_run_id = _ensure_in_flight(glue, first_run_id, _start, _wait_terminal)
    ids_before.add(first_run_id)
    code, message = _refusal(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", (
        f"expected ColumnStatisticsTaskRunningException for a concurrent run, got {code}"
    )
    assert message == "Column Statistics task for input table has already started", message

    # Effect absent: no second, concurrent task run was recorded for this
    # table while the first was active.
    run_ids = _run_ids()
    assert run_ids == ids_before, f"expected only {ids_before!r} on record, found {run_ids!r}"

    # Wait out the first run's terminal state (SUCCEEDED or FAILED are both
    # fine -- we only need it to stop being "in progress").
    _wait_terminal(first_run_id)

    # Positive control: once the first run is no longer in progress, a fresh
    # start succeeds and gets its own, different run id.
    second = glue.start_column_statistics_task_run(
        DatabaseName=db_name, TableName=table_name, Role=role_arn
    )
    assert second["ColumnStatisticsTaskRunId"] != first_run_id, (
        "expected a fresh run id once the first run stopped being in progress, got the same id back"
    )


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _retry_role_not_ready(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            transient = code in ("AccessDeniedException", "InvalidInputException")
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_bucket(s3, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})


def _delete_bucket(s3, bucket_name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_glue_assumable_role(ctx, s3_bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-colstats-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: _best_effort_detach_policy(iam, role_name, managed_policy_arn))

    if s3_bucket:
        inline_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{s3_bucket}",
                        f"arn:aws:s3:::{s3_bucket}/*",
                    ],
                }
            ],
        }
        policy_name = "sim2real-colstats-s3-access"
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: _best_effort_delete_role_policy(iam, role_name, policy_name))
    return role_arn


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_in_flight(glue, run_id, start, wait_terminal, attempts=3):
    """A run of the table read STARTING or RUNNING right before the conflicting call: ``run_id``
    while it still is, else a fresh run started once the previous one is terminal. A target that
    finishes every run before it can be read in flight fails here."""
    seen = []
    for attempt in range(attempts):
        status = glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
            "ColumnStatisticsTaskRun"
        ]["Status"]
        if status in ("STARTING", "RUNNING"):
            return run_id
        seen.append((run_id, status))
        if attempt == attempts - 1:
            break
        wait_terminal(run_id)
        run_id = start()
    raise AssertionError(
        f"no column statistics task run was ever read in flight (STARTING/RUNNING) before the "
        f"conflicting start; runs and statuses seen: {seen!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
