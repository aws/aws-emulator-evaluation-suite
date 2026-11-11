"""start-column-statistics-task-run-already-running-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-column-statistics-task-run-already-running-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartColumnStatisticsTaskRun while a run is already in progress for the same table returns
    ColumnStatisticsTaskRunningException; once the run finishes, a new run is accepted (positive
    control)."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)
    table = _create_stats_table(ctx)

    run_id_1 = _retry_until_role_usable(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=table["database"], TableName=table["table"], Role=role_arn
        )
    )["ColumnStatisticsTaskRunId"]
    ctx.on_cleanup(lambda: _safe_stop_column_stats(ctx, table["database"], table["table"]))

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=table["database"], TableName=table["table"], Role=role_arn
        )["ColumnStatisticsTaskRunId"]

    ids_before = {
        r["ColumnStatisticsTaskRunId"]
        for r in glue.get_column_statistics_task_runs(
            DatabaseName=table["database"], TableName=table["table"]
        )["ColumnStatisticsTaskRuns"]
    }
    run_id_1 = _ensure_in_flight(
        glue, run_id_1, _start, lambda rid: _wait_column_stats_terminal(ctx, rid, timeout_s=180)
    )
    ids_before.add(run_id_1)
    code, message = _refusal(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=table["database"], TableName=table["table"], Role=role_arn
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", code
    assert message == "Column Statistics task for input table has already started", message

    # effect absent: the refused start created no run
    runs = glue.get_column_statistics_task_runs(DatabaseName=table["database"], TableName=table["table"])[
        "ColumnStatisticsTaskRuns"
    ]
    run_ids = {r["ColumnStatisticsTaskRunId"] for r in runs}
    assert run_ids == ids_before, (
        f"the refused start created a run: tracked {ids_before!r} before, {run_ids!r} after"
    )

    # positive control: once the run finishes, starting a new one succeeds
    glue.stop_column_statistics_task_run(DatabaseName=table["database"], TableName=table["table"])
    _wait_column_stats_terminal(ctx, run_id_1, timeout_s=180)
    run_id_2 = glue.start_column_statistics_task_run(
        DatabaseName=table["database"], TableName=table["table"], Role=role_arn
    )["ColumnStatisticsTaskRunId"]
    ctx.on_cleanup(lambda: _safe_stop_column_stats(ctx, table["database"], table["table"]))
    assert run_id_2 != run_id_1, f"the new run got the same run id as the first: {run_id_2!r}"

    # terminal read: independent of the start call above, confirm the destination now tracks
    # the new run rather than trusting the mutating call's own response
    runs_after = glue.get_column_statistics_task_runs(
        DatabaseName=table["database"], TableName=table["table"]
    )["ColumnStatisticsTaskRuns"]
    run_ids_after = {r["ColumnStatisticsTaskRunId"] for r in runs_after}
    assert run_id_2 in run_ids_after, (
        f"the accepted run {run_id_2!r} is not visible via get_column_statistics_task_runs; "
        f"tracked run ids are {run_ids_after!r}"
    )


# ===== helpers =====
def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _ensure_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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


def _create_stats_table(ctx):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    bucket = ctx.unique_name("sim2real-glue-cs-").lower()
    kwargs = {"Bucket": bucket}
    # us-east-1 literal: S3's own CreateBucket contract rejects a LocationConstraint for that
    # region specifically, not a check-chosen pin.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key="data/sample.csv", Body=b"id,value\n1,10\n2,20\n3,30\n")

    db_name = ctx.unique_name("sim2real_glue_cs_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe_delete_database(ctx, db_name))
    table_name = "sample_tbl"
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "bigint"}, {"Name": "value", "Type": "bigint"}],
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return {"database": db_name, "table": table_name, "bucket": bucket}


def _wait_column_stats_terminal(ctx, run_id, timeout_s=180.0, interval_s=5.0):
    glue = ctx.client("glue")
    terminal = {"SUCCEEDED", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
            "ColumnStatisticsTaskRun"
        ]["Status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"column statistics task run {run_id} never reached {terminal}; last={last}")


def _safe_delete_database(ctx, db_name):
    try:
        ctx.client("glue").delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_stop_column_stats(ctx, db_name, table_name):
    try:
        ctx.client("glue").stop_column_statistics_task_run(DatabaseName=db_name, TableName=table_name)
    except ClientError as exc:
        # a run that already finished or is already stopping has nothing left to stop
        if exc.response["Error"]["Code"] not in (
            "ColumnStatisticsTaskNotRunningException",
            "ColumnStatisticsTaskStoppingException",
            "EntityNotFoundException",
        ):
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
