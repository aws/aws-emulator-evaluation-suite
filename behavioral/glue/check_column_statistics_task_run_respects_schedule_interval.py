"""column-statistics-task-run-respects-schedule-interval."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "column-statistics-task-run-respects-schedule-interval"
GROUP = "visibility-timeout-ttl"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateColumnStatisticsTaskSettings persists the ScheduleExpression; a second
    StartColumnStatisticsTaskRun while one is in flight fails with
    ColumnStatisticsTaskRunningException, and succeeds once the first run is terminal."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)
    db_name, table_name = _create_glue_table(ctx, role_arn)

    schedule_cron = "cron(0 0 * * ? *)"

    def _create_settings():
        return glue.create_column_statistics_task_settings(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role_arn,
            Schedule=schedule_cron,
        )

    _retry_iam_propagation(_create_settings)
    ctx.on_cleanup(
        lambda: _safe_call(
            glue.delete_column_statistics_task_settings,
            DatabaseName=db_name,
            TableName=table_name,
        )
    )

    settings = glue.get_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_name
    )["ColumnStatisticsTaskSettings"]
    schedule = settings["Schedule"]
    assert schedule["ScheduleExpression"] == schedule_cron, (
        f"expected persisted ScheduleExpression {schedule_cron!r}, got {schedule['ScheduleExpression']!r}"
    )
    assert schedule["State"] == "SCHEDULED", (
        f"expected a freshly created schedule to be in state SCHEDULED, got {schedule['State']!r}"
    )

    first = _retry_iam_propagation(
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
        return {
            r["ColumnStatisticsTaskRunId"]
            for r in glue.get_column_statistics_task_runs(
                DatabaseName=db_name, TableName=table_name
            )["ColumnStatisticsTaskRuns"]
        }

    def _wait_terminal(run_id):
        return _poll_until(
            lambda: glue.get_column_statistics_task_run(
                ColumnStatisticsTaskRunId=run_id
            )["ColumnStatisticsTaskRun"]["Status"],
            lambda status: status in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"),
            timeout_s=600,
            interval_s=10,
        )

    # Break exactly one thing: try to start a second run while the first is
    # read in flight (STARTING/RUNNING) -- this should be rejected.
    ids_before = _run_ids()
    first_run_id = _ensure_in_flight(glue, first_run_id, _start, _wait_terminal)
    ids_before.add(first_run_id)
    code, message = _error(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", (
        f"expected ColumnStatisticsTaskRunningException while first run is in flight, got {code!r}"
    )
    assert message == "Column Statistics task for input table has already started", message

    # Effect absent: the rejected call did not create a second run entry.
    run_ids_while_busy = _run_ids()
    assert run_ids_while_busy == ids_before, (
        f"the refused start created a run: {ids_before} before, {run_ids_while_busy} after"
    )

    # Positive control: once the first run reaches a terminal state, a new
    # run on the same table is accepted (the exclusivity guard has lifted).
    terminal = _wait_terminal(first_run_id)
    assert terminal in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"), (
        f"expected first run to reach a terminal status, got {terminal!r}"
    )

    second_run_id = _start()
    assert second_run_id != first_run_id, (
        f"expected a new run id, got the same id back: {second_run_id!r}"
    )

    # Terminal read: an independent GetColumnStatisticsTaskRun, not the mutating
    # StartColumnStatisticsTaskRun response, confirms the second run actually exists
    # and is progressing at the destination.
    second_status = glue.get_column_statistics_task_run(
        ColumnStatisticsTaskRunId=second_run_id
    )["ColumnStatisticsTaskRun"]["Status"]
    assert second_status in ("STARTING", "RUNNING", "SUCCEEDED", "FAILED"), (
        f"expected the second run to be observably in flight, got status={second_status!r}"
    )



def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            retryable = code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume" in message.lower()
            )
            if retryable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _safe_call(fn, **kwargs):
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    managed_policy_arns = (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    )
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policy_arns:
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


def _create_glue_table(ctx, role_arn):
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    _put_csv_data(ctx, bucket, "data/part-0000.csv")
    db_name = ctx.unique_name("sim2real-glue-db-")
    table_name = ctx.unique_name("sim2real-glue-tbl-")

    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_call(glue.delete_database, Name=db_name))

    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "bigint"},
                    {"Name": "value", "Type": "double"},
                ],
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _safe_call(glue.delete_table, DatabaseName=db_name, Name=table_name))
    return db_name, table_name


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _put_csv_data(ctx, bucket, key):
    s3 = ctx.client("s3")
    body = "\n".join(f"{i},{i}.0" for i in range(1, 51)).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=body)


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
