"""start-column-statistics-task-run-while-running-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-column-statistics-task-run-while-running-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartColumnStatisticsTaskRun while a run is in flight for the same table raises
    ColumnStatisticsTaskRunningException and records no second run; once the first run is
    stopped, a new start succeeds."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket, role_arn = _setup_bucket_and_role(ctx, s3, iam)

    db_name = ctx.unique_name("sim2realgluedb").replace("-", "_")
    table_name = ctx.unique_name("sim2realgluetbl").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "col1", "Type": "string"}],
                "Location": f"s3://{bucket}/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    def _stop_quietly():
        from botocore.exceptions import ClientError

        try:
            glue.stop_column_statistics_task_run(DatabaseName=db_name, TableName=table_name)
        except ClientError as exc:
            # a run that already finished or is already stopping has nothing left to stop
            if exc.response["Error"]["Code"] not in (
                "ColumnStatisticsTaskNotRunningException",
                "ColumnStatisticsTaskStoppingException",
                "EntityNotFoundException",
            ):
                raise

    # Newly-attached IAM permissions can lag; retry the actual call on that specific,
    # transient rejection rather than sleeping blind before it.
    first_id = _retry_role_not_ready(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["col1"]
        )
    )["ColumnStatisticsTaskRunId"]
    ctx.on_cleanup(_stop_quietly)

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["col1"]
        )["ColumnStatisticsTaskRunId"]

    def _run_ids():
        runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)
        return {r["ColumnStatisticsTaskRunId"] for r in runs["ColumnStatisticsTaskRuns"]}

    def _wait_terminal(run_id):
        return _poll_until(
            lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
                "ColumnStatisticsTaskRun"
            ]["Status"],
            lambda status: status in ("STOPPED", "SUCCEEDED", "FAILED"),
            timeout_s=600,
            interval_s=3,
        )

    # Negative: a second start while the first is read in flight must be rejected.
    ids_before = _run_ids()
    first_id = _ensure_in_flight(glue, first_id, _start, _wait_terminal)
    ids_before.add(first_id)
    code, message = _error(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["col1"]
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", code
    expected = "Column Statistics task for input table has already started"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the runs on record for this table are those before the refused start,
    # not a second one that slipped through.
    run_ids = _run_ids()
    assert run_ids == ids_before, f"expected only {ids_before} on record, found {run_ids}"

    # Drain the first run to a terminal state, then the positive control: starting again
    # once nothing is running must succeed.
    _stop_quietly()
    _wait_terminal(first_id)

    second_id = _start()
    ctx.on_cleanup(_stop_quietly)

    # Terminal read is independent of the mutating call: the new run must be on record
    # at the destination, distinct from the drained first run.
    runs_after = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)[
        "ColumnStatisticsTaskRuns"
    ]
    run_ids_after = {r["ColumnStatisticsTaskRunId"] for r in runs_after}
    assert second_id != first_id and second_id in run_ids_after, (
        f"expected a new, independently-visible run distinct from {first_id}, "
        f"got {second_id} in {run_ids_after}"
    )


# ===== helpers =====

def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_role_not_ready(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "InvalidInputException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _setup_bucket_and_role(ctx, s3, iam):
    bucket = ctx.unique_name("sim2real-glue-colstats-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key="data/data.csv", Body=b"col1\nalpha\nbeta\ngamma\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="data/data.csv"))

    role_name = ctx.unique_name("sim2real-glue-colstats-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    # IAM role/policy propagation is eventually consistent; the first use of this role
    # (in run()) retries past AccessDeniedException/InvalidInputException on that basis
    # rather than sleeping blind here.
    return bucket, role["Arn"]


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
