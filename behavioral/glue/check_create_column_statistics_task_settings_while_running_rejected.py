"""create-column-statistics-task-settings-while-running-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-column-statistics-task-settings-while-running-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]

# Without a Schedule, CreateColumnStatisticsTaskSettings defaults to AUTO, which leaves
# GetColumnStatisticsTaskSettings 404ing for minutes after creation; a far-future CRON avoids that.
_FUTURE_SCHEDULE = "cron(0 12 1 1 ? 2099)"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateColumnStatisticsTaskSettings while a column-statistics run is in flight raises
    ColumnStatisticsTaskRunningException and persists nothing; once the run stops it succeeds."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket, role_arn = _setup_bucket_and_role(ctx, s3, iam)

    db_name = ctx.unique_name("sim2realgluedb").replace("-", "_")
    table_name = ctx.unique_name("sim2realgluetbl").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
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
            if exc.response["Error"]["Code"] not in (
                "EntityNotFoundException",
                "ColumnStatisticsTaskNotRunningException",
                "ColumnStatisticsTaskStoppingException",
            ):
                raise

    run_id = _retry_while_role_propagates(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["col1"]
        )
    )["ColumnStatisticsTaskRunId"]
    ctx.on_cleanup(_stop_quietly)

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role_arn, ColumnNameList=["col1"]
        )["ColumnStatisticsTaskRunId"]

    def _wait_terminal(rid):
        return _poll_until(
            lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=rid)[
                "ColumnStatisticsTaskRun"
            ]["Status"],
            lambda status: status in ("STOPPED", "SUCCEEDED", "FAILED"),
            timeout_s=600,
            interval_s=3,
        )

    # AWS only enforces this rejection when no Schedule is given, so the negative call omits it.
    run_id = _ensure_in_flight(glue, run_id, _start, _wait_terminal)
    code, message = _error(
        lambda: glue.create_column_statistics_task_settings(
            DatabaseName=db_name, TableName=table_name, Role=role_arn
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", code
    assert message == "Column statistics task for input table has already started", f"unexpected CreateColumnStatisticsTaskSettings message: {message!r}"

    # Effect absent: no settings were persisted by the rejected call.
    settings_code, settings_message = _error(
        lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    )
    assert settings_code == "EntityNotFoundException", settings_code
    assert settings_message == (
        "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist"
    ), f"unexpected GetColumnStatisticsTaskSettings message: {settings_message!r}"

    # Drain the run, then the positive control: creating settings once idle must succeed.
    _stop_quietly()
    _wait_terminal(run_id)

    glue.create_column_statistics_task_settings(
        DatabaseName=db_name, TableName=table_name, Role=role_arn, Schedule=_FUTURE_SCHEDULE
    )
    ctx.on_cleanup(lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name))

    # GetColumnStatisticsTaskSettings can lag a successful create by a few seconds; retry while
    # it is specifically not-found, and raise on any other error.
    persisted = _poll_until_visible(
        lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)[
            "ColumnStatisticsTaskSettings"
        ]
    )
    assert persisted["Role"] == role_arn, f"expected Role {role_arn!r}, got {persisted['Role']!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_while_role_propagates(fn, timeout_s=90.0, interval_s=5.0):
    """Retry fn() while IAM propagation is pending: Glue reports an unpropagated role as
    AccessDeniedException or an InvalidInputException about assuming it. Other errors raise."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume" in message.lower()
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until_visible(fn, timeout_s=60.0, interval_s=3.0):
    """Retry fn() while it specifically raises EntityNotFoundException (the record has not yet
    become visible); any other error is real and raises immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _setup_bucket_and_role(ctx, s3, iam):
    bucket = ctx.unique_name("sim2real-glue-colstats2-").lower()
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on CreateBucket.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="data/data.csv", Body=b"col1\nalpha\nbeta\ngamma\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="data/data.csv"))

    role_name = ctx.unique_name("sim2real-glue-colstats2-")
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
        f"conflicting call; runs and statuses seen: {seen!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
