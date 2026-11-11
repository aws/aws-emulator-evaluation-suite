"""column-statistics-task-settings-duplicate-create-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "column-statistics-task-settings-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _quiet(fn):
    """Best-effort teardown: the target may already be gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_role(ctx, suffix: str, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-glue-cs-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # AWSGlueServiceRole only grants S3 access under the "aws-glue-*" naming convention, so
    # grant explicit access to our own, differently-named bucket.
    s3_policy_name = "sim2real-bucket-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=s3_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=s3_policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_settings_with_role_retry(fn, *, timeout_s=90, interval_s=5.0):
    """IAM role trust-policy propagation is eventually consistent, so the first
    CreateColumnStatisticsTaskSettings call against a just-created role can be rejected for
    some seconds after the role exists. Bounded retry, not a sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unset column statistics task settings read as EntityNotFoundException with its exact message; a second Create
    during the first task's run fails with ColumnStatisticsTaskRunningException and its exact message and starts
    no run, and once StopColumnStatisticsTaskRun leaves that run STOPPED the same Create succeeds.
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-glue-csdup-").lower().replace("_", "-")
    # us-east-1 is an S3 API quirk, not a region assumption: CreateBucketConfiguration with
    # LocationConstraint=us-east-1 is itself rejected there, so the region check follows
    # ctx.region rather than pinning one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _empty_and_delete_bucket():
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete_bucket)

    db_name = ctx.unique_name("sim2real_csdup_db_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_csdup_tbl_")
    s3.put_object(Bucket=bucket, Key=f"{table_name}/data.csv", Body=b"id\n1\n2\n")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Location": f"s3://{bucket}/{table_name}/",
                "Columns": [{"Name": "id", "Type": "int"}],
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    # Overly-permissive guard: Get/Delete against a table that was never given settings 404s,
    # with no side effect (no settings materialize as a result of the rejected calls).
    code, message = _error(lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name))
    assert code == "EntityNotFoundException", f"Get on a table with no settings: expected EntityNotFoundException, got {code}"
    assert message == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", message
    code, message = _error(
        lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
    )
    assert code == "EntityNotFoundException", f"Delete on a table with no settings: expected EntityNotFoundException, got {code}"
    assert message == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", message
    code, message = _error(lambda: glue.get_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name))
    assert code == "EntityNotFoundException", (
        f"Get after a no-op Delete must still 404 (no side effect): expected EntityNotFoundException, got {code}"
    )
    assert message == "ColumnStatisticsTaskSettings entry for input DatabaseName and TableName does not exist", message

    role_a = _create_glue_role(ctx, "a", bucket)
    role_b = _create_glue_role(ctx, "b", bucket)

    def _poll_task_runs(timeout_s: float = 60, interval_s: float = 3.0):
        deadline = time.monotonic() + timeout_s
        runs = []
        while time.monotonic() < deadline:
            runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name).get(
                "ColumnStatisticsTaskRuns", []
            )
            if runs:
                return runs
            time.sleep(interval_s)
        return runs

    def _wait_terminal(timeout_s: float = 60, interval_s: float = 3.0) -> str:
        deadline = time.monotonic() + timeout_s
        status = None
        while time.monotonic() < deadline:
            runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name).get(
                "ColumnStatisticsTaskRuns", []
            )
            status = runs[0]["Status"] if runs else None
            if status not in ("STARTING", "RUNNING"):
                return status
            time.sleep(interval_s)
        raise AssertionError(f"the latest task run stayed in {status!r} for {timeout_s}s")

    # Positive control: Create succeeds and starts an async task run for role_a.
    _create_settings_with_role_retry(
        lambda: glue.create_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name, Role=role_a)
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: glue.stop_column_statistics_task_run(DatabaseName=db_name, TableName=table_name))
    )
    ctx.on_cleanup(
        lambda: _quiet(
            lambda: glue.delete_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name)
        )
    )

    # Independent read: the task run is visible through GetColumnStatisticsTaskRuns, not just
    # inferred from Create's own response.
    runs = _poll_task_runs()
    assert runs, "expected GetColumnStatisticsTaskRuns to show a run after a successful Create, got none"
    assert runs[0]["Role"] == role_a, f"expected the task run's Role to be {role_a!r}, got {runs[0].get('Role')!r}"

    # The conflict needs a run read in flight right before the second Create: a run that already
    # finished is followed by a fresh StartColumnStatisticsTaskRun under role_a (bounded).
    seen = []
    for attempt in range(3):
        status = runs[0]["Status"]
        if status in ("STARTING", "RUNNING"):
            break
        seen.append(status)
        if attempt == 2:
            raise AssertionError(f"no task run was ever read in flight (STARTING/RUNNING); statuses seen: {seen!r}")
        _wait_terminal(timeout_s=600)
        glue.start_column_statistics_task_run(DatabaseName=db_name, TableName=table_name, Role=role_a)
        runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)[
            "ColumnStatisticsTaskRuns"
        ]
    ids_before = {r["ColumnStatisticsTaskRunId"] for r in runs}

    # Break: a second Create for the same table (different Role) while that run is in flight is rejected with
    # ColumnStatisticsTaskRunningException.
    code, message = _error(
        lambda: glue.create_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name, Role=role_b)
    )
    assert code == "ColumnStatisticsTaskRunningException", (
        f"expected a Create while a task run is in flight to be rejected with "
        f"ColumnStatisticsTaskRunningException, got {code}"
    )
    assert message == "Column statistics task for input table has already started", message

    # No side effect: the same task runs as before the rejected Create, the latest still role_a's.
    runs_after = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)[
        "ColumnStatisticsTaskRuns"
    ]
    ids_after = {r["ColumnStatisticsTaskRunId"] for r in runs_after}
    assert ids_after == ids_before, (
        f"the rejected Create must not have started a task run: {ids_before} before, {ids_after} after"
    )
    assert runs_after[0]["Role"] == role_a, (
        f"the rejected Create must not have touched Role, expected {role_a!r} got {runs_after[0].get('Role')!r}"
    )

    # Restore: stop the in-flight run; the identical Create then succeeds.
    glue.stop_column_statistics_task_run(DatabaseName=db_name, TableName=table_name)

    final_status = _wait_terminal()
    assert final_status == "STOPPED", f"expected StopColumnStatisticsTaskRun to leave the run STOPPED, got {final_status}"

    _create_settings_with_role_retry(
        lambda: glue.create_column_statistics_task_settings(DatabaseName=db_name, TableName=table_name, Role=role_b)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

