"""start-column-statistics-task-run-running-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-column-statistics-task-run-running-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting a second column statistics task run for a table that already has one in
    flight is rejected with ColumnStatisticsTaskRunningException, no second run is actually
    created, and once the first run reaches a terminal state a new run is accepted."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    _put_csv_data(ctx, bucket, "data/part-0000.csv")
    role = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real_glue_db_")
    table_name = ctx.unique_name("sim2real_glue_tbl_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "Columns": [{"Name": "id", "Type": "bigint"}, {"Name": "name", "Type": "string"}],
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role["arn"]
        )["ColumnStatisticsTaskRunId"]

    def _status(run_id):
        return glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
            "ColumnStatisticsTaskRun"
        ]["Status"]

    def _wait_terminal(run_id):
        return _poll_until(
            lambda: _status(run_id),
            lambda status: status in ("SUCCEEDED", "FAILED", "STOPPED"),
            timeout_s=900,
            interval_s=15,
        )

    run_id_1 = _retry_on_access_denied(_start, timeout_s=150, interval_s=10)
    ids_before = set(_table_task_run_ids(glue, db_name, table_name))
    assert run_id_1 in ids_before, f"expected {run_id_1} in {ids_before} right after starting it"

    # Break exactly one thing: try to start a second run on the same table while the first
    # is read in flight.
    run_id_1 = _ensure_in_flight(glue, run_id_1, _start, _wait_terminal)
    ids_before.add(run_id_1)
    code, message = _refusal(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name, TableName=table_name, Role=role["arn"]
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", f"expected ColumnStatisticsTaskRunningException, got {code}"
    assert message == "Column Statistics task for input table has already started", message

    # Effect absent: the rejected call did not create a new run, and the original run is
    # untouched.
    ids_after = set(_table_task_run_ids(glue, db_name, table_name))
    assert ids_after == ids_before, f"a second column statistics task run was created despite the conflict: before={ids_before} after={ids_after}"
    run1_status = _status(run_id_1)
    assert run1_status in ("STARTING", "RUNNING", "SUCCEEDED", "FAILED"), (
        f"run {run_id_1} unexpectedly moved to {run1_status}"
    )

    # Positive control: once the first run reaches a terminal state, starting a new run
    # on the same table is accepted.
    final_status = _wait_terminal(run_id_1)
    assert final_status in ("SUCCEEDED", "FAILED", "STOPPED"), (
        f"run {run_id_1} never reached a terminal state, last status {final_status}"
    )
    run_id_2 = _start()
    assert run_id_2 != run_id_1, f"expected a distinct run id, got {run_id_1} again"
    status2 = _status(run_id_2)
    assert status2 in ("STARTING", "RUNNING", "SUCCEEDED", "FAILED"), (
        f"run {run_id_2} had unexpected status {status2}"
    )


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _table_task_run_ids(glue, db_name, table_name, max_pages=25):
    # GetColumnStatisticsTaskRuns is scoped to one table; ListColumnStatisticsTaskRuns is
    # account-wide and would pick up unrelated concurrent activity on a shared account.
    ids: list[str] = []
    token = None
    for _ in range(max_pages):
        kwargs = {"DatabaseName": db_name, "TableName": table_name, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = glue.get_column_statistics_task_runs(**kwargs)
        ids.extend(r["ColumnStatisticsTaskRunId"] for r in resp.get("ColumnStatisticsTaskRuns", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_access_denied(fn, *, timeout_s=120.0, interval_s=5.0):
    """A just-created IAM role can take some seconds to propagate before Glue can
    successfully assume it; StartColumnStatisticsTaskRun validates the role synchronously
    and returns AccessDeniedException or InvalidInputException("...unable to assume
    provided role...") until propagation completes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            transient = code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume" in message.lower() and "role" in message.lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-glue-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 is the only region that rejects an explicit LocationConstraint on CreateBucket.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
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
    body = "\n".join(f"{i},name-{i}" for i in range(1, 51)).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=body)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ):
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return {"name": name, "arn": role_arn}


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
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
