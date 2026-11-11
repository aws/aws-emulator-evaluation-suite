"""column-statistics-concurrent-run-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-concurrent-run-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]

# Starting a column statistics task run launches a real, billed Spark job on real AWS, and this
# check starts two (the conflict probe and the positive control) -- over an 8-row CSV table with
# one column requested, which is as small as the job gets.
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A second StartColumnStatisticsTaskRun on the same table while one is already running is rejected."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    db_name = _create_database(ctx)
    table_name = _create_csv_table(ctx, bucket, db_name)
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket)

    def _start():
        return glue.start_column_statistics_task_run(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role_arn,
            ColumnNameList=["id"],
        )["ColumnStatisticsTaskRunId"]

    def _wait_terminal(run_id):
        return _poll_until(
            lambda: glue.get_column_statistics_task_run(ColumnStatisticsTaskRunId=run_id)[
                "ColumnStatisticsTaskRun"
            ],
            lambda r: r["Status"] not in ("STARTING", "RUNNING"),
            timeout_s=900.0,
            interval_s=15.0,
        )

    def _run_ids():
        runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)
        return {r["ColumnStatisticsTaskRunId"] for r in runs["ColumnStatisticsTaskRuns"]}

    first_run_id = _retry_call(_start, timeout_s=90.0, interval_s=5.0)

    # The conflict is probed only on a run read mid-flight right before it.
    ids_before = _run_ids()
    first_run_id = _ensure_in_flight(glue, first_run_id, _start, _wait_terminal)
    ids_before.add(first_run_id)

    code, message = _error(
        lambda: glue.start_column_statistics_task_run(
            DatabaseName=db_name,
            TableName=table_name,
            Role=role_arn,
            ColumnNameList=["id"],
        )
    )
    assert code == "ColumnStatisticsTaskRunningException", (
        f"expected ColumnStatisticsTaskRunningException for a concurrent run, got {code}"
    )
    assert message == "Column Statistics task for input table has already started", message

    # Effect absent: the refused start created no run for this table.
    run_ids = _run_ids()
    assert run_ids == ids_before, f"expected only {ids_before} to exist, got {run_ids}"

    final = _wait_terminal(first_run_id)
    assert final["Status"] in _TERMINAL_STATES, f"first run never reached terminal state: {final}"

    # Positive control: once the table is free again, a new run is accepted.
    second_run_id = _start()
    assert second_run_id != first_run_id, (
        f"expected a fresh run id once the table is free, got the same id {second_run_id}"
    )
    _wait_terminal(second_run_id)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the concurrent StartColumnStatisticsTaskRun to be rejected, "
        f"but it succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-cstc-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_database(ctx):
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_cstc_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_csv_table(ctx, bucket, db_name):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    prefix = "data/"
    csv_body = "id,name\n1,alice\n2,bob\n3,carol\n4,dave\n5,erin\n6,frank\n7,gina\n8,hank\n"
    s3.put_object(Bucket=bucket, Key=f"{prefix}sample.csv", Body=csv_body.encode())
    table_name = ctx.unique_name("sim2real_glue_cstc_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"skip.header.line.count": "1"},
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "name", "Type": "string"}],
                "Location": f"s3://{bucket}/{prefix}",
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
    return table_name


def _create_glue_service_role(ctx, s3_bucket=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-cstc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    if s3_bucket:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{s3_bucket}", f"arn:aws:s3:::{s3_bucket}/*"],
            }],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


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
