"""column-statistics-task-runs-ordering."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "column-statistics-task-runs-ordering"
GROUP = "ordering"
SERVICES = ["glue"]

# Each column statistics task run is a billed Spark job (several minutes); running two
# sequentially (a second run cannot start until the first is terminal - see the
# ColumnStatisticsTaskRunningException negative check) doubles that cost on real AWS. Each
# run is scoped to a single column ("id") of a tiny CSV table to keep that cost minimal.
_TERMINAL_STATES = {"SUCCEEDED", "FAILED", "STOPPED"}


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """GetColumnStatisticsTaskRuns returns both sequential runs of a table exactly once, and their
    CreationTime orders them in the sequence they were started."""
    glue = ctx.client("glue")
    bucket = _create_bucket(ctx)
    db_name = _create_database(ctx)
    table_name = _create_csv_table(ctx, bucket, db_name)
    role_arn = _create_glue_service_role(ctx, s3_bucket=bucket)

    run_ids = []
    for _ in range(2):
        task_run_id = _retry_call(
            lambda: glue.start_column_statistics_task_run(
                DatabaseName=db_name,
                TableName=table_name,
                Role=role_arn,
                ColumnNameList=["id"],
            )["ColumnStatisticsTaskRunId"],
            timeout_s=90.0,
            interval_s=5.0,
        )
        run_ids.append(task_run_id)
        final = _poll_until(
            lambda rid=task_run_id: glue.get_column_statistics_task_run(
                ColumnStatisticsTaskRunId=rid
            )["ColumnStatisticsTaskRun"],
            lambda r: r["Status"] not in ("STARTING", "RUNNING"),
            timeout_s=900.0,
            interval_s=15.0,
        )
        assert final["Status"] in _TERMINAL_STATES, f"run {task_run_id} never reached terminal state: {final}"

    runs = glue.get_column_statistics_task_runs(DatabaseName=db_name, TableName=table_name)[
        "ColumnStatisticsTaskRuns"
    ]
    # GetColumnStatisticsTaskRuns documents no result order, so runs are ordered by CreationTime.
    ours = sorted(
        (r for r in runs if r["ColumnStatisticsTaskRunId"] in run_ids), key=lambda r: r["CreationTime"]
    )
    seen_ids = [r["ColumnStatisticsTaskRunId"] for r in ours]
    assert seen_ids == run_ids, (
        f"expected both runs once, in start sequence {run_ids} by CreationTime, got {seen_ids}"
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
    bucket = ctx.unique_name("sim2real-glue-csto-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_database(ctx):
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_glue_csto_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_csv_table(ctx, bucket, db_name):
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    prefix = "data/"
    csv_body = "id,name\n1,alice\n2,bob\n3,carol\n4,dave\n5,erin\n6,frank\n7,gina\n8,hank\n"
    s3.put_object(Bucket=bucket, Key=f"{prefix}sample.csv", Body=csv_body.encode())
    table_name = ctx.unique_name("sim2real_glue_csto_tbl_").replace("-", "_")
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
    role_name = ctx.unique_name("sim2real-glue-csto-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
