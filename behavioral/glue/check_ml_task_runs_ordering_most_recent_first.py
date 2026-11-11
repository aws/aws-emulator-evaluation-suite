"""ml-task-runs-ordering-most-recent-first."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ml-task-runs-ordering-most-recent-first"
GROUP = "ordering"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMLTaskRuns returns task runs for a transform with the most recent first."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    db_name, table_name = _create_db_and_table(ctx, glue)

    transform_name = ctx.unique_name("sim2real-mltransform-")
    role_arn = _create_glue_service_role(ctx)
    transform_id = _retry_iam_propagation(lambda: glue.create_ml_transform(
        Name=transform_name,
        InputRecordTables=[{"DatabaseName": db_name, "TableName": table_name}],
        Parameters={
            "TransformType": "FIND_MATCHES",
            "FindMatchesParameters": {"PrimaryKeyColumnName": "id"},
        },
        Role=role_arn,
        GlueVersion="3.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
    ))["TransformId"]
    ctx.on_cleanup(lambda: _safe_call(glue.delete_ml_transform, TransformId=transform_id))

    run_id_1 = _start_and_wait_run(glue, transform_id, f"s3://{bucket}/labels1/")
    run_id_2 = _start_and_wait_run(glue, transform_id, f"s3://{bucket}/labels2/")

    resp = glue.get_ml_task_runs(TransformId=transform_id)
    run_ids = [r["TaskRunId"] for r in resp["TaskRuns"]]
    assert run_id_1 in run_ids and run_id_2 in run_ids, (
        f"expected both task runs {run_id_1!r} and {run_id_2!r} in GetMLTaskRuns response, got {run_ids!r}"
    )
    assert run_ids.index(run_id_2) < run_ids.index(run_id_1), (
        "GetMLTaskRuns must order the most recently started task run first"
    )


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-glue-ml-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_db_and_table(ctx, glue):
    db_name = ctx.unique_name("sim2real_glue_ml_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_glue_ml_tbl_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "name", "Type": "string"},
                ],
                "Location": f"s3://sim2real-ml-nonexistent/{table_name}/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return db_name, table_name


def _create_glue_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-mlt-role-")
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
    )
    role_arn = resp["Role"]["Arn"]
    glue_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    s3_policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=glue_policy_arn)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=s3_policy_arn)

    def _cleanup():
        for policy_arn in (glue_policy_arn, s3_policy_arn):
            _safe_call(iam.detach_role_policy, RoleName=role_name, PolicyArn=policy_arn)
        _safe_call(iam.delete_role, RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_iam_propagation(fn, *, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _safe_call(fn, **kwargs):
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "NoSuchEntity"):
            raise


def _start_and_wait_run(glue, transform_id: str, output_s3_path: str) -> str:
    run_id = glue.start_ml_labeling_set_generation_task_run(
        TransformId=transform_id, OutputS3Path=output_s3_path
    )["TaskRunId"]
    _poll_until(
        lambda: glue.get_ml_task_run(TransformId=transform_id, TaskRunId=run_id),
        lambda r: r["Status"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    return run_id


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
