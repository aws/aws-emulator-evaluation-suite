"""list-executors-fails-after-session-termination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executors-fails-after-session-termination"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExecutors lists a live session's executors and, after TerminateSession, keeps succeeding
    with the same roster settled to a terminal ExecutorState (like GetSession, it does not raise)."""
    athena = ctx.client("athena")
    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)
    session_id = _start_spark_session(ctx, workgroup, role_arn)

    executors = athena.list_executors(SessionId=session_id)["ExecutorsSummary"]
    assert len(executors) >= 1
    executor_ids_before = {e["ExecutorId"] for e in executors}
    for executor in executors:
        assert executor["ExecutorId"]
        assert executor["ExecutorState"] in (
            "CREATING", "CREATED", "REGISTERED", "TERMINATING", "TERMINATED", "FAILED",
        )

    athena.terminate_session(SessionId=session_id)
    state = _poll_session_state(ctx, session_id, {"TERMINATED", "FAILED"}, timeout_s=180)
    assert state == "TERMINATED", f"session never reached TERMINATED, ended at {state!r}"

    # Executor state settles to a terminal value asynchronously after termination.
    final_executors = _poll_for_terminal_executors(ctx, session_id, timeout_s=90)
    final_ids = {e["ExecutorId"] for e in final_executors}
    assert executor_ids_before <= final_ids, (
        f"terminated session's executor roster lost pre-termination executors: "
        f"{executor_ids_before - final_ids}"
    )
    for executor in final_executors:
        assert executor["ExecutorState"] in ("TERMINATING", "TERMINATED", "FAILED"), executor



def _poll_for_terminal_executors(ctx, session_id, timeout_s, interval_s=5.0):
    athena = ctx.client("athena")
    terminal = {"TERMINATING", "TERMINATED", "FAILED"}
    deadline = time.monotonic() + timeout_s
    executors = athena.list_executors(SessionId=session_id)["ExecutorsSummary"]
    while time.monotonic() < deadline:
        if executors and all(e["ExecutorState"] in terminal for e in executors):
            return executors
        time.sleep(interval_s)
        executors = athena.list_executors(SessionId=session_id)["ExecutorsSummary"]
    return executors


def _iam_role_for_spark(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "athena.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policies = [
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ]
    for arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _spark_workgroup(ctx, role_arn):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-spark-wg-")
    # Real AWS requires ResultConfiguration on CreateWorkGroup even for a Spark
    # (interactive) workgroup.
    bucket = _s3_output_bucket(ctx)
    athena.create_work_group(
        Name=name,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_session_state(ctx, session_id, target_states, timeout_s, interval_s=6.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    return state


def _start_spark_session(ctx, workgroup, role_arn, notebook_id=None, timeout_s=480):
    athena = ctx.client("athena")
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 2, "DefaultExecutorDpuSize": 1}
    kwargs = {}
    if notebook_id:
        engine_config["AdditionalConfigs"] = {"NotebookId": notebook_id}
        kwargs["NotebookVersion"] = "Athena notebook version 1"
    # A just-created role is not immediately assumable by Athena (IAM propagation), so
    # StartSession is retried on that failure up to a deadline.
    deadline = time.monotonic() + 60.0
    session_id = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn,
                EngineConfiguration=engine_config, **kwargs,
            )["SessionId"]
            break
        except ClientError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {exc}") from exc
            if "assume" not in msg and "not authorized" not in msg and "access denied" not in msg:
                raise
            last_exc = exc
            time.sleep(5.0)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))
    state = _poll_session_state(ctx, session_id, {"IDLE", "FAILED", "DEGRADED"}, timeout_s)
    if state != "IDLE":
        raise AssertionError(f"session {session_id} never reached IDLE, ended at {state!r}")
    return session_id


def _safe_terminate(ctx, session_id):
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
