"""start-calculation-execution-terminated-session-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-calculation-execution-terminated-session-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCalculationExecution completes on a live Spark session, and on a session id that never
    existed raises InvalidRequestException and mints no CalculationExecutionId."""
    athena = ctx.client("athena")

    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)
    session_id = _start_spark_session(ctx, workgroup, role_arn, timeout_s=180)

    # Positive control: the operation under test succeeds against a real, live session.
    calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock="1 + 1")[
        "CalculationExecutionId"
    ]
    assert calc_id, "positive-control StartCalculationExecution minted no CalculationExecutionId"
    state = _poll_calc_state(ctx, calc_id, {"COMPLETED", "FAILED", "CANCELED"}, timeout_s=60)
    assert state == "COMPLETED", f"positive-control calculation never COMPLETED, ended at {state!r}"

    # Independent read, through a different operation than the one that mutated.
    listed = {
        c["CalculationExecutionId"]: c
        for c in athena.list_calculation_executions(SessionId=session_id)["Calculations"]
    }
    assert calc_id in listed and listed[calc_id]["Status"]["State"] == "COMPLETED", (
        f"positive-control calculation {calc_id} not visible as COMPLETED via "
        f"ListCalculationExecutions: {listed.get(calc_id)!r}"
    )

    # The negative: a SessionId this account has never minted.
    fake_session_id = str(uuid.uuid4())
    try:
        resp = athena.start_calculation_execution(SessionId=fake_session_id, CodeBlock="1 + 1")
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        expected = ("InvalidRequestException", "Not authorized to make this request.")
        assert err == expected, (
            f"StartCalculationExecution: expected {expected} for a "
            f"nonexistent session, got {err}"
        )
        return

    raise AssertionError(
        f"StartCalculationExecution unexpectedly succeeded against a nonexistent "
        f"session, minting CalculationExecutionId={resp.get('CalculationExecutionId')!r}"
    )


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
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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


def _start_spark_session(ctx, workgroup, role_arn, timeout_s=180):
    athena = ctx.client("athena")
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 2, "DefaultExecutorDpuSize": 1}
    # A just-created role is not always immediately assumable by the Athena service
    # principal (IAM propagation delay), so StartSession is retried on that specific
    # failure rather than slept for ahead of time — this bounds the wait to only as
    # long as propagation actually takes, with a stated deadline.
    deadline = time.monotonic() + 60.0
    session_id = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn, EngineConfiguration=engine_config,
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


def _poll_calc_state(ctx, calc_id, target_states, timeout_s, interval_s=5.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
