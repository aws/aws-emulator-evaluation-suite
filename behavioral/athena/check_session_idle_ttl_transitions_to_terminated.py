"""session-idle-ttl-transitions-to-terminated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-idle-ttl-transitions-to-terminated"
GROUP = "visibility-timeout-ttl"
SERVICES = ["athena"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/athena/latest/APIReference/API_StartSession.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A Spark session started with SessionIdleTimeoutInMinutes=1 (the API minimum) and left idle
    moves from IDLE to TERMINATED on its own, without any TerminateSession call."""
    ctx.client("athena")
    bucket = _create_result_bucket(ctx)
    role_arn = _create_spark_execution_role(ctx)
    wg_name = _create_spark_workgroup(ctx, role_arn, bucket)

    session_id = _start_session_with_retry(ctx, wg_name, session_idle_timeout_minutes=1)
    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))

    state = _poll_session_state(ctx, session_id, {"IDLE"}, timeout_s=600, interval_s=10)
    assert state == "IDLE", f"session never reached IDLE, last observed state={state!r}"

    # The idle clock starts at IDLE and runs out after ~1 minute; the 420 s bound adds slack.
    state = _poll_session_state(ctx, session_id, {"TERMINATED"}, timeout_s=420, interval_s=10)
    assert state == "TERMINATED", (
        f"session did not auto-terminate after its SessionIdleTimeoutInMinutes elapsed; "
        f"last observed state={state!r}"
    )


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-spark-")
    # S3 rejects a LocationConstraint for us-east-1; every other region requires one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_spark_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "athena.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-athena-spark-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:*", "glue:*", "logs:*", "athena:*"], "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_spark_workgroup(ctx, role_arn: str, bucket: str) -> str:
    athena = ctx.client("athena")
    wg_name = ctx.unique_name("sim2real-athena-spark-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))
    return wg_name


def _start_session_with_retry(ctx, wg_name: str, session_idle_timeout_minutes: int) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + 90
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=wg_name,
                EngineConfiguration={"CoordinatorDpuSize": 1, "DefaultExecutorDpuSize": 1, "MaxConcurrentDpus": 2},
                SessionIdleTimeoutInMinutes=session_idle_timeout_minutes,
            )
            return resp["SessionId"]
        except ClientError as exc:  # newly created IAM role/policy can lag on propagation
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartSession never succeeded (IAM role propagation?): {last_exc}")


def _poll_session_state(ctx, session_id: str, target_states: set[str], timeout_s: float, interval_s: float) -> str:
    athena = ctx.client("athena")
    terminal_states = {"TERMINATED", "FAILED", "DEGRADED"}
    deadline = time.monotonic() + timeout_s
    state = ""
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states or (state in terminal_states and state not in target_states):
            return state
        time.sleep(interval_s)
    return state


def _safe_terminate(ctx, session_id: str) -> None:
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
