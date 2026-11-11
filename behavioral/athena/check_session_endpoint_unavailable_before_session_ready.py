"""session-endpoint-unavailable-before-session-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-endpoint-unavailable-before-session-ready"
GROUP = "visibility-timeout-ttl"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSessionEndpoint right after StartSession, before IDLE, is rejected with
    InvalidRequestException; once the session reaches IDLE the same call returns an endpoint and token.
    """
    athena = ctx.client("athena")
    bucket = _create_result_bucket(ctx)
    role_arn = _create_spark_execution_role(ctx)
    wg_name = _create_spark_workgroup(ctx, role_arn, bucket)

    session_id = _start_session_with_retry(ctx, wg_name, session_idle_timeout_minutes=60)
    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))

    # A Spark session takes well over a second to acquire resources, so this is pre-IDLE.
    status = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    assert status != "IDLE", "session was unexpectedly already IDLE; cannot exercise the not-ready path"

    code, message = _error_code(lambda: athena.get_session_endpoint(SessionId=session_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException while not ready, got {code!r}"
    assert message == "Can not generate Session endpoint URL for Session in PROVISIONING state", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )

    # Positive control: once IDLE, the same call succeeds.
    state = _poll_session_state(ctx, session_id, {"IDLE"}, timeout_s=600, interval_s=10)
    assert state == "IDLE", f"session never reached IDLE, last observed state={state!r}"

    try:
        resp = athena.get_session_endpoint(SessionId=session_id)
    except ClientError as exc:
        raise AssertionError(
            f"positive control failed: GetSessionEndpoint on an IDLE session was rejected with {exc.response['Error']}"
        ) from exc
    assert resp["EndpointUrl"], "expected a non-empty EndpointUrl once the session is IDLE"
    assert resp["AuthToken"], "expected a non-empty AuthToken once the session is IDLE"
    assert resp["AuthTokenExpirationTime"] is not None, "expected a non-None AuthTokenExpirationTime once the session is IDLE"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected while the session is not ready, but it SUCCEEDED and returned {result!r}")


def _create_result_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-spark-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "session-endpoint-unavailable-before-session-ready"}]}
    )
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
        Tags=[{"Key": "sim2real", "Value": "session-endpoint-unavailable-before-session-ready"}],
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
    _create_work_group_with_role_retry(
        athena,
        Name=wg_name,
        # On "PySpark engine version 3" GetSessionEndpoint is refused at every session state, so
        # the IDLE leg needs "Apache Spark version 3.5", which rejects a ResultConfiguration.
        Configuration={
            "ExecutionRole": role_arn,
            "EngineVersion": {"SelectedEngineVersion": "Apache Spark version 3.5"},
        },
        Tags=[{"Key": "sim2real", "Value": "session-endpoint-unavailable-before-session-ready"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))
    return wg_name


def _create_work_group_with_role_retry(athena, *, timeout_s: float = 120.0, interval_s: float = 5.0, **kwargs):
    """Retry CreateWorkGroup while the just-created execution role is not yet assumable by
    athena.amazonaws.com (IAM propagation surfaces as "Misconfigured service role")."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return athena.create_work_group(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            transient = err.get("Code") == "InvalidRequestException" and (
                "Misconfigured service role" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _start_session_with_retry(ctx, wg_name: str, session_idle_timeout_minutes: int) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + 90
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            # No DPU sizing: an "Apache Spark version 3.5" workgroup rejects DefaultExecutorDpuSize.
            resp = athena.start_session(
                WorkGroup=wg_name,
                EngineConfiguration={"MaxConcurrentDpus": 2},
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
    raise AssertionError(f"session {session_id} did not reach {target_states} within {timeout_s}s; last observed state={state!r}")


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
