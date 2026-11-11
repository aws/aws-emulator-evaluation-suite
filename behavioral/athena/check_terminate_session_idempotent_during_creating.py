"""terminate-session-idempotent-during-creating."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "terminate-session-idempotent-during-creating"
GROUP = "state-machine"
SERVICES = ["athena"]

_TERMINAL = {"TERMINATED", "FAILED"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateSession on a still-provisioning Spark session drives it to a terminal state, and a
    second TerminateSession succeeds as a no-op leaving that terminal state unchanged."""
    athena = ctx.client("athena")
    iam = ctx.client("iam")

    role_arn = _create_spark_execution_role(ctx, iam)
    bucket = _create_output_bucket(ctx)
    wg = ctx.unique_name("sim2real-athena-sparkwg-")

    try:
        athena.create_work_group(
            Name=wg,
            Configuration={
                "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
                "ExecutionRole": role_arn,
                "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
            },
            Tags=[{"Key": "sim2real", "Value": "terminate-session-idempotent-during-creating"}],
        )
    except ClientError as exc:
        raise AssertionError(f"Spark-enabled workgroups unavailable here: {exc}")

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True)
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
                raise

    ctx.on_cleanup(_cleanup_wg)

    session_id = _start_session_with_retry(athena, wg, role_arn, timeout_s=60.0)

    def _cleanup_session() -> None:
        try:
            athena.terminate_session(SessionId=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_session)

    # Athena may report CREATED rather than CREATING here, so assert "not ready, not terminal".
    initial_state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    assert initial_state != "IDLE" and initial_state not in _TERMINAL, (
        f"expected session to still be provisioning (pre-IDLE) immediately "
        f"after StartSession, got {initial_state!r} (this check exercises "
        f"TerminateSession against an early lifecycle point, not a settled one)"
    )

    first = athena.terminate_session(SessionId=session_id)
    assert first["State"] in ("TERMINATING", "TERMINATED", "FAILED"), (
        f"unexpected State from TerminateSession on a CREATING session: {first['State']!r}"
    )

    terminal_state = _wait_for_session_terminal(athena, session_id, timeout_s=240)
    assert terminal_state in _TERMINAL, (
        f"session never reached a terminal state, last state={terminal_state}"
    )

    second = athena.terminate_session(SessionId=session_id)
    assert second["State"] == terminal_state, (
        f"idempotent TerminateSession changed reported state: "
        f"{terminal_state} -> {second['State']}"
    )

    after = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    assert after == terminal_state, (
        f"second TerminateSession call mutated session state: "
        f"{terminal_state} -> {after}"
    )


def _wait_for_session_terminal(athena, session_id, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in _TERMINAL:
            return state
        time.sleep(interval_s)
    return state


def _create_spark_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-athena-sparkrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "terminate-session-idempotent-during-creating"}],
    )["Role"]

    def _cleanup_role() -> None:
        for arn in (
            "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
            "arn:aws:iam::aws:policy/AmazonS3FullAccess",
            "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
        ):
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    for arn in (
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    # Bounded wait for IAM eventual consistency before Athena assumes the role.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2.0)

    return role["Arn"]


def _start_session_with_retry(athena, workgroup, role_arn, timeout_s=60.0, interval_s=5.0):
    """Retry StartSession until Athena can assume the new role; the policy attachment can lag past
    GetRole visibility."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=workgroup,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    "DefaultExecutorDpuSize": 1,
                    "MaxConcurrentDpus": 2,
                },
                ClientRequestToken=uuid.uuid4().hex,
            )
            return resp["SessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"StartSession unavailable in this environment: {last_exc}")


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
