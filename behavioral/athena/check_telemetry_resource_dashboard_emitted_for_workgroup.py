"""telemetry-resource-dashboard-emitted-for-workgroup."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-resource-dashboard-emitted-for-workgroup"
GROUP = "server-side"
SERVICES = ["athena"]

_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard rejects a live session's ARN built as AWS's documented sample does (a
    StartSession SessionId never matches its `s-[a-z0-9]+` session segment) and a workgroup-only
    ARN with a different message; a completed calculation shows the session itself is live."""
    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    # us-east-1 is the only region where CreateBucket rejects an explicit LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-athena-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    wg_name = ctx.unique_name("sim2real-behav-spark-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_workgroup(athena, wg_name))

    session_id = _start_session_with_retry(athena, wg_name)
    ctx.on_cleanup(lambda: _terminate_session(athena, session_id))

    _poll_session_idle(athena, session_id, timeout_s=600)

    # Positive control: the session is genuinely live and can run real Spark code, not
    # merely reporting IDLE while actually unusable -- so a rejection below is the
    # dashboard surface's own validation, not a dead session.
    _run_trivial_calculation(athena, session_id)

    # AWS's own documented ResourceARN construction, verbatim (raw SessionId).
    session_arn = (
        f"arn:aws:athena:{region}:{account_id}:workgroup/{wg_name}/session/{session_id}"
    )
    code, message = _error_code_and_message(
        lambda: athena.get_resource_dashboard(ResourceARN=session_arn)
    )
    assert code == "InvalidRequestException", (
        f"expected the documented ResourceARN construction to be rejected with "
        f"InvalidRequestException, got {code}: {message}"
    )
    assert "resourceARN" in message and "constraint" in message, (
        f"expected a ResourceARN pattern-constraint rejection, got a different "
        f"InvalidRequestException: {message}"
    )

    # Determinism: the identical call fails identically on a second attempt, ruling out
    # a transient/contention explanation for the rejection above.
    code2, message2 = _error_code_and_message(
        lambda: athena.get_resource_dashboard(ResourceARN=session_arn)
    )
    assert (code2, message2) == (code, message), (
        f"the same call produced a different result on retry: "
        f"first={code}:{message!r} second={code2}:{message2!r}"
    )

    # Contrast: not a blanket failure returning one fixed message for every input -- a
    # workgroup-only ARN (no session suffix at all) is rejected as incomplete, with a
    # DIFFERENT message than the pattern-constraint rejection above.
    bogus_wg_arn = f"arn:aws:athena:{region}:{account_id}:workgroup/{wg_name}"
    bogus_code, bogus_message = _error_code_and_message(
        lambda: athena.get_resource_dashboard(ResourceARN=bogus_wg_arn)
    )
    assert bogus_code == "InvalidRequestException", (
        f"expected InvalidRequestException for a workgroup-only ARN, got {bogus_code}: {bogus_message}"
    )
    assert bogus_message == "ResourceARN is not complete or invalid", (
        f"expected the exact InvalidRequestException message AWS returns, got {bogus_message!r}"
    )
    assert bogus_message != message, (
        "expected a workgroup-only ARN to be rejected for a DIFFERENT reason than the "
        f"documented session ARN above -- got the identical message: {bogus_message!r}"
    )


def _delete_bucket(s3, bucket: str) -> None:
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name: str) -> None:
    for policy_arn in _MANAGED_POLICIES:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_workgroup(athena, wg_name: str) -> None:
    try:
        athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "not found" in err.get("Message", "")):
            raise


def _terminate_session(athena, session_id: str) -> None:
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_session_with_retry(athena, wg_name: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(WorkGroup=wg_name, EngineConfiguration={})
            return resp["SessionId"]
        except Exception as exc:  # IAM role trust-policy propagation lag
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"start_session never succeeded (IAM propagation?): {last_exc}")


def _poll_session_idle(athena, session_id: str, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = athena.get_session_status(SessionId=session_id)["Status"]
        state = status["State"]
        if state == "IDLE":
            return
        if state in ("FAILED", "DEGRADED", "TERMINATED", "TERMINATING"):
            raise AssertionError(f"session hit terminal/bad state {state!r} before IDLE: {status}")
        time.sleep(2)
    raise AssertionError(f"session never reached IDLE within {timeout_s}s")


def _run_trivial_calculation(athena, session_id: str, timeout_s: float = 120.0) -> None:
    calc_id = athena.start_calculation_execution(
        SessionId=session_id, CodeBlock="1 + 1"
    )["CalculationExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_calculation_execution_status(CalculationExecutionId=calc_id)[
            "Status"
        ]["State"]
        if state == "COMPLETED":
            return
        if state in ("FAILED", "CANCELED"):
            raise AssertionError(
                f"trivial calculation ended in {state}: the session is not actually usable"
            )
        time.sleep(5)
    raise AssertionError(f"trivial calculation did not complete within {timeout_s}s, last state={state}")


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
