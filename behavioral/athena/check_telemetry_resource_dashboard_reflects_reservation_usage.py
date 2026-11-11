"""telemetry-resource-dashboard-reflects-reservation-usage."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "telemetry-resource-dashboard-reflects-reservation-usage"
GROUP = "telemetry"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard rejects the documented session ARN (raw SessionId) with a pattern-
    constraint InvalidRequestException, identically on retry, and a workgroup-only ARN differently.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/notebooks-spark-connect.html"""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    role_arn = _create_spark_execution_role(ctx)
    spark_version = _find_spark_engine_version(ctx)
    output_bucket = _create_output_bucket(ctx)

    wg_name = ctx.unique_name("sim2real-behav-sparkwg-")
    _create_spark_workgroup_with_retry(ctx, wg_name, role_arn, spark_version, output_bucket)

    session_id = _start_session_with_retry(ctx, wg_name, role_arn)
    _wait_for_session_ready(ctx, session_id)

    # Positive control: the session is genuinely live and can run real Spark code,
    # not merely reporting IDLE while actually unusable.
    _run_trivial_calculation(ctx, session_id)

    # The documented ARN construction, verbatim; the service requires the session segment to
    # match s-[a-z0-9]+, which a StartSession SessionId (a hyphenated UUID) never does.
    session_arn = (
        f"arn:{partition}:athena:{ctx.region}:{account_id}"
        f":workgroup/{wg_name}/session/{session_id}"
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

    # The identical call fails identically on retry, ruling out a transient rejection.
    code2, message2 = _error_code_and_message(
        lambda: athena.get_resource_dashboard(ResourceARN=session_arn)
    )
    assert (code2, message2) == (code, message), (
        f"the same call produced a different result on retry: "
        f"first={code}:{message!r} second={code2}:{message2!r}"
    )

    # Contrast: a workgroup-only ARN gets a different message, so the validator inspects shape.
    bogus_wg_arn = (
        f"arn:{partition}:athena:{ctx.region}:{account_id}"
        f":workgroup/{ctx.unique_name('sim2real-behav-nonexistent-wg-')}"
    )
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
    assert "complete" in bogus_message.lower(), (
        f"expected an ARN-completeness rejection, got a different InvalidRequestException: {bogus_message}"
    )




def _create_spark_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-athena-spark-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-athena-spark-inline"
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "glue:*", "logs:*", "cloudwatch:PutMetricData", "athena:*"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


def _find_spark_engine_version(ctx) -> str:
    # Prefer "PySpark engine version 3": newer Spark engines reject an explicit
    # DefaultExecutorDpuSize on StartSession. Fall back to any Spark-capable version.
    athena = ctx.client("athena")
    resp = athena.list_engine_versions()
    candidates = [
        ev.get("EngineVersion", ev).get("SelectedEngineVersion", "")
        for ev in resp.get("EngineVersions", [])
    ]
    spark_candidates = [c for c in candidates if "Spark" in c]
    for preferred in spark_candidates:
        if preferred == "PySpark engine version 3":
            return preferred
    if spark_candidates:
        return spark_candidates[0]
    raise AssertionError("no Spark-capable engine version advertised by ListEngineVersions")


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-spark-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup() -> None:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_spark_workgroup_with_retry(
    ctx, wg_name: str, role_arn: str, spark_version: str, output_bucket: str
) -> None:
    athena = ctx.client("athena")
    deadline = time.monotonic() + 90
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(
                Name=wg_name,
                Configuration={
                    "ExecutionRole": role_arn,
                    "EngineVersion": {"SelectedEngineVersion": spark_version},
                    "ResultConfiguration": {"OutputLocation": f"s3://{output_bucket}/"},
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
            )
            return
        except Exception as exc:  # noqa: BLE001 - retry on IAM propagation delay only
            last_exc = exc
            if "not authorized" not in str(exc).lower() and "InvalidRequestException" not in str(exc):
                raise
            time.sleep(5)
    raise AssertionError(f"could not create Spark workgroup after retries: {last_exc}")


def _start_session_with_retry(ctx, wg_name: str, role_arn: str) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + 90
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=wg_name,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    "MaxConcurrentDpus": 2,
                    "DefaultExecutorDpuSize": 1,
                },
            )
            session_id = resp["SessionId"]
            ctx.on_cleanup(lambda: athena.terminate_session(SessionId=session_id))
            return session_id
        except Exception as exc:  # noqa: BLE001 - retry on IAM propagation delay only
            last_exc = exc
            if "not authorized" not in str(exc).lower() and "InvalidRequestException" not in str(exc):
                raise
            time.sleep(5)
    raise AssertionError(f"could not start Spark session after retries: {last_exc}")


def _wait_for_session_ready(ctx, session_id: str, timeout_s: float = 480.0) -> None:
    # StartCalculationExecution rejects a session that is merely CREATED; it must be IDLE.
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state == "IDLE":
            return
        if state in ("FAILED", "DEGRADED", "TERMINATED"):
            raise AssertionError(f"session entered terminal non-ready state: {state}")
        time.sleep(2)
    raise AssertionError(f"session did not become ready in {timeout_s}s, last state={state}")


def _run_trivial_calculation(ctx, session_id: str, timeout_s: float = 120.0) -> None:
    athena = ctx.client("athena")
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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


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
