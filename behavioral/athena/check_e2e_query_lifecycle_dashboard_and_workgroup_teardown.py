"""e2e-query-lifecycle-dashboard-and-workgroup-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-query-lifecycle-dashboard-and-workgroup-teardown"
GROUP = "e2e"
SERVICES = ["athena"]

_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark workgroup's session completes a calculation with a result location, GetResourceDashboard
    refuses the session ARN with its exact pattern-validation error, and after the recursive delete
    GetWorkGroup fails InvalidRequestException "WorkGroup is not found."."""
    bucket = _create_bucket(ctx)
    role_arn = _create_execution_role(ctx)
    wg_name = ctx.unique_name("sim2real-behav-spark-wg-")
    athena = ctx.client("athena")
    athena.create_work_group(
        Name=wg_name,
        Configuration={
            "ExecutionRole": role_arn,
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
        },
        Tags=[{"Key": "sim2real", "Value": "query-lifecycle-dashboard-and-workgroup-teardown"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    session_id = _start_session_with_retry(ctx, wg_name, role_arn, timeout_s=120)
    # StartCalculationExecution needs an IDLE session; CREATED is a transient step before it.
    state = _wait_session_state(ctx, session_id, {"IDLE", "FAILED"}, timeout_s=240)
    assert state == "IDLE", f"session {session_id} did not reach IDLE (got {state})"

    calc_id = athena.start_calculation_execution(SessionId=session_id, CodeBlock="1 + 1")[
        "CalculationExecutionId"
    ]
    calc_state, calc = _wait_calculation_terminal(ctx, calc_id, timeout_s=180)
    assert calc_state == "COMPLETED", f"calculation did not complete: {calc.get('Status')}"
    assert calc.get("Result", {}).get("ResultS3Uri"), "completed calculation has no result location"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    session_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}/session/{session_id}"
    dash_code, dash_message = _error_detail(lambda: athena.get_resource_dashboard(ResourceARN=session_arn))
    assert dash_code == "InvalidRequestException", (
        f"expected the documented session ARN to be rejected as InvalidRequestException, got {dash_code!r}"
    )
    expected_dash = (
        "1 validation error detected: Value at 'resourceARN' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        "^arn:(aws[a-zA-Z0-9-]*):athena:[a-zA-Z0-9-]+:\\d{12}:"
        "(workgroup|datacatalog|capacity-reservation|system-table)/[a-zA-Z0-9+=,.@_-]+"
        "(/session/s-[a-z0-9]+)?$"
    )
    assert dash_message == expected_dash, (
        f"expected the exact ARN-pattern validation message {expected_dash!r}, got {dash_message!r}"
    )

    athena.terminate_session(SessionId=session_id)
    _wait_session_state(ctx, session_id, {"TERMINATED", "FAILED"}, timeout_s=120)

    athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)
    code, message = _error_detail(lambda: athena.get_work_group(WorkGroup=wg_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for a deleted workgroup, got {code!r}"
    assert message == "WorkGroup is not found.", f"expected 'WorkGroup is not found.', got {message!r}"


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        raise AssertionError("expected call to raise, but it succeeded")
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")


#: Seconds the check's teardowns may spend retrying a refusal.
_CLEANUP_BUDGET_S = 900.0


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-athena-spark-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "query-lifecycle-dashboard-and-workgroup-teardown"},
    ]})

    def _cleanup():
        # Spark can still be writing results: re-empty and retry until DeleteBucket succeeds.
        deadline = time.monotonic() + _CLEANUP_BUDGET_S
        while True:
            failed = []
            try:
                for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                    objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                    if objs:
                        failed += s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors", [])
                if not failed:
                    s3.delete_bucket(Bucket=name)
                    return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchBucket":
                    return
                if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                    raise
            if failed and time.monotonic() >= deadline:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            time.sleep(2.0)

    ctx.on_cleanup(_cleanup)
    return name


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-athena-spark-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "athena.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "query-lifecycle-dashboard-and-workgroup-teardown"}],
    )["Role"]["Arn"]

    def _cleanup():
        for policy_arn in _MANAGED_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        # A detach still propagating answers DeleteConflict; retry it every 2 s.
        deadline = time.monotonic() + _CLEANUP_BUDGET_S
        while True:
            try:
                iam.delete_role(RoleName=role_name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchEntity":
                    return
                if code != "DeleteConflict" or time.monotonic() >= deadline:
                    raise
            time.sleep(2.0)

    ctx.on_cleanup(_cleanup)
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _start_session_with_retry(ctx, wg_name: str, role_arn: str, timeout_s: float = 120.0) -> str:
    """IAM role propagation is eventually consistent; retry StartSession on
    AccessDenied/InvalidRequestException until the role is usable."""
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = athena.start_session(
                WorkGroup=wg_name,
                ExecutionRole=role_arn,
                EngineConfiguration={
                    "CoordinatorDpuSize": 1,
                    "DefaultExecutorDpuSize": 1,
                    "MaxConcurrentDpus": 2,
                },
            )
            return resp["SessionId"]
        except Exception as err:  # noqa: BLE001 - broad retry on transient IAM propagation
            last_error = err
            time.sleep(5)
    raise AssertionError(f"StartSession never succeeded within {timeout_s}s: {last_error}")


def _wait_session_state(ctx, session_id: str, target_states: set, timeout_s: float = 120.0) -> str:
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(5)
    raise AssertionError(f"session {session_id} still in {state!r} after {timeout_s}s")


def _wait_calculation_terminal(ctx, calculation_execution_id: str, timeout_s: float = 180.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    calc = None
    while time.monotonic() < deadline:
        calc = athena.get_calculation_execution(CalculationExecutionId=calculation_execution_id)
        state = calc["Status"]["State"]
        if state in ("COMPLETED", "FAILED", "CANCELED"):
            return state, calc
        time.sleep(5)
    raise AssertionError(f"calculation {calculation_execution_id} did not terminate in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
