"""durable-execution-checkpoint-sequence-monotonic."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-checkpoint-sequence-monotonic"
GROUP = "ordering"
SERVICES = ["lambda"]

_HANDLER_CODE = '''
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
    durable_step,
)
from aws_durable_execution_sdk_python.config import Duration


@durable_step
def step_a(step_context, n):
    return {"step": "a", "value": n + 1}


@durable_step
def step_b(step_context, n):
    return {"step": "b", "value": n + 2}


@durable_step
def step_c(step_context, n):
    return {"step": "c", "value": n + 3}


@durable_step
def step_d(step_context, n):
    return {"step": "d", "value": n + 4}


@durable_execution
def lambda_handler(event, context: DurableContext):
    n = event.get("n", 0)
    ra = context.step(step_a(n))
    rb = context.step(step_b(n))
    # Force a suspend/resume boundary in the middle of the checkpoint sequence: real
    # checkpoint-token rotation on the runtime side happens across this replay boundary.
    context.wait(Duration.from_seconds(2))
    rc = context.step(step_c(n))
    rd = context.step(step_d(n))
    return {"results": [ra, rb, rc, rd]}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-step durable execution's checkpoints strictly increase EventId in
    GetDurableExecutionHistory, with no duplicates, across the wait-induced suspend/resume.
    """
    # CheckpointDurableExecution's token is only handed to the running function, so the sequence
    # is driven through a real execution and observed via history EventIds.
    fn = _create_durable_function(ctx, _HANDLER_CODE, execution_timeout=300, retention_days=1)
    exec_name = ctx.unique_name("sim2real-decs-")
    arn = _invoke_durable(ctx, fn["name"], {"n": 10}, exec_name)

    status = _wait_for_execution_status(
        ctx, arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}, timeout_s=180
    )
    assert status == "SUCCEEDED", f"execution ended in unexpected status {status}"

    events = _get_history_events(ctx, arn)
    assert len(events) >= 6, f"expected >=6 checkpointed events for 4 steps + a wait, got {len(events)}"

    event_ids = [ev["EventId"] for ev in events]
    for prev, nxt in zip(event_ids, event_ids[1:]):
        assert nxt > prev, f"checkpoint sequence id did not strictly increase: {prev} -> {nxt} in {event_ids}"

    assert len(set(event_ids)) == len(event_ids), f"duplicate checkpoint sequence ids found: {event_ids}"

    # There must be exactly one step-succeeded checkpoint per durable step called.
    step_succeeded = [ev for ev in events if ev.get("StepSucceededDetails") is not None]
    assert len(step_succeeded) == 4, f"expected 4 StepSucceeded checkpoints, got {len(step_succeeded)}"
    step_ids = [ev["EventId"] for ev in step_succeeded]
    assert step_ids == sorted(step_ids), "StepSucceeded checkpoints are not themselves monotonically ordered"


_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_MANAGED_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
)


def _zip_from_source(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_durable_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-derole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
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

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_function_active(ctx, fn_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {fn_name} entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError(f"function {fn_name} did not become Active in {timeout_s}s (last state={state})")


def _create_durable_function(ctx, code: str, execution_timeout: int = 300, retention_days: int = 1) -> dict:
    lam = ctx.client("lambda")
    role_arn = _create_durable_execution_role(ctx)
    fn_name = ctx.unique_name("sim2real-dfn-")
    zip_bytes = _zip_from_source(code)

    resp = None
    last_err = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=60,
                DurableConfig={
                    "ExecutionTimeout": execution_timeout,
                    "RetentionPeriodInDays": retention_days,
                },
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create durable function, last error: {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_function_active(ctx, fn_name)
    return {"name": fn_name, "arn": resp["FunctionArn"]}


def _wait_for_durable_execution_arn(ctx, fn_name: str, execution_name: str, timeout_s: float = 30.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = lam.list_durable_executions_by_function(
            FunctionName=fn_name, DurableExecutionName=execution_name
        )
        execs = resp.get("DurableExecutions", [])
        if execs:
            return execs[0]["DurableExecutionArn"]
        time.sleep(2)
    raise AssertionError(f"durable execution named {execution_name} not found in {timeout_s}s")


def _invoke_durable(ctx, fn_name: str, payload: dict, execution_name: str) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    assert resp["StatusCode"] == 202, f"expected async invoke StatusCode 202, got {resp['StatusCode']}"
    arn = resp.get("DurableExecutionArn")
    if not arn:
        arn = _wait_for_durable_execution_arn(ctx, fn_name, execution_name)
    return arn


def _wait_for_execution_status(ctx, arn: str, target_statuses: set, timeout_s: float = 120.0) -> str:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            resp = lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False)
        except ClientError as err:
            # GetDurableExecution can lag the async invoke's own acceptance by a beat even
            # after the execution is already visible via ListDurableExecutionsByFunction.
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(2)
                continue
            raise
        status = resp["Status"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"execution {arn} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _get_history_events(ctx, arn: str) -> list:
    lam = ctx.client("lambda")
    events: list = []
    marker = None
    while True:
        kwargs = {"DurableExecutionArn": arn, "MaxItems": 1000}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.get_durable_execution_history(**kwargs)
        events.extend(resp.get("Events", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return events


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
