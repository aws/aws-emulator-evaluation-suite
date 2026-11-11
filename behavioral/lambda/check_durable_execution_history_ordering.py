"""durable-execution-history-ordering."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "durable-execution-history-ordering"
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
def step_one(step_context, n):
    return {"step": 1, "value": n}


@durable_step
def step_two(step_context, n):
    return {"step": 2, "value": n * 2}


@durable_step
def step_three(step_context, n):
    return {"step": 3, "value": n * 3}


@durable_execution
def lambda_handler(event, context: DurableContext):
    n = event.get("n", 1)
    r1 = context.step(step_one(n))
    context.wait(Duration.from_seconds(2))
    r2 = context.step(step_two(n))
    r3 = context.step(step_three(n))
    return {"results": [r1, r2, r3]}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-step durable execution with a wait reaches SUCCEEDED, and GetDurableExecutionHistory
    returns its events in timestamp and EventId order from ExecutionStarted to ExecutionSucceeded with
    the wait in between."""
    fn = _create_durable_function(ctx, _HANDLER_CODE, execution_timeout=300, retention_days=1)
    exec_name = ctx.unique_name("sim2real-deho-")
    arn = _invoke_durable(ctx, fn["name"], {"n": 3}, exec_name)

    status = _wait_for_execution_status(
        ctx, arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}, timeout_s=180
    )
    assert status == "SUCCEEDED", f"execution ended in unexpected status {status}"

    events = _get_history_events(ctx, arn)
    assert len(events) >= 5, f"expected several history events for a multi-step execution, got {len(events)}"

    timestamps = [ev["EventTimestamp"] for ev in events]
    assert timestamps == sorted(timestamps), (
        f"history events are not in chronological order by EventTimestamp: {timestamps}"
    )

    event_ids = [ev["EventId"] for ev in events]
    assert event_ids == sorted(event_ids), (
        f"history events are not in chronological order by EventId: {event_ids}"
    )

    # The very first checkpointed event must be the execution starting, and the very last
    # must be the execution succeeding - anchoring the ordering to real lifecycle semantics.
    assert events[0].get("ExecutionStartedDetails") is not None, (
        f"first history event should carry ExecutionStartedDetails, got keys={list(events[0].keys())}"
    )
    assert events[-1].get("ExecutionSucceededDetails") is not None, (
        f"last history event should carry ExecutionSucceededDetails, got keys={list(events[-1].keys())}"
    )

    # A wait was used, so there must be a WaitStarted/WaitSucceeded pair strictly between
    # execution start and end, in that relative order.
    wait_started_idx = next(
        (i for i, ev in enumerate(events) if ev.get("WaitStartedDetails") is not None), -1
    )
    assert wait_started_idx != -1, f"expected a WaitStartedDetails event in history, got events={events}"
    wait_succeeded_idx = next(
        (i for i, ev in enumerate(events) if ev.get("WaitSucceededDetails") is not None), -1
    )
    assert wait_succeeded_idx != -1, f"expected a WaitSucceededDetails event in history, got events={events}"
    assert 0 < wait_started_idx < wait_succeeded_idx < len(events) - 1, (
        "wait checkpoint pair is not positioned in strict chronological order within the history"
    )


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
            # list_durable_executions_by_function can report the execution before
            # GetDurableExecution can see it: a real, observed eventual-consistency lag,
            # not a terminal error.
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(3)
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
