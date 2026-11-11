"""callback-no-heartbeat-times-out."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "callback-no-heartbeat-times-out"
GROUP = "visibility-timeout-ttl"
SERVICES = ["lambda"]

_HANDLER_CODE = '''
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig


def _register_callback(callback_id):
    return None


@durable_execution
def lambda_handler(event, context: DurableContext):
    timeout_seconds = event.get("timeoutSeconds", 120)
    heartbeat_seconds = event.get("heartbeatTimeoutSeconds", 0)
    config_kwargs = {"timeout": Duration.from_seconds(timeout_seconds)}
    if heartbeat_seconds:
        config_kwargs["heartbeat_timeout"] = Duration.from_seconds(heartbeat_seconds)
    result = context.wait_for_callback(
        _register_callback, name="wait-for-signal", config=WaitForCallbackConfig(**config_kwargs)
    )
    if isinstance(result, bytes):
        result = result.decode("utf-8")
    return {"status": "completed", "result": result}
'''


# timing:real-time — workflow: 8 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A waiting callback with no heartbeat sent before its deadline auto-transitions to timeout.

    Lambda must autonomously detect the elapsed deadline, drive the execution to a non-running
    terminal state, and record a CallbackTimedOutDetails checkpoint after CallbackStartedDetails.
    """
    callback_timeout_s = 8

    fn = _create_durable_function(ctx, _HANDLER_CODE, execution_timeout=120, retention_days=1)
    exec_name = ctx.unique_name("sim2real-cbnh-")
    arn = _invoke_durable(
        ctx,
        fn["name"],
        {"timeoutSeconds": callback_timeout_s, "heartbeatTimeoutSeconds": 0},
        exec_name,
    )

    # Real AWS can take well over a minute to cold-start the durable-execution SDK runtime,
    # checkpoint through wait_for_callback, and surface a CallbackStartedDetails history event
    # (observed empirically; a 60s budget is too tight and spuriously fails this check). It's
    # also possible for a given invocation to never reach that checkpoint at all within any
    # reasonable budget (a cold-start / scheduling hiccup on the durable-execution control
    # plane) -- in that case there is nothing left to exercise, so this fails (never skips)
    # rather than silently passing.
    callback_id, _started_at = _wait_for_callback_id(ctx, arn, timeout_s=180)
    if callback_id is None:
        raise AssertionError(
            f"durable execution {arn} never reached the wait_for_callback checkpoint "
            "(no CallbackStartedDetails history event appeared within the poll window)",
        )

    # Deliberately do nothing: no heartbeat, no success, no failure. Poll (bounded) until
    # Lambda autonomously drives the execution out of RUNNING once the deadline elapses.
    status = _wait_for_execution_status(
        ctx, arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"}, timeout_s=90
    )
    assert status in {"FAILED", "TIMED_OUT"}, (
        f"an unresolved, un-heartbeated callback should not succeed; got status={status}"
    )

    events = _get_history_events(ctx, arn)
    timed_out_events = [ev for ev in events if ev.get("CallbackTimedOutDetails") is not None]
    assert timed_out_events, (
        f"expected a CallbackTimedOutDetails checkpoint in history, got event types present: "
        f"{sorted({k for ev in events for k in ev if k.endswith('Details')})}"
    )

    # The timeout checkpoint must be chronologically after the callback started and at/near the
    # end of the history (the execution has nothing meaningful left to do afterwards).
    started_idx = next(i for i, ev in enumerate(events) if ev.get("CallbackStartedDetails") is not None)
    timed_out_idx = events.index(timed_out_events[0])
    assert timed_out_idx > started_idx, "CallbackTimedOutDetails checkpoint precedes CallbackStartedDetails"


# ===== plumbing (self-contained) =====

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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_durable_execution_role(ctx, fn_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-derole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The generic "basic durable execution" managed policy is not guaranteed to grant the
    # SDK's runtime callback into the Lambda control plane (CheckpointDurableExecution /
    # GetDurableExecutionState) for this specific function. Without those, the SDK's
    # internal checkpoint calls are denied, the execution never reaches the
    # wait_for_callback checkpoint, and GetDurableExecutionHistory never emits a
    # CallbackStartedDetails event -- so grant them explicitly, scoped to this function.
    account = _account_id(ctx)
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:CheckpointDurableExecution", "lambda:GetDurableExecutionState"],
                "Resource": f"arn:aws:lambda:{ctx.region}:{account}:function:{fn_name}:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="durable-inline", PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
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
    # IAM's eventual consistency for this role is already covered by
    # _create_durable_function's own bounded retry on InvalidParameterValueException below;
    # no sleep needed here.
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
    fn_name = ctx.unique_name("sim2real-dfn-")
    role_arn = _create_durable_execution_role(ctx, fn_name)
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
                Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
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
        resp = lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False)
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
        try:
            resp = lam.get_durable_execution_history(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                # The just-started execution is eventually consistent here; treat as no events yet.
                return events
            raise
        events.extend(resp.get("Events", []))
        marker = resp.get("NextMarker")
        if not marker:
            break
    return events


def _wait_for_callback_id(ctx, arn: str, timeout_s: float = 180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        events = _get_history_events(ctx, arn)
        for ev in events:
            details = ev.get("CallbackStartedDetails")
            if details:
                return details["CallbackId"], time.monotonic()
        time.sleep(3)
    # The execution may never reach the wait_for_callback checkpoint within any bounded
    # window (an environment/scheduling limitation, not a product defect to assert on) --
    # return None so the caller can decide to skip instead of raising here.
    return None, None


def _delete_lambda_log_group(
    ctx, function_name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine.

    Late log delivery can recreate it after a delete, so it must stay absent across ``reads``
    consecutive reads before this returns.
    """
    logs = ctx.client("logs")
    name = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
