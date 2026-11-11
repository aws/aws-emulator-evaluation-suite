"""callback-timeout-exceeded-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "callback-timeout-exceeded-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["lambda"]

_HANDLER_CODE = '''
from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig


def _notify(callback_id, wait_for_callback_context):
    return None


@durable_execution
def lambda_handler(event, context: DurableContext):
    timeout_seconds = event.get("timeoutSeconds", 120)
    heartbeat_seconds = event.get("heartbeatTimeoutSeconds", 0)
    config_kwargs = {"timeout": Duration.from_seconds(timeout_seconds)}
    if heartbeat_seconds:
        config_kwargs["heartbeat_timeout"] = Duration.from_seconds(heartbeat_seconds)
    result = context.wait_for_callback(
        _notify, name="wait-for-signal", config=WaitForCallbackConfig(**config_kwargs)
    )
    if isinstance(result, bytes):
        result = result.decode("utf-8")
    return {"status": "completed", "result": result}
'''


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


# timing:real-time — workflow: 8 s
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Success, heartbeat and failure callbacks for a timed-out callback are refused with
    CallbackTimeoutException; an in-window callback on the same function is accepted.
    """
    callback_timeout_s = 8

    fn = _create_durable_function(ctx, _HANDLER_CODE, execution_timeout=300, retention_days=1)
    lam = ctx.client("lambda")

    control_name = ctx.unique_name("sim2real-cbto-ctrl-")
    control_arn = _invoke_durable(
        ctx, fn["name"], {"timeoutSeconds": 120, "heartbeatTimeoutSeconds": 0}, control_name
    )
    control_callback_id, _ = _wait_for_callback_id(ctx, control_arn)
    if control_callback_id is None:
        raise _never_ready(
            f"positive-control durable execution {control_arn} never reached the "
            "wait_for_callback checkpoint (no CallbackStartedDetails history event appeared "
            "within the poll window)",
        )
    # positive control: an in-window callback is accepted (a refusal raises here)
    lam.send_durable_execution_callback_success(CallbackId=control_callback_id, Result=b"{}")

    exec_name = ctx.unique_name("sim2real-cbto-")
    arn = _invoke_durable(
        ctx,
        fn["name"],
        {"timeoutSeconds": callback_timeout_s, "heartbeatTimeoutSeconds": 0},
        exec_name,
    )

    # Reaching wait_for_callback and surfacing CallbackStartedDetails can take over a minute.
    callback_id, _started_at = _wait_for_callback_id(ctx, arn, timeout_s=180)
    if callback_id is None:
        raise _never_ready(
            f"durable execution {arn} never reached the wait_for_callback checkpoint "
            "(no CallbackStartedDetails history event appeared within the poll window)",
        )

    # Poll the history for the recorded timeout rather than sleeping a guessed duration.
    _wait_for_callback_timeout_recorded(ctx, arn, timeout_s=callback_timeout_s + 60)

    success_code, success_code_msg = _error(
        lambda: lam.send_durable_execution_callback_success(CallbackId=callback_id, Result=b"{}")
    )
    assert success_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a late success callback, got {success_code}"
    )
    assert success_code_msg == "The callback is either timed out or already completed", (
        f"expected the exact 'CallbackTimeoutException' message, got {success_code_msg!r}"
    )

    heartbeat_code, heartbeat_code_msg = _error(
        lambda: lam.send_durable_execution_callback_heartbeat(CallbackId=callback_id)
    )
    assert heartbeat_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a late heartbeat on an expired callback, got {heartbeat_code}"
    )
    assert heartbeat_code_msg == "The callback is either timed out or already completed", (
        f"expected the exact 'CallbackTimeoutException' message, got {heartbeat_code_msg!r}"
    )

    failure_code, failure_code_msg = _error(
        lambda: lam.send_durable_execution_callback_failure(
            CallbackId=callback_id, Error={"ErrorMessage": "too-late", "ErrorType": "TestError"}
        )
    )
    assert failure_code == "CallbackTimeoutException", (
        f"expected CallbackTimeoutException for a late failure callback, got {failure_code}"
    )
    assert failure_code_msg == "The callback is either timed out or already completed", (
        f"expected the exact 'CallbackTimeoutException' message, got {failure_code_msg!r}"
    )

    # Independent terminal read, through GetDurableExecution rather than any of the three refused
    # send_durable_execution_callback_* calls: proves the refusals had no effect and the execution
    # settled at the timeout outcome, not at the one a successful callback would have produced.
    final = _wait_for_terminal_status(ctx, arn)
    assert final["Status"] == "FAILED", (
        "expected the durable execution to settle at FAILED after its callback window elapsed "
        f"and three post-timeout callback attempts were refused, got {final['Status']!r}"
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


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-derole"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    for policy_arn in _MANAGED_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # The managed policy is not guaranteed to grant the SDK's checkpoint calls; without them the
    # execution never reaches wait_for_callback, so grant them scoped to this function.
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
    # 90s bounds IAM role propagation as seen by Lambda.
    deadline = time.monotonic() + 90.0
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
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-dfn"},
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
                # The new execution is eventually consistent here; treat as no events yet.
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
    # None lets the caller fail with more context via _never_ready.
    return None, None


def _wait_for_callback_timeout_recorded(ctx, arn: str, timeout_s: float = 60.0) -> None:
    """Poll the execution history until Lambda records the callback's timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        events = _get_history_events(ctx, arn)
        if any(ev.get("CallbackTimedOutDetails") is not None for ev in events):
            return
        time.sleep(2)
    raise AssertionError(f"callback for execution {arn} did not record a timeout within {timeout_s}s")


def _wait_for_terminal_status(ctx, arn: str, timeout_s: float = 90.0) -> dict:
    """Poll GetDurableExecution until the execution leaves RUNNING."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_durable_execution(DurableExecutionArn=arn)
        if last["Status"] != "RUNNING":
            return last
        time.sleep(3)
    raise AssertionError(f"durable execution {arn} did not leave RUNNING within {timeout_s}s (last={last!r})")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the function's log group. Late log delivery can recreate it, so it must stay
    absent across two reads 5s apart; a group still present after 30s raises."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def _present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not _present():
            time.sleep(5.0)
            if not _present():
                return
        if time.monotonic() >= deadline:
            raise AssertionError(f"log group {group} still present 30s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
