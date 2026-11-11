"""durable-execution-callback-success-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-execution-callback-success-flow"
GROUP = "state-machine"
SERVICES = ["lambda"]

_CALLBACK_HANDLER = '''
import json

from aws_durable_execution_sdk_python import (
    DurableContext,
    durable_execution,
)
from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig


def _notify(callback_id, wait_for_callback_context):
    # No side channel needed: the test observes CallbackId via GetDurableExecutionHistory.
    return None


@durable_execution
def lambda_handler(event, context: DurableContext):
    timeout_seconds = int(event.get("timeout_seconds", 300))
    # The resumed Result is the raw string handed to SendDurableExecutionCallbackSuccess;
    # the SDK does not parse it, so the caller's JSON encoding is decoded here.
    raw = context.wait_for_callback(
        _notify,
        name="approval-callback",
        config=WaitForCallbackConfig(timeout=Duration.from_seconds(timeout_seconds)),
    )
    approval = json.loads(raw) if isinstance(raw, str) else raw
    return {"approval": approval}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Sending a success callback for a waiting durable execution's task token
    transitions the execution to SUCCEEDED and the callback's Result payload flows
    back into the resumed function's return value."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-durcbok-")
    role_arn = _create_durable_role(ctx, name)
    _create_durable_function(
        ctx,
        name=name,
        role_arn=role_arn,
        handler_source=_CALLBACK_HANDLER,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )

    arn = _invoke_durable(
        ctx, function_name=name, payload={"timeout_seconds": 300}, execution_name=ctx.unique_name("cb-ok-")
    )

    callback_id = _wait_for_callback_id(ctx, arn)
    if callback_id is None:
        raise AssertionError(
            "durable execution never reached the wait_for_callback checkpoint "
            "(no CallbackStartedDetails history event appeared within the poll window); "
            "cannot exercise the callback-success effect without a callback to resolve",
        )

    lam.send_durable_execution_callback_success(
        CallbackId=callback_id,
        Result=json.dumps({"approved": True, "comments": "looks good"}).encode("utf-8"),
    )

    final = _poll_until(
        lambda: lam.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True),
        lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
        timeout_s=45.0,
        interval_s=2.0,
    )
    assert final["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['Status']}: {final.get('Error')}"

    result_payload = json.loads(final["Result"])
    approval = result_payload["approval"]
    assert approval["approved"] is True, f"expected the callback Result payload to carry approved=True, got {approval!r}"
    assert approval["comments"] == "looks good", f"expected callback comments 'looks good', got {approval!r}"


# ===== helpers (self-contained) =====


def _zip_from_source(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_for_callback_id(ctx: Any, arn: str, timeout_s: float = 180.0):
    # Real AWS can take well over a minute to cold-start the durable-execution SDK runtime,
    # checkpoint through wait_for_callback, and surface a CallbackStartedDetails history event. It's
    # also possible for the execution to never reach that checkpoint at all (e.g. it settles into a
    # terminal state first) -- polling forever in that case would just be waiting out the clock, so
    # this returns None on timeout instead of raising, and the caller decides whether that's a
    # reason to skip.
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s

    def _probe():
        try:
            events = lam.get_durable_execution_history(DurableExecutionArn=arn)["Events"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                # The execution record can take a moment to become visible to
                # GetDurableExecutionHistory right after invoke() returns the ARN
                # (eventual consistency on the control plane); treat as "not yet
                # reached the checkpoint" rather than a hard failure.
                return None
            raise
        for e in events:
            details = e.get("CallbackStartedDetails")
            if details and details.get("CallbackId"):
                return details["CallbackId"]
        return None

    while time.monotonic() < deadline:
        callback_id = _probe()
        if callback_id is not None:
            return callback_id
        time.sleep(3.0)
    return None


def _account_id(ctx: Any) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_durable_role(ctx: Any, function_name: str) -> str:
    iam = ctx.client("iam")
    account = _account_id(ctx)
    role_name = ctx.unique_name("sim2real-durable-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-durable-role"}],
    )
    role_arn = resp["Role"]["Arn"]

    # A generic "basic durable execution" managed policy is not guaranteed to grant the
    # SDK's runtime callback into the Lambda control plane (CheckpointDurableExecution /
    # GetDurableExecutionState) for this specific function. Without those, the SDK's
    # internal checkpoint calls are denied, the execution never reaches the
    # wait_for_callback checkpoint, and GetDurableExecutionHistory never emits a
    # CallbackStartedDetails event -- so grant them explicitly, scoped to this function.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["lambda:CheckpointDurableExecution", "lambda:GetDurableExecutionState"],
                "Resource": f"arn:aws:lambda:{ctx.region}:{account}:function:{function_name}:*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="durable-inline", PolicyDocument=json.dumps(policy_doc))

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline")
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


def _create_durable_function(
    ctx: Any,
    *,
    name: str,
    role_arn: str,
    handler_source: str,
    durable_config: dict,
    timeout_s: float = 120.0,
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    if not hasattr(lam, "get_durable_execution"):
        raise AssertionError("installed botocore/client does not expose the Lambda durable-execution APIs")

    zip_bytes = _zip_from_source("lambda_function.py", handler_source)
    deadline = time.monotonic() + timeout_s
    resp = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=120,
                MemorySize=256,
                DurableConfig=durable_config,
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-durcbok"},
            )
            break
        except ClientError as exc:
            last_exc = exc
            code = exc.response["Error"]["Code"]
            msg = str(exc)
            if code == "InvalidParameterValueException" and "role" in msg.lower():
                # IAM role propagation is eventually consistent; the freshly created role
                # may not yet be assumable when CreateFunction first validates it.
                time.sleep(3)
                continue
            raise AssertionError(f"durable functions are not available in this environment: {exc}") from exc
    if resp is None:
        raise AssertionError(f"could not create durable function after retries: {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    cfg = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0,
        interval_s=2.0,
    )
    if cfg["State"] != "Active":
        raise AssertionError(f"durable function failed to activate: {cfg.get('StateReason')}")
    return resp["FunctionArn"]


def _invoke_durable(ctx: Any, *, function_name: str, payload: dict, execution_name: str) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(payload).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    arn = resp.get("DurableExecutionArn")
    if arn:
        return arn
    return _poll_until(
        lambda: _find_execution_arn(lam, function_name, execution_name),
        lambda a: a is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )


def _find_execution_arn(lam, function_name: str, execution_name: str):
    execs = lam.list_durable_executions_by_function(FunctionName=function_name)["DurableExecutions"]
    for e in execs:
        if e["DurableExecutionName"] == execution_name:
            return e["DurableExecutionArn"]
    return None


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
