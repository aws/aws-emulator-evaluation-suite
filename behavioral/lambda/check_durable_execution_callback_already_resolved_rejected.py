"""durable-execution-callback-already-resolved-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-execution-callback-already-resolved-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]

HANDLER_SRC = textwrap.dedent(
    """
    from aws_durable_execution_sdk_python import DurableContext, durable_execution
    from aws_durable_execution_sdk_python.config import Duration, WaitForCallbackConfig

    def _notify(callback_id, wait_for_callback_context):
        pass

    @durable_execution
    def lambda_handler(event, context: DurableContext):
        approval = context.wait_for_callback(
            _notify, name="approval", config=WaitForCallbackConfig(timeout=Duration.from_seconds(300))
        )
        return {"approval": approval}
    """
).strip()


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second SendDurableExecutionCallbackSuccess call for a CallbackId that
    has already been resolved is rejected (the callback cannot be completed
    twice), not silently accepted as a no-op."""
    lam = ctx.client("lambda")

    try:
        fn_name = _create_durable_function(ctx, HANDLER_SRC, execution_timeout=300)
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"durable functions unavailable in this account/region/SDK: {e}")

    execution_name = ctx.unique_name("cb-already-resolved-")
    try:
        arn = _invoke_durable(ctx, function_name=fn_name, execution_name=execution_name)
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"could not invoke durable function: {e}")

    callback_id = _wait_for_callback_id(ctx, arn, timeout_s=180)
    if callback_id is None:
        raise AssertionError("execution never reached a callback checkpoint")

    result_payload = json.dumps({"approved": True}).encode()
    lam.send_durable_execution_callback_success(CallbackId=callback_id, Result=result_payload)

    def get_execution():
        return lam.get_durable_execution(DurableExecutionArn=arn)

    final = _poll_until(get_execution, lambda e: e["Status"] in ("SUCCEEDED", "FAILED"), timeout_s=60, interval_s=2)
    assert final["Status"] == "SUCCEEDED", f"expected first callback resolution to SUCCEED, got {final}"

    code, msg = _client_error(
        lambda: lam.send_durable_execution_callback_success(CallbackId=callback_id, Result=result_payload)
    )
    assert code == "CallbackTimeoutException", (
        f"expected re-resolving an already-closed callback to be rejected with "
        f"CallbackTimeoutException, got {code}"
    )
    assert msg == "The callback is either timed out or already completed", f"re-resolution refusal message: {msg!r}"

    after = lam.get_durable_execution(DurableExecutionArn=arn)
    assert after["Status"] == "SUCCEEDED", (
        f"the rejected re-resolution must not disturb the already-recorded terminal status, got {after['Status']}"
    )


# ===== helpers =====
def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _invoke_durable(ctx, *, function_name: str, execution_name: str, timeout_s: float = 30.0) -> str:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=b"{}",
        DurableExecutionName=execution_name,
    )
    arn = resp.get("DurableExecutionArn")
    if arn:
        return arn
    found = _poll_until(
        lambda: _find_execution_arn(lam, function_name, execution_name),
        lambda a: a is not None,
        timeout_s=timeout_s,
        interval_s=2.0,
    )
    return found


def _find_execution_arn(lam, function_name: str, execution_name: str):
    execs = lam.list_durable_executions_by_function(FunctionName=function_name)["DurableExecutions"]
    for e in execs:
        if e["DurableExecutionName"] == execution_name:
            return e["DurableExecutionArn"]
    return None


def _wait_for_callback_id(ctx, durable_execution_arn: str, timeout_s: float = 60.0):
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events = lam.get_durable_execution_history(DurableExecutionArn=durable_execution_arn)["Events"]
        except ClientError as e:
            # The Invoke response can name the execution fractionally before
            # GetDurableExecutionHistory can see it -- a brief propagation gap, not
            # a missing execution.
            if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            time.sleep(2)
            continue
        for e in events:
            details = e.get("CallbackStartedDetails")
            if details and details.get("CallbackId"):
                return details["CallbackId"]
        time.sleep(2)
    return None


def _make_zip(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_durable_role(ctx, function_name: str) -> str:
    iam = ctx.client("iam")
    account = _account_id(ctx)
    role_name = ctx.unique_name("sim2real-durable-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

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
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="durable-inline"))
    return role_arn


def _create_durable_function(
    ctx, handler_src: str, execution_timeout: int = 300, retention_days: int = 1
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-durable-")
    role_arn = _create_durable_role(ctx, fn_name)
    zip_bytes = _make_zip(handler_src)
    last_err = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.13",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                DurableConfig={"ExecutionTimeout": execution_timeout, "RetentionPeriodInDays": retention_days},
                Tags={"sim2real-check": CHECK},
            )
            break
        except ClientError as e:
            # IAM role propagation lag: create_function can reject a just-created
            # role as not-yet-assumable for up to tens of seconds.
            if e.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            last_err = e
            time.sleep(5)
    else:
        raise AssertionError(f"role never became assumable for CreateFunction within 60s: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_for_active(ctx, fn_name)
    return fn_name


def _wait_for_active(ctx, fn_name: str, timeout_s: float = 120.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn_name)
        if cfg["State"] in ("Active", "Failed"):
            break
        time.sleep(2)
    if cfg is None or cfg["State"] != "Active":
        raise AssertionError(f"function did not become Active: {cfg}")


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
