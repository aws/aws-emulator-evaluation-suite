"""durable-execution-name-conflict-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-execution-name-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]

HANDLER_SRC = textwrap.dedent(
    """
    from aws_durable_execution_sdk_python import DurableContext, durable_execution

    @durable_execution
    def lambda_handler(event, context: DurableContext):
        return {"value": event.get("value")}
    """
).strip()


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-invoking a durable function under a DurableExecutionName in use with a different payload is
    DurableExecutionAlreadyStartedException "Execution already started: <arn>", while the same name and
    payload returns the existing execution and only one execution carries that name."""
    lam = ctx.client("lambda")

    try:
        fn_name = _create_durable_function(ctx, HANDLER_SRC, execution_timeout=600)
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"durable functions unavailable in this account/region/SDK: {e}")

    execution_name = ctx.unique_name("sim2real-durexec-conflict-")
    first_payload = json.dumps({"value": "first"}).encode()

    try:
        resp1 = lam.invoke(
            FunctionName=fn_name,
            Qualifier="$LATEST",
            Payload=first_payload,
            DurableExecutionName=execution_name,
        )
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"could not invoke durable function: {e}")

    arn1 = resp1.get("DurableExecutionArn")
    if not arn1:
        raise AssertionError("Invoke did not return a DurableExecutionArn; durable functions unsupported here")

    different_payload = json.dumps({"value": "second-different"}).encode()
    code, msg = _client_error(
        lambda: lam.invoke(
            FunctionName=fn_name,
            Qualifier="$LATEST",
            Payload=different_payload,
            DurableExecutionName=execution_name,
        )
    )
    assert code == "DurableExecutionAlreadyStartedException", (
        f"expected DurableExecutionAlreadyStartedException reusing a name with a different "
        f"payload, got {code}"
    )
    assert msg == f"Execution already started: {arn1}", f"name-reuse refusal message: {msg!r}"

    # Same name + same payload must be idempotent: returns the existing execution, not a
    # rejection and not a brand new execution.
    resp_same = lam.invoke(
        FunctionName=fn_name,
        Qualifier="$LATEST",
        Payload=first_payload,
        DurableExecutionName=execution_name,
    )
    assert resp_same.get("DurableExecutionArn") == arn1, (
        f"expected the idempotent re-invoke to return the existing execution {arn1}, "
        f"got {resp_same.get('DurableExecutionArn')}"
    )

    # Independent read at the destination (ListDurableExecutionsByFunction, not Invoke):
    # exactly one execution must be recorded under this name, proving neither the
    # rejected conflicting invoke nor the idempotent replay minted a second execution.
    executions = lam.list_durable_executions_by_function(FunctionName=fn_name)["DurableExecutions"]
    matches = [e for e in executions if e["DurableExecutionName"] == execution_name]
    assert len(matches) == 1, (
        f"expected exactly 1 execution recorded for name {execution_name!r}, "
        f"got {len(matches)}: {matches}"
    )
    assert matches[0]["DurableExecutionArn"] == arn1, (
        f"expected the independently-read execution to be the original {arn1}, "
        f"got {matches[0]['DurableExecutionArn']}"
    )


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    ctx, handler_src: str, execution_timeout: int = 3600, retention_days: int = 1
) -> str:
    from botocore.exceptions import ClientError

    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-durable-")
    role_arn = _create_durable_role(ctx, fn_name)
    zip_bytes = _make_zip(handler_src)
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
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
            )
            break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "InvalidParameterValueException" and "role" in str(e).lower():
                # IAM role trust/propagation lag: retry until the role is assumable.
                last_err = e
                time.sleep(3)
                continue
            raise AssertionError(f"durable functions are not available in this environment: {e}") from e
    else:
        raise AssertionError(f"IAM role never propagated for create_function: {last_err}")
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
