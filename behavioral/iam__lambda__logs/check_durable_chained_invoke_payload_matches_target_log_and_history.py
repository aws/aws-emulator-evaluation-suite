"""durable-chained-invoke-payload-matches-target-log-and-history."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "durable-chained-invoke-payload-matches-target-log-and-history"
GROUP = "chained-invoke"
SERVICES = ["iam", "lambda", "logs"]

_TARGET_CODE = '''
import json


def lambda_handler(event, context):
    print("CHAIN_TARGET_RECEIVED " + json.dumps(event, sort_keys=True))
    return {"received": event}
'''

_CALLER_CODE = '''
from aws_durable_execution_sdk_python import DurableContext, durable_execution


@durable_execution
def lambda_handler(event, context: DurableContext):
    return context.invoke(event["target_arn"], event["payload"], name="forward-to-target")
'''


def _zip_module(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _teardown(undo, *not_found_codes: str):
    """A cleanup running ``undo()`` where a failed delete raises; only the resource's own
    not-found codes mean it is already gone."""

    def _run() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found_codes:
                return
            raise

    return _run


def _reap_log_group(logs_client, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs_client.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs_client.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _wait_until(probe, done, *, timeout_s: float, interval_s: float, tolerate_missing: bool = False):
    deadline = time.monotonic() + timeout_s
    observed = None
    while time.monotonic() < deadline:
        try:
            observed = probe()
        except ClientError as exc:
            if tolerate_missing and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(interval_s)
                continue
            raise
        if done(observed):
            return observed
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for condition; last observed {observed!r}")


def _make_execution_role(ctx, iam, *, managed_policy_arn: str, invoke_targets: list) -> str:
    """A fresh role trusting lambda.amazonaws.com, carrying exactly the policies a run needs."""
    role_name = ctx.unique_name("sim2real-chain-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = created["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn), "NoSuchEntity"))

    if invoke_targets:
        policy_name = ctx.unique_name("sim2real-chain-invoke-policy-")
        resources: list[str] = []
        for arn in invoke_targets:
            resources.append(arn)
            resources.append(f"{arn}:*")
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": resources}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))

    return role_arn


def _deploy_function(
    ctx, lam, logs_client, *, name: str, role_arn: str, source: str,
    durable_config: dict | None = None, func_timeout: int = 30, memory_mb: int = 128,
    role_wait_s: float = 90.0,
) -> str:
    code = _zip_module(source)
    ctx.on_cleanup(lambda: _reap_log_group(logs_client, f"/aws/lambda/{name}"))
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.13",
        Role=role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": code},
        Timeout=func_timeout,
        MemorySize=memory_mb,
    )
    if durable_config is not None:
        kwargs["DurableConfig"] = durable_config

    deadline = time.monotonic() + role_wait_s
    response = None
    while True:
        try:
            response = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            # A role IAM just created is not always visible to Lambda yet.
            err_code = exc.response["Error"]["Code"]
            if err_code == "InvalidParameterValueException" and "role" in str(exc).lower() and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    cfg = _wait_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=90.0, interval_s=2.0,
    )
    assert cfg["State"] == "Active", f"function {name!r} failed to activate: {cfg.get('StateReason')!r}"
    return response["FunctionArn"]


def _start_execution(lam, function_name: str, execution_name: str, event: dict) -> str:
    response = lam.invoke(
        FunctionName=function_name,
        Qualifier="$LATEST",
        InvocationType="Event",
        Payload=json.dumps(event).encode("utf-8"),
        DurableExecutionName=execution_name,
    )
    arn = response.get("DurableExecutionArn")
    if arn:
        return arn
    for execution in lam.list_durable_executions_by_function(FunctionName=function_name)["DurableExecutions"]:
        if execution["DurableExecutionName"] == execution_name:
            return execution["DurableExecutionArn"]
    raise AssertionError(f"invoke of {function_name!r} returned no DurableExecutionArn and none was listed")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A durable context.invoke() delivers the exact payload to the target: the target's own
    log shows one invocation carrying it, matching GetDurableExecutionHistory's record of the call.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs_client = ctx.client("logs")
    if not hasattr(lam, "get_durable_execution_history"):
        raise AssertionError("installed botocore/client does not expose the Lambda durable-execution APIs")

    target_name = ctx.unique_name("sim2real-chain-target-")
    target_role = _make_execution_role(
        ctx, iam,
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        invoke_targets=[],
    )
    target_arn = _deploy_function(ctx, lam, logs_client, name=target_name, role_arn=target_role, source=_TARGET_CODE)

    caller_name = ctx.unique_name("sim2real-chain-caller-")
    caller_role = _make_execution_role(
        ctx, iam,
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicDurableExecutionRolePolicy",
        invoke_targets=[target_arn],
    )
    caller_arn = _deploy_function(
        ctx, lam, logs_client, name=caller_name, role_arn=caller_role, source=_CALLER_CODE,
        durable_config={"ExecutionTimeout": 300, "RetentionPeriodInDays": 1},
    )
    assert caller_arn

    payload = {
        "greeting": "hello-from-durable-chain",
        "marker": ctx.unique_name("sim2real-chain-marker-"),
        "numbers": [1, 2, 3],
    }
    event = {"target_arn": target_arn, "payload": payload}

    # IAM propagation for the chain-invoke permission exposes no condition to poll, so retry the
    # first chained call on AccessDenied.
    propagation_deadline = time.monotonic() + 120.0
    final = None
    execution_arn = None
    attempt = 0
    while True:
        attempt += 1
        execution_arn = _start_execution(lam, caller_name, ctx.unique_name(f"chain-try{attempt}-"), event)
        final = _wait_until(
            lambda: lam.get_durable_execution(DurableExecutionArn=execution_arn),
            lambda e: e["Status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "STOPPED"),
            timeout_s=90.0, interval_s=3.0, tolerate_missing=True,
        )
        if final["Status"] == "SUCCEEDED":
            break
        error_text = json.dumps(final.get("Error", {}))
        if "AccessDenied" in error_text and time.monotonic() < propagation_deadline:
            time.sleep(5.0)
            continue
        raise AssertionError(f"durable execution ended {final['Status']!r} unexpectedly: {final.get('Error')!r}")

    expected_result = {"received": payload}
    actual_result = json.loads(final["Result"])
    assert actual_result == expected_result, (
        f"GetDurableExecution Result was {actual_result!r}, expected {expected_result!r}"
    )

    history = lam.get_durable_execution_history(
        DurableExecutionArn=execution_arn, IncludeExecutionData=True
    )["Events"]
    started = [e for e in history if e.get("EventType") == "ChainedInvokeStarted"]
    succeeded = [e for e in history if e.get("EventType") == "ChainedInvokeSucceeded"]
    assert len(started) == 1, f"expected exactly one ChainedInvokeStarted event, found {len(started)}"
    assert len(succeeded) == 1, f"expected exactly one ChainedInvokeSucceeded event, found {len(succeeded)}"
    assert started[0]["Id"] == succeeded[0]["Id"], (
        f"ChainedInvokeStarted Id {started[0]['Id']!r} and ChainedInvokeSucceeded Id "
        f"{succeeded[0]['Id']!r} do not name the same chained call"
    )

    sent_payload = json.loads(started[0]["ChainedInvokeStartedDetails"]["Input"]["Payload"])
    assert sent_payload == payload, f"history recorded the chained call's input as {sent_payload!r}, sent {payload!r}"

    chained_result = json.loads(succeeded[0]["ChainedInvokeSucceededDetails"]["Result"]["Payload"])
    assert chained_result == expected_result, (
        f"history recorded the chained call's result as {chained_result!r}, expected {expected_result!r}"
    )

    log_group = f"/aws/lambda/{target_name}"
    marker = "CHAIN_TARGET_RECEIVED "

    def _marker_lines():
        events = logs_client.filter_log_events(logGroupName=log_group, filterPattern='"CHAIN_TARGET_RECEIVED"')["events"]
        return [e["message"] for e in events if marker in e["message"]]

    lines = _wait_until(
        _marker_lines, lambda ls: len(ls) >= 1, timeout_s=60.0, interval_s=3.0, tolerate_missing=True
    )
    assert len(lines) == 1, (
        f"target's log carried {len(lines)} invocation(s) of the payload, expected exactly one: {lines!r}"
    )
    logged_event = json.loads(lines[0].split(marker, 1)[1])
    assert logged_event == payload, f"target's log recorded {logged_event!r}, expected the sent payload {payload!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
