"""sfn-invoke-lambda-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-invoke-lambda-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]


_HANDLER = """
import os


def lambda_handler(event, context):
    print("BACKEND-INVOKED " + os.environ["MARKER"])
    return event
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With lambda:InvokeFunction the Task state SUCCEEDS and the function runs; without it the same Task
    FAILS with Lambda.AWSLambdaException and the function never runs; with the permission restored the
    execution SUCCEEDS again.
    """
    marker = ctx.unique_name("backend-")
    fn = _create_lambda(ctx, handler_code=_HANDLER, env={"MARKER": marker})
    log_group = f"/aws/lambda/{fn['name']}"

    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    invoke_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": fn["arn"],
            }
        ],
    }
    role = _create_role(ctx, "states.amazonaws.com", inline_policy=invoke_policy)
    role_name, role_arn = role["name"], role["arn"]

    sm_name = ctx.unique_name("sm-noinvoke-")
    definition = json.dumps(
        {
            "StartAt": "InvokeLambda",
            "States": {
                "InvokeLambda": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": fn["arn"], "Payload.$": "$"},
                    "End": True,
                }
            },
        }
    )
    sm = _poll_until(
        lambda: _try_create_state_machine(sfn, sm_name, definition, role_arn),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="CreateStateMachine past IAM propagation of the fresh execution role",
    )
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    def run_execution():
        execution = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"value": 1})
        )
        exec_arn = execution["executionArn"]
        return _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda d: d["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=60,
            interval_s=3,
            description=f"execution {exec_arn} to reach a terminal state",
        )

    # --- Control: the role has the permission, so the Task state must succeed and the
    #     backend must observably run. Also measures the log-delivery latency that bounds
    #     the absence window below, so a slow but correct target is not mistaken for one
    #     that blocks delivery.
    #
    #     A freshly-created role needs its own propagation window before every service that
    #     touches it agrees it exists -- observed on real AWS as either SFN itself refusing
    #     to assume the role ("is not authorized to assume the provided role") or Lambda
    #     rejecting the assumed session (UnrecognizedClientException / "security token
    #     included in the request is invalid"), on different runs against the same code.
    #     That is a transient STS/IAM artifact of the role's age, not the target under test,
    #     so the control retries on ANY terminal state until SUCCEEDED or the deadline --
    #     same shape as the restore leg below. A target that never succeeds still fails
    #     loudly with its last real error once the deadline is reached.
    control_start_ms = int(time.time() * 1000) - 5_000
    control_t0 = time.monotonic()
    control = _poll_until(
        run_execution,
        lambda d: d["status"] == "SUCCEEDED",
        timeout_s=90.0,
        interval_s=5.0,
        description=(
            "the control execution past IAM/STS propagation for the freshly granted role"
        ),
    )
    assert control["status"] == "SUCCEEDED", (
        f"positive control: with lambda:InvokeFunction granted, expected SUCCEEDED, got "
        f"{control['status']} (error={control.get('error')}, cause={control.get('cause')})"
    )
    _poll_until(
        lambda: _log_events_containing(
            ctx, log_group, f"BACKEND-INVOKED {marker}", control_start_ms
        ),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description="the control invocation's BACKEND-INVOKED log line",
    )
    control_latency_s = time.monotonic() - control_t0

    # --- Break exactly one thing: revoke the permission. IAM policy-removal propagates on its
    #     own timeline, so denial is confirmed with a bounded retry (re-run the execution until
    #     it is observed FAILED) rather than a blind sleep before a single attempt.
    iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
    negative = _poll_until(
        run_execution,
        lambda d: d["status"] == "FAILED" and not _is_transient_token_propagation(d),
        timeout_s=120.0,
        interval_s=5.0,
        description="an execution to observe the revoked lambda:InvokeFunction as a denial",
    )
    assert negative.get("error") == "Lambda.AWSLambdaException", (
        f"Expected Lambda.AWSLambdaException, got error={negative.get('error')}, "
        f"cause={negative.get('cause')}"
    )
    # message varies: the cause ("User: <assumed-role arn>/<session> is not authorized to perform:
    # lambda:InvokeFunction ... (Service: Lambda, Status Code: 403, Request ID: <id>)") carries a
    # session name Step Functions chooses and a per-call Lambda Request ID.
    # Absence window starts now, once denial is confirmed in effect -- not at revoke time --
    # so a transient stale-permission SUCCEEDED during IAM's own convergence isn't mistaken
    # for the target failing to enforce the revoke.
    negative_start_ms = int(time.time() * 1000) - 2_000

    # --- Effect absent: the backend must never run, held for >= 3x the control's own
    #     measured delivery latency.
    _stays_absent(
        lambda: _log_events_containing(
            ctx, log_group, f"BACKEND-INVOKED {marker}", negative_start_ms
        ),
        lambda msgs: bool(msgs),
        window_s=max(3 * control_latency_s, 15.0),
        interval_s=5.0,
        description=(
            f"a BACKEND-INVOKED log line in {log_group} (the backend Lambda running "
            f"for an execution the missing IAM permission should have blocked)"
        ),
    )

    # --- Restore: the identical call now succeeds again, confirmed with the same
    #     bounded-retry shape for the grant's own propagation.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(invoke_policy)
    )
    _poll_until(
        run_execution,
        lambda d: d["status"] == "SUCCEEDED",
        timeout_s=120.0,
        interval_s=5.0,
        description="an execution to observe the restored lambda:InvokeFunction grant",
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _try_create_state_machine(sfn, name, definition, role_arn):
    """CreateStateMachine, or None while SFN cannot yet assume the just-created role."""
    try:
        return sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return None
        raise


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
            # function deletion, so delete it
            # too (best-effort — on_cleanup swallows if it was never created).
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(
                    logGroupName=f"/aws/lambda/{name}"
                )
            )
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


_TRANSIENT_TOKEN_MARKERS = (
    "unrecognizedclientexception",
    "security token included in the request is invalid",
    "invalidclienttokenid",
    "is not authorized to assume the provided role",
)


def _is_transient_token_propagation(desc: dict) -> bool:
    """True if `desc` (a describe_execution result) FAILED for STS/IAM role propagation
    lag on a just-created or just-changed role, not for the thing under test."""
    if desc.get("status") != "FAILED":
        return False
    combined = ((desc.get("error") or "") + (desc.get("cause") or "")).lower()
    return any(m in combined for m in _TRANSIENT_TOKEN_MARKERS)


def _stays_absent(
    probe, predicate, *, window_s=25.0, interval_s=2.5, description="effect"
):
    """Assert predicate(probe()) stays FALSY for a whole bounded window.

    The negative-delivery shape: an effect that must NEVER appear is observed over a
    settle window, not with one racy read that could pass simply by being early.
    """
    deadline = time.monotonic() + window_s
    while True:
        last = probe()
        assert not predicate(last), (
            f"{description} appeared but must NOT have (delivery was suppressed "
            f"upstream). Observed: {last!r}"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


def _log_events_containing(ctx, log_group, needle, start_ms=None):
    """Every message in log_group containing `needle`. A MISSING log group is 'no events',
    not an error — for a suppressed-delivery check the group legitimately never appears."""
    logs = ctx.client("logs")
    kwargs: dict[str, Any] = {"logGroupName": log_group, "limit": 100}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    out = []
    try:
        paginator = logs.get_paginator("filter_log_events")
        for page in paginator.paginate(**kwargs):
            for ev in page.get("events", []):
                if needle in ev.get("message", ""):
                    out.append(ev["message"])
            if len(out) >= 20:
                break
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
