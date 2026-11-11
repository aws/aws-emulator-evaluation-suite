"""sfn-task-lambda-passes-input-output."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-task-lambda-passes-input-output"

GROUP = "data-format"

SERVICES = ["lambda", "s3", "stepfunctions"]


def _cleanup_state_machine(ctx, arn: str) -> None:
    """Delete a state machine, then block until it is truly gone.

    StepFunctions DeleteStateMachine is asynchronous — the machine lingers in DELETING for up to
    ~a minute after the call returns. The account residual audit runs shortly after teardown, so a
    machine created by one of the last checks is still mid-deletion and gets misreported as a LEAK
    even though its delete was correctly issued. Wait out that window so teardown is deterministic.
    """
    sfn = ctx.client("stepfunctions")
    sfn.delete_state_machine(stateMachineArn=arn)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if (
                sfn.describe_state_machine(stateMachineArn=arn).get("status")
                != "DELETING"
            ):
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        time.sleep(5)


def _is_trust_lag(result: dict) -> bool:
    """True when an execution FAILED only because role trust had not propagated."""
    blob = result.get("cause", "") + result.get("error", "")
    return result.get("status") == "FAILED" and (
        "not authorized to assume" in blob or "AccessDenied" in blob
    )


def _bust_cached_trust(ctx, sm_arn):
    """Force Step Functions to re-resolve the state machine's role.

    A CreateStateMachine issued before the role's states.amazonaws.com trust has
    propagated leaves SFN holding a NEGATIVE trust resolution: executions keep
    failing with "not authorized to assume" even after IAM has settled, because
    the state machine still caches the stale result. Re-applying the same roleArn
    via UpdateStateMachine makes SFN re-resolve the (now-propagated) trust, so the
    next execution can succeed. Best-effort: a failure here just costs one retry.
    """
    sfn = ctx.client("stepfunctions")
    try:
        role_arn = sfn.describe_state_machine(stateMachineArn=sm_arn)["roleArn"]
        sfn.update_state_machine(stateMachineArn=sm_arn, roleArn=role_arn)
    except Exception:
        pass


def _run_execution_past_trust_lag(
    ctx, sm_arn, exec_input, *, attempts=8, backoff_s=15, timeout_s=120
):
    """Start a STANDARD execution, retrying past role-trust propagation lag.

    Returns the settled describe_execution result. A non-trust failure (e.g. an
    intentional Lambda error caught by a Catch state) is returned immediately so
    negative/catch assertions still see the real terminal state. Between trust-lag
    retries it re-resolves the SM role (see _bust_cached_trust) — a plain re-run is
    not enough when SFN has cached the pre-propagation negative validation.
    """
    sfn = ctx.client("stepfunctions")
    result = None
    for _ in range(attempts):
        ex = sfn.start_execution(stateMachineArn=sm_arn, input=exec_input)
        exec_arn = ex["executionArn"]
        result = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn),
            lambda r: r["status"] in ("SUCCEEDED", "FAILED"),
            timeout_s=timeout_s,
            interval_s=3,
        )
        if not _is_trust_lag(result):
            return result
        time.sleep(backoff_s)
        _bust_cached_trust(ctx, sm_arn)
    return result


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Step Functions correctly passes InputPath to Lambda and maps ResultPath back into execution state."""
    # The state machine doesn't exist yet, so its cleanup is registered against this holder
    # rather than at creation time. ctx.on_cleanup is LIFO, and _cleanup_state_machine can wait
    # up to 120s for DELETING to clear against a 60s total cleanup budget — registering it here,
    # first, makes it the LAST teardown to run instead of the first, so the cheap Lambda
    # function/role deletes below aren't starved if the state machine wait eats the budget.
    sm_arn_holder: dict[str, str] = {}
    ctx.on_cleanup(
        lambda: _cleanup_state_machine(ctx, sm_arn_holder["arn"])
        if "arn" in sm_arn_holder
        else None
    )

    handler_code = """
def lambda_handler(event, context):
    return {'echoed': event, 'extra': 'added_by_lambda'}
"""
    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
    )

    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-io-role")
    sfn_role_resp = iam.create_role(
        RoleName=sfn_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    sfn_role_arn = sfn_role_resp["Role"]["Arn"]
    # Use the harness's policy-aware role deletion: these roles get an inline
    # put_role_policy, and a plain iam.delete_role fails with DeleteConflict while
    # any policy is still attached, leaking the role. _delete_role detaches/deletes
    # policies first.
    ctx.on_cleanup(lambda name=sfn_role_name: _delete_role(ctx, name))
    _poll_until(
        lambda: iam.get_role(RoleName=sfn_role_name),
        lambda r: r.get("Role", {}).get("Arn") == sfn_role_arn,
        timeout_s=30,
        interval_s=3,
    )

    iam = ctx.client("iam")
    io_policy_name = ctx.unique_name("sfn-io-policy")
    iam.put_role_policy(
        RoleName=sfn_role_name,
        PolicyName=io_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["lambda:InvokeFunction"],
                        "Resource": fn["arn"],
                    }
                ],
            }
        ),
    )
    _poll_until(
        lambda: iam.get_role_policy(RoleName=sfn_role_name, PolicyName=io_policy_name),
        lambda r: "PolicyDocument" in r,
        timeout_s=30,
        interval_s=3,
    )

    definition = json.dumps(
        {
            "StartAt": "SetData",
            "States": {
                "SetData": {
                    "Type": "Pass",
                    "Result": {"name": "alice", "value": 99},
                    "ResultPath": "$.data",
                    "Next": "InvokeLambda",
                },
                "InvokeLambda": {
                    "Type": "Task",
                    "Resource": fn["arn"],
                    "InputPath": "$.data",
                    "ResultPath": "$.lambdaResult",
                    "End": True,
                },
            },
        }
    )

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-io-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=definition,
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    sm_arn_holder["arn"] = sm_arn

    result = _run_execution_past_trust_lag(ctx, sm_arn, "{}")

    assert result["status"] == "SUCCEEDED", (
        f"Execution not SUCCEEDED: {result['status']} cause={result.get('cause', '')}"
    )
    output = json.loads(result["output"])
    lr = output["lambdaResult"]
    assert lr["echoed"]["name"] == "alice", f"name mismatch: {lr}"
    assert lr["echoed"]["value"] == 99, f"value mismatch: {lr}"
    assert lr["extra"] == "added_by_lambda", f"extra mismatch: {lr}"
    assert "data" in output, "$.data not preserved in output"


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
    # no-ops for code that's already column-0 and defines lambda_handler. (Folds in the dedent+alias
    # that ~8 per-suite harness overrides used to do, so no suite needs its own create_lambda shim.)
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
            # function deletion and sweep_account doesn't scan log groups, so it would leak. Delete it
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
