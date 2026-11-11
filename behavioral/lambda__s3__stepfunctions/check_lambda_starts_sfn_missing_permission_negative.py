"""lambda-starts-sfn-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-starts-sfn-missing-permission-negative"

GROUP = "overly-permissive"

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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda's StartExecution starts an execution while its role holds states:StartExecution, is
    denied with no new execution at Step Functions once revoked, and starts a new one again once
    restored."""
    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-noperm2-role")
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

    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sfn-noperm2-sm")
    sm_resp = sfn.create_state_machine(
        name=sm_name,
        definition=json.dumps(
            {
                "StartAt": "Pass",
                "States": {"Pass": {"Type": "Pass", "End": True}},
            }
        ),
        roleArn=sfn_role_arn,
        type="STANDARD",
    )
    sm_arn = sm_resp["stateMachineArn"]
    ctx.on_cleanup(lambda arn=sm_arn: _cleanup_state_machine(ctx, arn))

    handler_code = """
import boto3, json, os
def lambda_handler(event, context):
    sfn = boto3.client('stepfunctions')
    try:
        resp = sfn.start_execution(
            stateMachineArn=os.environ['STATE_MACHINE_ARN'],
            input=json.dumps(event)
        )
        return {'executionArn': resp['executionArn']}
    except Exception as e:
        return {
            'error': type(e).__name__,
            'message': str(e),
            'code': getattr(e, 'response', {}).get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
        }
"""
    logs_statement = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }
    granted_policy = {
        "Version": "2012-10-17",
        "Statement": [
            logs_statement,
            {"Effect": "Allow", "Action": ["states:StartExecution"], "Resource": sm_arn},
        ],
    }
    revoked_policy = {"Version": "2012-10-17", "Statement": [logs_statement]}

    lambda_role = _create_role(ctx, "lambda.amazonaws.com", inline_policy=granted_policy)
    fn = _create_function_with_retry(
        ctx, handler_code, lambda_role["arn"], {"STATE_MACHINE_ARN": sm_arn}
    )

    # Beat 1 — positive control: with the permission granted, the SDK call succeeds. Poll through
    # IAM's propagation window instead of trusting a flat sleep.
    control = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"test": True}),
        lambda r: "executionArn" in r.get("payload", {}),
        timeout_s=60.0,
        interval_s=3.0,
        description="positive control: Lambda starts the execution once granted",
    )
    control_exec_arn = control["payload"]["executionArn"]
    control_desc = sfn.describe_execution(executionArn=control_exec_arn)
    assert control_desc["status"] in ("RUNNING", "SUCCEEDED"), (
        f"Positive control execution in unexpected state: {control_desc['status']}"
    )
    execs_after_control = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    assert len(execs_after_control) == 1, (
        f"Expected exactly 1 execution after the positive control, got {len(execs_after_control)}"
    )

    # Beat 2 — break exactly one thing: revoke states:StartExecution.
    iam.put_role_policy(
        RoleName=lambda_role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(revoked_policy),
    )

    # Beats 3+4 — assert the specific error, and that it is *stable*, not a transient flap in
    # IAM's own eventual consistency (a single immediate re-check can still race a not-quite-
    # settled revoke back into a success). Require three consecutive denials, resetting the
    # streak on any intervening success, then use the reads bracketing that stable streak as the
    # independent absence proof at the destination (Step Functions), not the Lambda's self-report.
    consecutive_denials = 0
    execs_before_stable = None
    result = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and consecutive_denials < 3:
        if consecutive_denials == 0:
            execs_before_stable = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
        result = _invoke_lambda(ctx, fn["name"], {"test": True})
        if result["payload"].get("code") == "AccessDeniedException":
            consecutive_denials += 1
        else:
            consecutive_denials = 0
        if consecutive_denials < 3:
            time.sleep(3.0)
    assert consecutive_denials >= 3, (
        f"Denial of states:StartExecution never stabilized within 90s; last result: "
        f"{result['payload'] if result else None}"
    )
    execs_after_stable = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    assert len(execs_after_stable) == len(execs_before_stable), (
        f"A denied call must start no execution; count grew from {len(execs_before_stable)} to "
        f"{len(execs_after_stable)} across three consecutive denials"
    )

    # Beat 5 — restore.
    iam.put_role_policy(
        RoleName=lambda_role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(granted_policy),
    )

    # Beat 6 — the identical call now succeeds again, polling through the restore's propagation
    # window.
    restored = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {"test": True}),
        lambda r: "executionArn" in r.get("payload", {}),
        timeout_s=60.0,
        interval_s=3.0,
        description="Lambda starts the execution again once the permission is restored",
    )
    restored_exec_arn = restored["payload"]["executionArn"]
    assert restored_exec_arn != control_exec_arn, (
        "Restored call should start a new execution, not reuse the control's"
    )
    restored_desc = sfn.describe_execution(executionArn=restored_exec_arn)
    assert restored_desc["status"] in ("RUNNING", "SUCCEEDED"), (
        f"Restored execution in unexpected state: {restored_desc['status']}"
    )
    # Every denied poll attempt above started nothing (beat 4), so exactly one new execution
    # appears the moment the restored grant is observed — regardless of how many denied attempts
    # preceded it here or in beat 3.
    execs_after_restore = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    assert len(execs_after_restore) == len(execs_after_stable) + 1, (
        f"Expected exactly one new execution after restore, went from {len(execs_after_stable)} "
        f"to {len(execs_after_restore)}"
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
    # No flat sleep for propagation here: the caller's first invoke is polled (see
    # `_poll_until` call sites in `run`), which absorbs IAM's propagation window as a bounded
    # retry instead of a fixed wait.
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
    # Dedent the inline source and alias `handler` to `lambda_handler`, the fixed entrypoint;
    # without that symbol the function fails with Runtime.HandlerNotFound.
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


def _invoke_lambda(ctx, name: str, payload: dict | None = None) -> dict[str, Any]:
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result: dict[str, Any] = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
