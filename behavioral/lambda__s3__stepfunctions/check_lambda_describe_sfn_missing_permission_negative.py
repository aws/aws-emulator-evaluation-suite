"""lambda-describe-sfn-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-describe-sfn-missing-permission-negative"

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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """states:DescribeExecution is enforced on the Lambda's own role: granted it succeeds
    (positive control), revoked it is denied with the specific AccessDeniedException code,
    and restoring the grant makes the identical call succeed again."""
    iam = ctx.client("iam")
    sfn_role_name = ctx.unique_name("sfn-nodesc-sm-role")
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
    sm_name = ctx.unique_name("sfn-nodesc-sm")
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

    iam.put_role_policy(
        RoleName=sfn_role_name,
        PolicyName=ctx.unique_name("sfn-nodesc-sm-policy"),
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["states:StartExecution"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    exec_resp = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"x": 1}))
    exec_arn = exec_resp["executionArn"]

    handler_code = """
import boto3, json, os
def lambda_handler(event, context):
    sfn = boto3.client('stepfunctions')
    try:
        resp = sfn.describe_execution(executionArn=os.environ['EXECUTION_ARN'])
        return {'status': resp['status']}
    except Exception as e:
        return {
            'error': type(e).__name__,
            'message': str(e),
            'code': getattr(e, 'response', {}).get('Error', {}).get('Code', '') if hasattr(e, 'response') else ''
        }
"""
    log_statement = {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:*",
    }
    granted_policy = {
        "Version": "2012-10-17",
        "Statement": [
            log_statement,
            {
                "Effect": "Allow",
                "Action": ["states:DescribeExecution", "states:ListExecutions"],
                "Resource": "*",
            },
        ],
    }
    revoked_policy = {
        "Version": "2012-10-17",
        "Statement": [
            log_statement,
            {"Effect": "Allow", "Action": ["states:ListExecutions"], "Resource": "*"},
        ],
    }

    lambda_role = _create_role(ctx, "lambda.amazonaws.com", inline_policy=granted_policy)
    fn = _create_function_with_retry(
        ctx, handler_code, lambda_role["arn"], env={"EXECUTION_ARN": exec_arn}
    )

    ok_statuses = ("RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")

    # Beat 1: positive control — with states:DescribeExecution granted, the call succeeds.
    positive = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"].get("status") in ok_statuses,
        timeout_s=45.0,
        interval_s=3.0,
        description="positive control: DescribeExecution with states:DescribeExecution granted",
    )
    assert positive["payload"].get("status") in ok_statuses, (
        f"Positive control failed with permission granted: {positive['payload']}"
    )

    # Beat 2: break exactly one thing — replace the inline policy, dropping only DescribeExecution.
    iam.put_role_policy(
        RoleName=lambda_role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(revoked_policy),
    )

    # Beat 3: the specific error code, bounded by the account's own IAM-propagation latency
    # rather than a blind sleep — an over-permissive target that never denies exhausts the
    # window and fails here.
    denied = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"].get("code") == "AccessDeniedException",
        timeout_s=45.0,
        interval_s=3.0,
        description="negative: DescribeExecution denied after revoking states:DescribeExecution",
    )
    assert denied["payload"].get("code") == "AccessDeniedException", (
        f"Expected AccessDeniedException after revoking states:DescribeExecution, got: {denied['payload']}"
    )

    # Beat 4: restore — put the DescribeExecution grant back.
    iam.put_role_policy(
        RoleName=lambda_role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(granted_policy),
    )

    # Beat 5: the identical call now succeeds again.
    restored = _poll_until(
        lambda: _invoke_lambda(ctx, fn["name"], {}),
        lambda r: r["payload"].get("status") in ok_statuses,
        timeout_s=45.0,
        interval_s=3.0,
        description="restore: DescribeExecution succeeds again after re-granting states:DescribeExecution",
    )
    assert restored["payload"].get("status") in ok_statuses, (
        f"Expected DescribeExecution to succeed again after restoring permission: {restored['payload']}"
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
    # IAM role/policy propagation is absorbed by the caller's bounded retry
    # (_create_function_with_retry's 30s window on "cannot be assumed"), not a blind sleep here.
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
