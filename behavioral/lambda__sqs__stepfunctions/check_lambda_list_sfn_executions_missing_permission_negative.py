"""lambda-list-sfn-executions-missing-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-list-sfn-executions-missing-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without states:ListExecutions gets AccessDenied naming that action, while a
    twin with it lists the started execution; granting the action to the denied role makes its
    call list it too."""
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    sm_role_name = ctx.unique_name("sm-list-role-")
    trust = json.dumps(
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
    )
    sm_role = iam.create_role(RoleName=sm_role_name, AssumeRolePolicyDocument=trust)
    sm_role_arn = sm_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=sm_role_name))

    sm_name = ctx.unique_name("sm-list-")
    definition = json.dumps(
        {
            "StartAt": "PassState",
            "States": {"PassState": {"Type": "Pass", "End": True}},
        }
    )
    sm = sfn.create_state_machine(
        name=sm_name, definition=definition, roleArn=sm_role_arn
    )
    sm_arn = sm["stateMachineArn"]
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=sm_arn)
    )

    # Something for a successful ListExecutions to actually find.
    started = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("exec-")
    )
    started_arn = started["executionArn"]

    handler_code = """
import boto3, os, json
def lambda_handler(event, context):
    sfn = boto3.client('stepfunctions')
    try:
        resp = sfn.list_executions(stateMachineArn=os.environ['STATE_MACHINE_ARN'])
        return {'ok': True, 'error': None, 'count': len(resp.get('executions', []))}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
"""

    # ---- positive control: a twin role WITH states:ListExecutions must succeed ----
    positive_fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["states:ListExecutions"], "Resource": sm_arn},
        ],
        env={"STATE_MACHINE_ARN": sm_arn},
    )
    positive_payload = _invoke_lambda(ctx, positive_fn["name"], {})["payload"]
    assert positive_payload.get("ok") is True, (
        f"positive control (role HAS states:ListExecutions) unexpectedly failed: "
        f"{positive_payload}"
    )
    assert positive_payload.get("count", 0) >= 1, (
        f"positive control did not see the execution {started_arn} it should have listed: "
        f"{positive_payload}"
    )

    # ---- break exactly one thing: same call, a role with StartExecution but not ListExecutions ----
    tested = _create_lambda_with_role(
        ctx,
        handler_code=handler_code,
        permissions=[
            {"Action": ["states:StartExecution"], "Resource": sm_arn},
        ],
        env={"STATE_MACHINE_ARN": sm_arn},
    )
    payload = _invoke_lambda(ctx, tested["name"], {})["payload"]
    assert payload.get("ok") is False, (
        f"Expected failure for ListExecutions, got: {payload}"
    )
    error = payload.get("error") or ""
    assert "AccessDenied" in error, f"Expected AccessDenied, got: {error}"
    assert "states:ListExecutions" in error, (
        f"denied for the wrong action — expected states:ListExecutions named in the error: {error}"
    )
    assert "count" not in payload, (
        f"a denied ListExecutions must not disclose any execution data: {payload}"
    )

    # ---- restore: grant states:ListExecutions to the SAME role; the SAME call now succeeds ----
    iam.put_role_policy(
        RoleName=tested["role_name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["states:StartExecution", "states:ListExecutions"],
                        "Resource": sm_arn,
                    },
                ],
            }
        ),
    )

    def _probe():
        return _invoke_lambda(ctx, tested["name"], {})["payload"]

    restored_payload = _poll_until(
        _probe,
        lambda p: p.get("ok") is True,
        timeout_s=60.0,
        interval_s=3.0,
        description="ListExecutions succeeds on the same role after granting states:ListExecutions",
    )
    assert restored_payload.get("count", 0) >= 1, (
        f"restored call succeeded but lost track of the execution {started_arn}: "
        f"{restored_payload}"
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
    # No unconditional sleep for trust/permission propagation: _create_function_with_retry already
    # retries CreateFunction through that exact window ("cannot be assumed" / InvalidParameterValue).
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


def _create_lambda_with_role(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Same as _create_lambda, but also returns the execution role's name so a caller can mutate
    its policy afterwards (e.g. to prove a restored permission takes effect on the SAME role).
    Returns {name,arn,role_name}."""
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
    fn = _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )
    return {**fn, "role_name": role["name"]}


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
    result = _create_lambda_with_role(
        ctx, handler_code, permissions, env, timeout, memory, runtime
    )
    return {"name": result["name"], "arn": result["arn"]}


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
