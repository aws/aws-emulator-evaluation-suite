"""lambda-without-ssm-permission-denied."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-without-ssm-permission-denied"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "ssm"]


def _ssm_param_arn(ctx, name: str) -> str:
    """Build an SSM parameter ARN for a flat or hierarchical parameter name.

    SSM parameter ARNs always use exactly one ``parameter/`` separator, so a
    flat name ``p`` becomes ``...:parameter/p`` and a hierarchical name
    ``/a/b`` becomes ``...:parameter/a/b``.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ssm:{ctx.region}:{account}:parameter/{name.lstrip('/')}"


def _payload(result: dict) -> dict:
    """Return an invocation's parsed payload, failing loudly on a Lambda error.

    ``invoke_lambda`` reports a handler crash via ``result["error"]`` while
    still returning a payload (the runtime's error envelope). Surfacing that
    here turns an opaque ``KeyError`` in a downstream assertion into the actual
    Lambda error message.
    """
    assert not result.get("error"), (
        f"Lambda invocation failed with {result['error']}: "
        f"{result.get('payload') or result.get('payload_raw')}"
    )
    payload = result.get("payload")
    assert isinstance(payload, dict), f"handler did not return a JSON object: {result}"
    return payload


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda role lacking ssm:GetParameter must receive AccessDenied, not silent success."""
    param_name = ctx.unique_name("param-denied-")
    param_value = "secret-value"
    ssm = ctx.client("ssm")
    ssm.put_parameter(Name=param_name, Value=param_value, Type="String")
    ctx.on_cleanup(lambda: ctx.client("ssm").delete_parameter(Name=param_name))

    code = f'''
import boto3
from botocore.exceptions import ClientError
ssm = boto3.client("ssm")

def lambda_handler(event, context):
    try:
        resp = ssm.get_parameter(Name="{param_name}")
        return {{"ok": True, "denied": False, "value": resp["Parameter"]["Value"]}}
    except ClientError as e:
        return {{"ok": False, "denied": True, "code": e.response["Error"]["Code"],
                 "message": e.response["Error"]["Message"]}}
'''
    # Positive control: same read, same parameter, a role that IS allowed to make it — proves
    # the parameter and the call are otherwise healthy, so the negative below cannot pass merely
    # because everything in this account is broken.
    allowed_fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {"Action": ["ssm:GetParameter"], "Resource": _ssm_param_arn(ctx, param_name)}
        ],
    )
    allowed_payload = _payload(_invoke_lambda(ctx, allowed_fn["name"], {}))
    assert allowed_payload["ok"] is True, (
        f"positive control: granted ssm:GetParameter should succeed, got {allowed_payload}"
    )
    assert allowed_payload["value"] == param_value, (
        f"positive control returned the wrong value: {allowed_payload}"
    )

    fn = _create_lambda(ctx, code, permissions=[])  # no SSM permissions at all

    result = _invoke_lambda(ctx, fn["name"], {})
    payload = _payload(result)
    assert payload["denied"] is True, f"expected AccessDenied, got {payload}"
    assert payload["ok"] is False, f"expected ok=False for a denied call, got {payload}"
    assert payload["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {payload}"
    )
    role_name = ctx.client("lambda").get_function_configuration(FunctionName=fn["name"])["Role"].rsplit("/", 1)[1]
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{fn['name']} is not authorized to "
        f"perform: ssm:GetParameter on resource: {_ssm_param_arn(ctx, param_name)} because no "
        "identity-based policy allows the ssm:GetParameter action"
    )
    assert payload["message"] == expected_message, (
        f"AccessDeniedException message {payload['message']!r} != {expected_message!r}"
    )
    assert "value" not in payload, f"denied call must not leak the parameter value: {payload}"


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
    # IAM role trust/permission propagation before a service assumes it is bounded by
    # _create_function_with_retry's own retry-with-deadline on "cannot be assumed" below,
    # so no blind sleep is needed here.
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
            # function deletion, so it is deleted here. A
            # function that is never invoked never creates it, so its absence is not a failure.
            ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
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


def _delete_function_log_group(ctx, name: str) -> None:
    """Delete /aws/lambda/<name>; a function that never ran has none to delete."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except logs.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
