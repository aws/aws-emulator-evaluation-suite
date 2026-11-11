"""lambda-sdk-denied-without-role-permissions."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-denied-without-role-permissions"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]

_PASS_DEFINITION = {
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


def _assert_stays_empty(ctx, probe, settle_s, what):
    """Assert *probe* never returns a truthy value within the settle window."""
    observed = None
    try:
        observed = _poll_until(
            probe, lambda r: bool(r), timeout_s=settle_s, interval_s=5
        )
    except Exception:
        observed = None
    assert not observed, f"{what}: expected no effect, observed {observed!r}"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role granting nothing is denied events:PutEvents and states:StartExecution with
    AccessDeniedException and the exact messages and starts no execution, while a twin role
    granting exactly those two actions succeeds at both."""
    handler_code = """
import boto3, os

def lambda_handler(event, context):
    out = {}
    try:
        boto3.client("events").put_events(Entries=[{
            "Source": "sim2real.denied", "DetailType": "X", "Detail": "{}"
        }])
        out["events"] = "ALLOWED"
    except Exception as e:
        out["events"] = "DENIED:" + type(e).__name__ + ":" + str(e)
    try:
        boto3.client("stepfunctions").start_execution(
            stateMachineArn=os.environ["SM_ARN"]
        )
        out["states"] = "ALLOWED"
    except Exception as e:
        out["states"] = "DENIED:" + type(e).__name__ + ":" + str(e)
    return out
"""
    account = ctx.client("sts").get_caller_identity()["Account"]
    bus_arn = f"arn:aws:events:{ctx.region}:{account}:event-bus/default"

    # --- Positive control (twin, same moment): a role granting EXACTLY these two actions must
    #     succeed at both, on the same handler code and the same call shapes as the negative below.
    allowed_sfn_role = _create_role_stmts(ctx, "states.amazonaws.com", [], "sfn-role-allowed")
    allowed_sm_arn = _create_state_machine_role(
        ctx, _PASS_DEFINITION, allowed_sfn_role, "sm-allowed"
    )
    allowed_fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        env={"SM_ARN": allowed_sm_arn},
        permissions=[
            {"Action": "events:PutEvents", "Resource": bus_arn},
            {"Action": "states:StartExecution", "Resource": allowed_sm_arn},
        ],
    )
    allowed_payload = _invoke_lambda(ctx, allowed_fn["name"], {})["payload"]
    assert allowed_payload["events"] == "ALLOWED", (
        f"positive control: events:PutEvents was denied even though the role grants it: "
        f"{allowed_payload}"
    )
    assert allowed_payload["states"] == "ALLOWED", (
        f"positive control: states:StartExecution was denied even though the role grants it: "
        f"{allowed_payload}"
    )

    # --- Break: the SAME handler code under a role granting nothing must be denied both.
    sfn_role = _create_role_stmts(ctx, "states.amazonaws.com", [], "sfn-role-target")
    sm_arn = _create_state_machine_role(ctx, _PASS_DEFINITION, sfn_role, "sm-target")
    fn = _create_lambda(ctx, handler_code=handler_code, env={"SM_ARN": sm_arn})

    payload = _invoke_lambda(ctx, fn["name"], {})["payload"]

    assert payload["events"].startswith("DENIED"), (
        f"events:PutEvents succeeded without permission -- overly permissive: {payload}"
    )
    principal = f"arn:aws:sts::{account}:assumed-role/{fn['role_name']}/{fn['name']}"
    events_error = payload["events"].split(":", 2)[2]
    assert events_error == (
        "An error occurred (AccessDeniedException) when calling the PutEvents operation: "
        f"User: {principal} is not authorized to perform: events:PutEvents on resource: {bus_arn} "
        "because no identity-based policy allows the events:PutEvents action"
    ), payload
    assert payload["states"].startswith("DENIED"), (
        f"states:StartExecution succeeded without permission -- overly permissive: {payload}"
    )
    states_error = payload["states"].split(":", 2)[2]
    assert states_error == (
        "An error occurred (AccessDeniedException) when calling the StartExecution operation: "
        f"User: {principal} is not authorized to perform: states:StartExecution on resource: "
        f"{sm_arn} because no identity-based policy allows the states:StartExecution action"
    ), payload

    sfn = ctx.client("stepfunctions")
    _assert_stays_empty(
        ctx,
        lambda: sfn.list_executions(stateMachineArn=sm_arn)["executions"],
        20,
        "execution started despite a Lambda role with no states:StartExecution",
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _create_role_stmts(ctx, service_principal, statements, name_hint="role"):
    """Create a role trusting *service_principal* with an optional inline policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_hint)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: ctx.client("iam").delete_role_policy(
                RoleName=role_name, PolicyName="inline"
            )
        )
    # Service-principal trust propagation has no pollable signal of its own; the caller
    # (_create_state_machine_role) retries CreateStateMachine on ClientError for up to 90s, which
    # absorbs the propagation window instead of an unconditional sleep here.
    return role["Role"]["Arn"]


def _create_state_machine_role(ctx, definition, role_arn, name_hint="sm"):
    """Create a state machine, tolerating IAM propagation delay."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name(name_hint)

    def probe():
        try:
            return sfn.create_state_machine(
                name=sm_name, definition=json.dumps(definition), roleArn=role_arn
            )
        except ClientError:
            return None

    sm = _wait_for_effect(probe, lambda r: r is not None, timeout_s=90)
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(
            stateMachineArn=sm["stateMachineArn"]
        )
    )
    return sm["stateMachineArn"]


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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
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
    # IAM role trust/permission propagation before a service assumes it has no pollable signal of
    # its own; the caller (_create_function_with_retry) retries CreateFunction on the specific
    # "cannot be assumed" / InvalidParameterValue errors for up to 40s, which absorbs the
    # propagation window instead of an unconditional sleep here.
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


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
    deadline = time.monotonic() + 40
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on first invoke and the group outlives the
            # function, so delete it too; a function never invoked has no log group to delete.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
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
    Returns {name, arn, role_name}."""
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
