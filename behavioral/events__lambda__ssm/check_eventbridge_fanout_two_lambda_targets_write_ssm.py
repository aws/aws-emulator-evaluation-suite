"""eventbridge-fanout-two-lambda-targets-write-ssm."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-fanout-two-lambda-targets-write-ssm"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "ssm"]


def _ssm_param_arn(ctx, name: str) -> str:
    """Build an SSM parameter ARN for a flat or hierarchical parameter name.

    SSM parameter ARNs always use exactly one ``parameter/`` separator, so a
    flat name ``p`` becomes ``...:parameter/p`` and a hierarchical name
    ``/a/b`` becomes ``...:parameter/a/b``.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ssm:{ctx.region}:{account}:parameter/{name.lstrip('/')}"


def _allow_eventbridge_invoke(ctx, fn: dict, rule_name: str) -> str:
    """Let a rule invoke a function, and wait until the grant is actually live.

    EventBridge does *not* retry a delivery that fails for permission reasons —
    such events are dropped immediately (see the target-DLQ docs) — so
    publishing before the Lambda resource policy has propagated silently loses
    the event. Poll until Lambda reports the statement, then allow a short
    settling window before the event is published.

    The SourceArn is built from the account in the function's own ARN, the way
    a real integration must resolve it.
    """
    lam = ctx.client("lambda")
    account = fn["arn"].split(":")[4]
    sid = ctx.unique_name("sid-")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=f"arn:aws:events:{ctx.region}:{account}:rule/{rule_name}",
    )

    def statement_visible() -> bool:
        try:
            return sid in lam.get_policy(FunctionName=fn["name"])["Policy"]
        except Exception:
            return False

    _poll_until(
        statement_visible,
        lambda visible: visible,
        timeout_s=30,
        interval_s=2.0,
        description=f"resource policy statement {sid} visible",
    )
    return sid


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """One EventBridge rule with two Lambda targets: both must be invoked (fan-out)."""
    events = ctx.client("events")
    ssm = ctx.client("ssm")
    param_a = ctx.unique_name("param-fanout-a-")
    param_b = ctx.unique_name("param-fanout-b-")

    def make_writer(param_name: str) -> str:
        return f'''
import boto3
ssm = boto3.client("ssm")

def lambda_handler(event, context):
    ssm.put_parameter(Name="{param_name}", Value="written", Type="String", Overwrite=True)
    return {{"ok": True}}
'''

    fn_a = _create_lambda(
        ctx,
        make_writer(param_a),
        permissions=[
            {"Action": ["ssm:PutParameter"], "Resource": _ssm_param_arn(ctx, param_a)}
        ],
    )
    fn_b = _create_lambda(
        ctx,
        make_writer(param_b),
        permissions=[
            {"Action": ["ssm:PutParameter"], "Resource": _ssm_param_arn(ctx, param_b)}
        ],
    )
    ctx.on_cleanup(lambda: ctx.client("ssm").delete_parameter(Name=param_a))
    ctx.on_cleanup(lambda: ctx.client("ssm").delete_parameter(Name=param_b))

    rule_name = ctx.unique_name("rule-fanout-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["integration.fanout"],
                "detail-type": ["Fanout"],
            }
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    for fn in (fn_a, fn_b):
        _allow_eventbridge_invoke(ctx, fn, rule_name)
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "ta", "Arn": fn_a["arn"]}, {"Id": "tb", "Arn": fn_b["arn"]}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["ta", "tb"])
    )

    fanout_event = {
        "Source": "integration.fanout",
        "DetailType": "Fanout",
        "Detail": json.dumps({}),
    }

    def probe():
        # Re-publish on each poll: a fan-out event sent before both targets are
        # live is dropped, and BOTH targets must be live for the assertion to
        # hold. Re-emitting until both parameters are written is far more
        # reliable than betting on a single PutEvents.
        events.put_events(Entries=[fanout_event])
        try:
            a = ssm.get_parameter(Name=param_a)["Parameter"]["Value"]
        except Exception:
            a = None
        try:
            b = ssm.get_parameter(Name=param_b)["Parameter"]["Value"]
        except Exception:
            b = None
        return (a, b)

    a, b = _wait_for_effect(
        probe,
        lambda ab: ab[0] == "written" and ab[1] == "written",
        timeout_s=180,
        interval_s=5.0,
    )
    assert a == "written", "First fan-out target was not invoked"
    assert b == "written", "Second fan-out target was not invoked"


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
            # function deletion, so it would be left behind. Delete it
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
