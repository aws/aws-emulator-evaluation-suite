"""eventbridge-lambda-missing-resource-policy."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-lambda-missing-resource-policy"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule without a lambda:InvokeFunction grant for events.amazonaws.com never invokes the
    function, while a granted twin rule on the same function, fired at the same time, does."""
    table = _create_table(ctx)
    code = f'''
import boto3
ddb = boto3.client("dynamodb")
TABLE = "{table["name"]}"
def lambda_handler(event, context):
    marker = event["detail"]["marker"]
    ddb.put_item(TableName=TABLE, Item={{"pk": {{"S": marker}}}})
    return {{"ok": True}}
'''
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
    )
    events = ctx.client("events")
    lam = ctx.client("lambda")

    rule_ctrl = ctx.unique_name("rule-ctrl-")
    events.put_rule(
        Name=rule_ctrl,
        EventPattern=json.dumps(
            {"source": ["test.withperm"], "detail-type": ["ShouldInvoke"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_ctrl))
    events.put_targets(Rule=rule_ctrl, Targets=[{"Id": "tc", "Arn": fn["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_ctrl, Ids=["tc"])
    )
    rule_ctrl_arn = events.describe_rule(Name=rule_ctrl)["Arn"]
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="eb-invoke-ctrl",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_ctrl_arn,
    )

    rule_noperm = ctx.unique_name("rule-noperm-")
    events.put_rule(
        Name=rule_noperm,
        EventPattern=json.dumps(
            {"source": ["test.noperm"], "detail-type": ["ShouldNotInvoke"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_noperm))
    events.put_targets(Rule=rule_noperm, Targets=[{"Id": "tn", "Arn": fn["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_noperm, Ids=["tn"])
    )
    rule_noperm_arn = events.describe_rule(Name=rule_noperm)["Arn"]
    # Intentionally NOT calling lambda.add_permission for rule_noperm's ARN — this is the
    # resource-policy boundary being probed (distinct from the execution-role IAM boundary).
    # Same function as the control leg, so the boundary under test is genuinely the per-statement
    # SourceArn condition on the function's resource policy, not some other difference between targets.

    ddb = ctx.client("dynamodb")

    def read_marker(marker):
        return ddb.get_item(TableName=table["name"], Key={"pk": {"S": marker}}).get(
            "Item"
        )

    def _fire_both():
        # Rule/target creation on the default bus is eventually consistent: an event published
        # immediately after PutTargets can be silently dropped. Republishing while polling for the
        # positive control makes the positive path deterministic.
        events.put_events(
            Entries=[
                {
                    "Source": "test.withperm",
                    "DetailType": "ShouldInvoke",
                    "Detail": json.dumps({"marker": "should-run"}),
                },
                {
                    "Source": "test.noperm",
                    "DetailType": "ShouldNotInvoke",
                    "Detail": json.dumps({"marker": "should-not-run"}),
                },
            ]
        )
        return read_marker("should-run")

    start = time.monotonic()
    _poll_until(
        _fire_both,
        lambda r: r is not None,
        timeout_s=90,
        interval_s=6.0,
        description="positive control invoked via its granted resource policy",
    )
    positive_latency_s = time.monotonic() - start

    # Calibrated absence window: hold for >=3x the positive control's measured latency on the
    # same wiring, re-reading (never sleeping blind) so a slower-but-correct target cannot be
    # mistaken for a blocked one, and any late invocation is caught the instant it lands.
    hold_s = max(3.0 * positive_latency_s, 15.0)
    deadline = time.monotonic() + hold_s
    samples = 0
    while time.monotonic() < deadline:
        item = read_marker("should-not-run")
        assert item is None, (
            f"rule invoked Lambda despite missing resource-based invoke permission "
            f"(observed within a {hold_s:.1f}s window calibrated to "
            f"{positive_latency_s:.1f}s positive-control latency)"
        )
        samples += 1
        time.sleep(2.0)
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"

    # Second independent observable, at the actual mechanism rather than only its side effect:
    # the function's resource policy must carry no statement admitting the no-perm rule's ARN.
    policy = json.loads(lam.get_policy(FunctionName=fn["name"])["Policy"])
    granted_source_arns = {
        stmt.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
        for stmt in policy.get("Statement", [])
    }
    assert rule_noperm_arn not in granted_source_arns, (
        f"function resource policy unexpectedly grants invoke access to {rule_noperm_arn}"
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
    # IAM role trust/permission propagation is bounded downstream, in
    # _create_function_with_retry's retry-on-"cannot be assumed" loop, rather than by a blind
    # sleep here.
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
    deadline = time.monotonic() + 30
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


def _create_table(
    ctx,
    key_schema=None,
    attributes=None,
    stream=False,
    stream_view_type="NEW_AND_OLD_IMAGES",
) -> dict[str, str]:
    """Create a DynamoDB table (PAY_PER_REQUEST; waits table_exists; registers delete_table).
    Returns {name,arn[,stream_arn]}."""
    name = _xname(ctx, "tbl")
    ddb = ctx.client("dynamodb")
    params: dict[str, Any] = {
        "TableName": name,
        "KeySchema": key_schema or [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": attributes
        or [{"AttributeName": "pk", "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
        "Tags": _xsvc_tags_kv(),
    }
    if stream:
        params["StreamSpecification"] = {
            "StreamEnabled": True,
            "StreamViewType": stream_view_type,
        }
    resp = ddb.create_table(**params)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(
        TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
    )
    result = {"name": name, "arn": resp["TableDescription"]["TableArn"]}
    if stream:
        result["stream_arn"] = resp["TableDescription"].get("LatestStreamArn", "")
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
