"""eventbridge-lambda-rule-matching."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-lambda-rule-matching"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "sns", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge invokes the Lambda target only for events matching the rule pattern."""
    table = _create_table(ctx)
    code = f'''
import boto3
ddb = boto3.client("dynamodb")
TABLE = "{table["name"]}"
def lambda_handler(event, context):
    ddb.put_item(TableName=TABLE, Item={{"pk": {{"S": event["id"]}}}})
    return {{"ok": True}}
'''
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
    )
    events = ctx.client("events")
    lam = ctx.client("lambda")
    rule_name = ctx.unique_name("rule-lambda-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["test.app"], "detail-type": ["OrderPlaced"]}
        ),
    )
    region = fn["arn"].split(":")[3]
    account = fn["arn"].split(":")[4]
    rule_arn = f"arn:aws:events:{region}:{account}:rule/{rule_name}"
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="ebInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "t1",
                "Arn": fn["arn"],
                "InputTransformer": {
                    "InputPathsMap": {"id": "$.detail.id"},
                    "InputTemplate": '{"id": <id>}',
                },
            }
        ],
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    ddb = ctx.client("dynamodb")
    key_match = {"pk": {"S": "eb-lambda-1"}}
    key_nonmatch = {"pk": {"S": "eb-lambda-2"}}

    match_entry = {
        "Source": "test.app",
        "DetailType": "OrderPlaced",
        "Detail": json.dumps({"id": "eb-lambda-1"}),
    }
    nonmatch_entry = {
        "Source": "test.other",
        "DetailType": "Unrelated",
        "Detail": json.dumps({"id": "eb-lambda-2"}),
    }

    # A freshly-created rule/target pair is eventually consistent: events published
    # before the rule goes live are silently dropped (no retry, no DLQ). Re-publish
    # both entries on every poll so activation timing cannot flake the check.
    # Publishing them in the SAME round keeps the negative assertion rigorous — the
    # non-matching event always had an equal opportunity to be delivered.
    def probe():
        events.put_events(Entries=[match_entry, nonmatch_entry])
        return ddb.get_item(TableName=table["name"], Key=key_match).get("Item")

    probe_start = time.monotonic()
    item = _wait_for_effect(
        probe, lambda i: i is not None, timeout_s=90, interval_s=5.0
    )
    assert item is not None, (
        "matching EventBridge event never invoked the Lambda target"
    )
    positive_latency_s = time.monotonic() - probe_start

    # Absence must be bounded by a window calibrated to the delivery latency this same
    # wiring just demonstrated, never a fixed guess -- a target slower than a flat 10s
    # would silently deliver the non-matching event after the check already passed.
    # Hold for >=3x the observed positive latency (floored so a suspiciously-fast
    # positive doesn't collapse the window, capped so a slow eventually-consistent
    # positive can't blow the check's own timeout budget), polling rather than
    # sleeping once so a mid-window delivery fails immediately instead of at the end.
    absence_window_s = min(max(3.0 * positive_latency_s, 15.0), 120.0)
    deadline = time.monotonic() + absence_window_s
    while time.monotonic() < deadline:
        seen = ddb.get_item(TableName=table["name"], Key=key_nonmatch).get("Item")
        assert seen is None, (
            f"non-matching event invoked the Lambda target during the "
            f"{absence_window_s:.0f}s absence window (>=3x the {positive_latency_s:.1f}s "
            f"positive-control latency): {seen!r}"
        )
        time.sleep(2.0)

    # Second, independent observable: a Scan (a different DynamoDB operation than the
    # GetItem above) must also show zero rows for the non-matching key.
    scan_count = ddb.scan(
        TableName=table["name"],
        FilterExpression="pk = :k",
        ExpressionAttributeValues={":k": key_nonmatch["pk"]},
        Select="COUNT",
    )["Count"]
    assert scan_count == 0, (
        f"non-matching event visible via independent Scan: count={scan_count}"
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
            # The function auto-creates /aws/lambda/<name> on first invoke and that log group survives
            # function deletion, so delete it too.
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
