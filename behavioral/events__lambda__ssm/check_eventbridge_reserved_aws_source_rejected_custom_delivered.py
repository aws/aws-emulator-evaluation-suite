"""eventbridge-reserved-aws-source-rejected-custom-delivered."""

from __future__ import annotations

import json
import textwrap
import time
import uuid
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-reserved-aws-source-rejected-custom-delivered"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "ssm"]


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
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutEvents rejects an entry claiming the reserved aws.ssm source (FailedEntryCount 1 with
    an ErrorCode) and never delivers it, while the same event under a custom source reaches
    Lambda with its detail intact."""
    events = ctx.client("events")
    table = _create_table(ctx)
    spoofed_source = "aws.ssm"
    custom_source = "integration.ssm-automation"
    detail_type = "EC2 Automation Execution Status-change Notification"

    code = f'''
import boto3, json
ddb = boto3.client("dynamodb")

def lambda_handler(event, context):
    detail = event.get("detail", {{}})
    ddb.put_item(TableName="{table["name"]}", Item={{
        "pk": {{"S": "status-" + str(event.get("source", "unknown"))}},
        "status": {{"S": str(detail.get("Status", "unknown"))}}
    }})
    return {{"ok": True}}
'''
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
    )

    # One rule matches BOTH sources, so a spoofed event would be delivered if
    # EventBridge accepted it — the negative assertion below is meaningful.
    rule_name = ctx.unique_name("rule-automation-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": [spoofed_source, custom_source],
                "detail-type": [detail_type],
            }
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    _allow_eventbridge_invoke(ctx, fn, rule_name)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": fn["arn"]}])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    detail = json.dumps({"Status": "Success", "ExecutionId": str(uuid.uuid4())})

    # 1) Spoof attempt: claim to be the SSM service.
    spoofed = events.put_events(
        Entries=[
            {
                "Source": spoofed_source,
                "DetailType": detail_type,
                "Detail": detail,
            }
        ]
    )
    assert spoofed["FailedEntryCount"] == 1, (
        f"reserved source {spoofed_source!r} was accepted by PutEvents: {spoofed}"
    )
    spoof_error = (spoofed.get("Entries") or [{}])[0].get("ErrorCode")
    assert spoof_error, f"rejected entry carried no ErrorCode: {spoofed}"

    # 2) Same payload under a caller-owned source: must be delivered.
    accepted = events.put_events(
        Entries=[
            {
                "Source": custom_source,
                "DetailType": detail_type,
                "Detail": detail,
            }
        ]
    )
    assert accepted["FailedEntryCount"] == 0, (
        f"custom-source event was rejected: {accepted}"
    )

    ddb = ctx.client("dynamodb")
    delivered_key = {"pk": {"S": f"status-{custom_source}"}}
    spoofed_key = {"pk": {"S": f"status-{spoofed_source}"}}

    def probe():
        # Re-publish the (accepted) custom-source event on each poll: the first
        # one can be dropped before the freshly created rule/target is live.
        # Only the caller-owned source is re-sent, never the spoofed aws.ssm
        # one, so the spoof-was-never-delivered assertion below stays valid.
        events.put_events(
            Entries=[
                {
                    "Source": custom_source,
                    "DetailType": detail_type,
                    "Detail": detail,
                }
            ]
        )
        try:
            return ddb.get_item(TableName=table["name"], Key=delivered_key).get("Item")
        except Exception:
            return None

    item = _wait_for_effect(
        probe, lambda i: i is not None, timeout_s=180, interval_s=5.0
    )
    assert item is not None, "custom-source SSM-shaped event did not reach Lambda"
    assert item["status"]["S"] == "Success", f"detail was not preserved: {item}"

    # The spoofed entry never entered the bus, so it cannot have been delivered.
    spoof_item = ddb.get_item(TableName=table["name"], Key=spoofed_key).get("Item")
    assert spoof_item is None, "spoofed aws.ssm event was delivered to the target"


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
