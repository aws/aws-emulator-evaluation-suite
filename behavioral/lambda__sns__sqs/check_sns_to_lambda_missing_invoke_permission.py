"""sns-to-lambda-missing-invoke-permission."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-to-lambda-missing-invoke-permission"

GROUP = "overly-permissive"

SERVICES = ["lambda", "sns", "sqs"]


_STATEMENT_ID = "sns-invoke"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """One publish reaches the topic's function with a lambda:InvokeFunction grant but not its
    ungranted twin, which stays silent for several times the granted twin's latency; granting the
    twin's permission lets a new publish reach it."""
    topic = _create_topic(ctx)
    table_ok = _create_table(ctx)
    table_blocked = _create_table(ctx)

    def _handler_code(table_name):
        return f'''
import boto3, json
ddb = boto3.client("dynamodb")
def lambda_handler(event, context):
    for record in event["Records"]:
        msg = json.loads(record["Sns"]["Message"])
        ddb.put_item(TableName="{table_name}", Item={{"pk": {{"S": msg["id"]}}}})
    return {{"ok": True}}
'''

    fn_ok = _create_lambda(
        ctx,
        _handler_code(table_ok["name"]),
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table_ok["arn"]}],
    )
    fn_blocked = _create_lambda(
        ctx,
        _handler_code(table_blocked["name"]),
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table_blocked["arn"]}],
    )
    lam = ctx.client("lambda")
    sns = ctx.client("sns")
    ddb = ctx.client("dynamodb")

    lam.add_permission(
        FunctionName=fn_ok["name"],
        StatementId=_STATEMENT_ID,
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic["arn"],
    )
    # fn_blocked deliberately never gets add_permission until the restore leg below.

    for fn in (fn_ok, fn_blocked):
        sub = sns.subscribe(TopicArn=topic["arn"], Protocol="lambda", Endpoint=fn["arn"])
        ctx.on_cleanup(
            lambda arn=sub["SubscriptionArn"]: ctx.client("sns").unsubscribe(
                SubscriptionArn=arn
            )
        )

    def _item(table_name, msg_id):
        return ddb.get_item(TableName=table_name, Key={"pk": {"S": msg_id}}).get("Item")

    # --- positive control: the granted twin, publishing once per poll (a publish that races
    # subscription activation is dropped with no retry on real AWS, and the write is idempotent
    # per id) — also measures this account's real delivery latency for the window below. ---
    msg_id = ctx.unique_name("twin-")
    t0 = time.monotonic()

    def probe():
        sns.publish(TopicArn=topic["arn"], Message=json.dumps({"id": msg_id}))
        return _item(table_ok["name"], msg_id)

    ok_item = _poll_until(
        probe,
        lambda r: r is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="fn_ok delivery (granted invoke permission)",
    )
    latency_s = time.monotonic() - t0
    assert ok_item is not None, (
        "positive control failed: the twin WITH a granted invoke permission was never invoked, so "
        "the other twin's silence would prove nothing about the missing permission"
    )

    # --- the ungranted twin must stay silent for the same publishes, held for several times the
    # granted twin's own measured latency, sampled repeatedly rather than checked once. ---
    window_s = min(max(3.0 * latency_s, 15.0), 180.0)
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        leaked = _item(table_blocked["name"], msg_id)
        assert leaked is None, (
            f"Lambda was invoked by SNS despite never being granted lambda:InvokeFunction for "
            f"this topic: {leaked!r}"
        )
        samples += 1
        time.sleep(5.0)
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"

    # --- restore: granting the permission unblocks the identical kind of call ---
    lam.add_permission(
        FunctionName=fn_blocked["name"],
        StatementId=_STATEMENT_ID,
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic["arn"],
    )
    restored_id = ctx.unique_name("restored-")

    def probe_restored():
        sns.publish(TopicArn=topic["arn"], Message=json.dumps({"id": restored_id}))
        return _item(table_blocked["name"], restored_id)

    restored_item = _poll_until(
        probe_restored,
        lambda r: r is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="fn_blocked delivery after granting invoke permission",
    )
    assert restored_item is not None, (
        "granting the resource-based invoke permission did not unblock delivery to the "
        "previously-silent function (positive control failed)"
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


def _delete_log_group_if_exists(ctx, log_group: str) -> None:
    """Delete a log group; one that was never created is already in the desired state."""
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group)
    except logs.exceptions.ResourceNotFoundException:
        pass


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
            # too; a function that was never invoked has no log group, which is not a failure.
            ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx, f"/aws/lambda/{name}"))
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


def _create_topic(ctx) -> dict[str, str]:
    """Create an SNS topic (registers delete_topic teardown). Returns {name,arn}."""
    name = _xname(ctx, "topic")
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=name, Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
