"""eventbridge-rule-without-lambda-permission-blocks-invocation."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-without-lambda-permission-blocks-invocation"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "ssm"]


@tags("axis:negative-delivery", "cap:c7", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule targeting Lambda without a resource-policy grant does not invoke it for the event the
    target DLQ receives with ERROR_CODE NO_PERMISSIONS naming the rule and target, while delivery
    works with the grant in place both before it is removed and after it is restored."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    ddb = ctx.client("dynamodb")

    table = _create_table(ctx)
    queue = _create_queue(ctx)
    sqs.set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventsDlq",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue["arn"],
                        }
                    ],
                }
            )
        },
    )

    code = f'''
import boto3

ddb = boto3.client("dynamodb")


def lambda_handler(event, context):
    key = event.get("detail", {{}}).get("key", "unknown")
    ddb.put_item(TableName="{table["name"]}", Item={{"pk": {{"S": key}}}})
    return {{"ok": True}}
'''
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": ["dynamodb:PutItem"], "Resource": table["arn"]}],
    )
    account = fn["arn"].split(":")[4]

    rule_name = ctx.unique_name("rule-noperm-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["integration.noperm"], "detail-type": ["ShouldNotInvoke"]}
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    source_arn = f"arn:aws:events:{ctx.region}:{account}:rule/{rule_name}"

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "t1",
                "Arn": fn["arn"],
                # The DLQ turns "nothing happened" into a positive NO_PERMISSIONS observation;
                # zero retries makes that message final rather than a mid-retry snapshot.
                "DeadLetterConfig": {"Arn": queue["arn"]},
                "RetryPolicy": {
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
            }
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["t1"])
    )

    sid = ctx.unique_name("sid-")

    def _grant() -> None:
        lam.add_permission(
            FunctionName=fn["name"],
            StatementId=sid,
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=source_arn,
        )

        def _statement_visible() -> bool:
            try:
                return sid in lam.get_policy(FunctionName=fn["name"])["Policy"]
            except ClientError:
                return False

        _poll_until(
            _statement_visible,
            lambda visible: visible,
            timeout_s=30,
            interval_s=2.0,
            description=f"resource policy statement {sid} visible",
        )
        # The probes below republish on a bounded deadline, absorbing residual propagation lag.

    def _invoked_item(key: str):
        return ddb.get_item(TableName=table["name"], Key={"pk": {"S": key}}).get(
            "Item"
        )

    def _publish(key: str) -> None:
        events.put_events(
            Entries=[
                {
                    "Source": "integration.noperm",
                    "DetailType": "ShouldNotInvoke",
                    "Detail": json.dumps({"key": key}),
                }
            ]
        )

    # Positive control: with the grant in place, the target must actually be invoked.
    _grant()
    control_key = ctx.unique_name("control-")

    def _control_probe():
        _publish(control_key)
        return _invoked_item(control_key)

    control_item = _poll_until(
        _control_probe,
        lambda item: item is not None,
        timeout_s=180,
        interval_s=5.0,
        description="positive control: Lambda invoked while the grant is in place",
    )
    assert control_item is not None, "positive control never invoked the target"

    # Break exactly one thing: withdraw the grant.
    lam.remove_permission(FunctionName=fn["name"], StatementId=sid)
    no_policy_code, no_policy_message = _error(lambda: lam.get_policy(FunctionName=fn["name"]))
    assert no_policy_code == "ResourceNotFoundException", (
        f"removing the only statement must leave no resource policy, GetPolicy returned "
        f"{no_policy_code!r}"
    )
    assert no_policy_message == "The resource you requested does not exist.", (
        f"expected GetPolicy's no-policy message, got {no_policy_message!r}"
    )

    # Removal propagates with a lag: an event published meanwhile may still be invoked. Each
    # attempt publishes a fresh key, and only a key whose event reached the DLQ is judged.
    negative_keys: list[str] = []

    def _negative_probe():
        negative_keys.append(ctx.unique_name("negative-"))
        _publish(negative_keys[-1])
        resp = sqs.receive_message(
            QueueUrl=queue["url"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        return [
            m for m in resp.get("Messages", [])
            if json.loads(m["Body"]).get("detail", {}).get("key") in negative_keys
        ]

    received = _poll_until(
        _negative_probe,
        lambda msgs: len(msgs) > 0,
        timeout_s=180,
        interval_s=1.0,
        description="undeliverable event captured in the target DLQ after the grant was removed",
    )
    message = received[0]
    dead_key = json.loads(message["Body"])["detail"]["key"]
    msg_attrs = message.get("MessageAttributes") or {}
    assert "ERROR_CODE" in msg_attrs, (
        f"DLQ message missing ERROR_CODE attribute: {sorted(msg_attrs)}"
    )
    error_code = msg_attrs["ERROR_CODE"].get("StringValue")
    assert error_code == "NO_PERMISSIONS", f"unexpected DLQ ERROR_CODE: {error_code}"
    assert rule_name in (msg_attrs.get("RULE_ARN") or {}).get("StringValue", ""), (
        f"DLQ RULE_ARN did not name this rule: {msg_attrs.get('RULE_ARN')}"
    )
    assert fn["arn"] == (msg_attrs.get("TARGET_ARN") or {}).get("StringValue"), (
        f"DLQ TARGET_ARN did not match the target: {msg_attrs.get('TARGET_ARN')}"
    )

    assert _invoked_item(dead_key) is None, (
        f"Lambda was invoked for {dead_key!r}, whose event EventBridge dead-lettered"
    )

    # Restoring the grant shows the absence above was the missing permission alone.
    _grant()
    restored_key = ctx.unique_name("restored-")

    def _restored_probe():
        _publish(restored_key)
        return _invoked_item(restored_key)

    restored_item = _poll_until(
        _restored_probe,
        lambda item: item is not None,
        timeout_s=180,
        interval_s=5.0,
        description="restore: Lambda invoked again once the grant was restored",
    )
    assert restored_item is not None, "restoring the grant did not resume delivery"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _error(call) -> tuple[str, str]:
    """Run call(); return (error_code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    # IAM propagation is absorbed by _create_function_with_retry's bounded retry.
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
    Its teardown runs before its role's (LIFO)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Dedent inline source and alias `handler` to the fixed `lambda_handler` entrypoint; without
    # that symbol the function fails with Runtime.HandlerNotFound.
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
            # /aws/lambda/<name> is created on first invoke and survives function deletion.
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


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
