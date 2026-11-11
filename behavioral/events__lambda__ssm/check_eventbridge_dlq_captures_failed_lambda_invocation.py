"""eventbridge-dlq-captures-failed-lambda-invocation."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-dlq-captures-failed-lambda-invocation"

GROUP = "error-propagation"

SERVICES = ["events", "lambda", "ssm"]


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda target without an invoke grant fails delivery, and its DeadLetterConfig queue
    receives the event with ERROR_CODE NO_PERMISSIONS, the rule ARN and the target ARN."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    queue = _create_queue(ctx)
    success_queue = _create_queue(ctx)
    sqs = ctx.client("sqs")

    # Allow EventBridge to send to the DLQ.
    policy = {
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
    sqs.set_queue_attributes(
        QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)}
    )

    # The handler forwards every event it actually runs to `success_queue`, an independent
    # side-channel that proves invocation happened (not merely that something ended up in the
    # DLQ) -- see the positive-control leg below.
    code = """
import json
import os

import boto3


def lambda_handler(event, context):
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["OUT_URL"], MessageBody=json.dumps(event)
    )
    return {"ok": True}
"""
    fn = _create_lambda(
        ctx,
        code,
        permissions=[{"Action": "sqs:SendMessage", "Resource": success_queue["arn"]}],
        env={"OUT_URL": success_queue["url"]},
    )

    rule_name = ctx.unique_name("rule-dlq-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["integration.dlqtest"],
                "detail-type": ["WillFail"],
            }
        ),
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    # Deliberately NO add_permission: EventBridge cannot invoke the target.
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "t1",
                "Arn": fn["arn"],
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

    # SQS policy changes can take up to 60s to take effect, and EventBridge
    # never retries a dropped delivery — so publish repeatedly until a DLQ
    # message shows up rather than betting on a single event.
    def publish_then_poll():
        events.put_events(
            Entries=[
                {
                    "Source": "integration.dlqtest",
                    "DetailType": "WillFail",
                    "Detail": json.dumps({"marker": "dlq-test"}),
                }
            ]
        )
        resp = sqs.receive_message(
            QueueUrl=queue["url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=20,
            MessageAttributeNames=["All"],
        )
        return resp.get("Messages", [])

    received = _poll_until(
        publish_then_poll,
        lambda msgs: len(msgs) > 0,
        timeout_s=180,
        interval_s=1.0,
        description="undeliverable event captured in the target DLQ",
    )
    message = received[0]

    body = message["Body"]
    assert "dlq-test" in body, (
        f"DLQ message did not carry the original event detail: {body[:300]}"
    )

    # EventBridge stamps diagnostic metadata as SQS message attributes.
    attrs = message.get("MessageAttributes") or {}
    assert "ERROR_CODE" in attrs, (
        f"DLQ message missing ERROR_CODE attribute: {sorted(attrs)}"
    )
    error_code = attrs["ERROR_CODE"].get("StringValue")
    assert error_code == "NO_PERMISSIONS", f"unexpected DLQ ERROR_CODE: {error_code}"
    assert "RULE_ARN" in attrs, (
        f"DLQ message missing RULE_ARN attribute: {sorted(attrs)}"
    )
    assert rule_name in attrs["RULE_ARN"].get("StringValue", "")
    assert fn["arn"] == attrs["TARGET_ARN"].get("StringValue"), (
        "DLQ TARGET_ARN did not match the target"
    )

    # Effect is absent at the real destination: withheld delivery means the function itself
    # never ran, so nothing was forwarded to the success queue.
    absent = sqs.receive_message(
        QueueUrl=success_queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=2
    )
    assert not absent.get("Messages"), (
        "the target ran despite the withheld invoke permission: "
        f"success queue got {absent.get('Messages')}"
    )

    # Positive control: grant the withheld permission and prove the identical rule/target now
    # actually invokes the function instead of routing to the DLQ. Without this leg, a target
    # that unconditionally routes every DeadLetterConfig-bearing delivery to its DLQ --
    # never truly attempting invocation -- would score identically to a correct implementation
    # of the NO_PERMISSIONS failure mode.
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId=ctx.unique_name("allow-invoke-"),
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    def publish_then_poll_success():
        events.put_events(
            Entries=[
                {
                    "Source": "integration.dlqtest",
                    "DetailType": "WillFail",
                    "Detail": json.dumps({"marker": "dlq-test-positive"}),
                }
            ]
        )
        resp = sqs.receive_message(
            QueueUrl=success_queue["url"], MaxNumberOfMessages=1, WaitTimeSeconds=20
        )
        return resp.get("Messages", [])

    # New resource-based policy can take a few seconds to propagate, so re-emit until the
    # invocation actually goes through rather than betting on one put_events landing right
    # after add_permission returns.
    delivered = _poll_until(
        publish_then_poll_success,
        lambda msgs: len(msgs) > 0,
        timeout_s=90,
        interval_s=5.0,
        description="permissioned event actually invoking the same DLQ-wired target",
    )
    forwarded = json.loads(delivered[0]["Body"])
    assert forwarded["detail"] == {"marker": "dlq-test-positive"}, (
        f"success queue received an unexpected payload: {forwarded}"
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
    # No unconditional wait here: _create_function_with_retry below already retries through
    # the IAM trust/permission propagation window on the specific "cannot be assumed" error.
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
