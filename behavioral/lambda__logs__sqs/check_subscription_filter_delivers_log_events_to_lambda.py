"""subscription-filter-delivers-log-events-to-lambda."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-filter-delivers-log-events-to-lambda"

GROUP = "data-delivery"

SERVICES = ["lambda", "logs", "sqs"]


def _decoder_code(queue_url: str) -> str:
    """Lambda code that decodes the CloudWatch Logs subscription payload and forwards it to SQS."""
    return f'''
import base64
import gzip
import json

import boto3


def lambda_handler(event, context):
    # CloudWatch Logs delivers subscription data as base64-encoded gzip under
    # event["awslogs"]["data"] -- the decode is part of the contract under test.
    raw = base64.b64decode(event["awslogs"]["data"])
    payload = json.loads(gzip.decompress(raw).decode("utf-8"))
    boto3.client("sqs").send_message(
        QueueUrl="{queue_url}",
        MessageBody=json.dumps(payload),
    )
    return {{"ok": True}}
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudWatch Logs subscription filter pushes matching log events to a Lambda function, in the
    base64+gzip `awslogs` envelope, and the decoded payload names the source log group and filter.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html
    """
    results = _create_queue(ctx)
    fn = _create_lambda(
        ctx,
        _decoder_code(results["url"]),
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": results["arn"]}],
    )
    account = fn["arn"].split(":")[4]

    logs = ctx.client("logs")
    group_name, stream_name = _log_group_with_stream(ctx)
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group_name}:*"

    ctx.client("lambda").add_permission(
        FunctionName=fn["name"],
        StatementId="AllowCloudWatchLogsInvoke",
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=group_arn,
        SourceAccount=account,
    )

    filter_name = _xname(ctx, "subfilter")
    logs.put_subscription_filter(
        logGroupName=group_name,
        filterName=filter_name,
        filterPattern="ERROR",
        destinationArn=fn["arn"],
    )
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_subscription_filter(
            logGroupName=group_name, filterName=filter_name
        )
    )

    described = logs.describe_subscription_filters(
        logGroupName=group_name, filterNamePrefix=filter_name
    )["subscriptionFilters"]
    assert described, f"subscription filter {filter_name} must be listed on {group_name}"
    assert described[0]["destinationArn"] == fn["arn"], (
        f"the destination ARN must round-trip, got {described[0].get('destinationArn')!r}"
    )
    assert described[0]["filterPattern"] == "ERROR", described[0]

    marker = ctx.unique_name("probe-")
    body = _emit_until_delivered(
        ctx,
        logs,
        group_name,
        stream_name,
        results["url"],
        f"ERROR sim2real subscription probe {marker}",
    )

    assert body["messageType"] == "DATA_MESSAGE", (
        f"a subscription delivery of real log data must be a DATA_MESSAGE, got "
        f"{body.get('messageType')!r}"
    )
    assert body["logGroup"] == group_name, (
        f"the payload must name the source log group, got {body.get('logGroup')!r}"
    )
    assert body["logStream"] == stream_name, (
        f"the payload must name the source log stream, got {body.get('logStream')!r}"
    )
    assert body["subscriptionFilters"] == [filter_name], (
        f"the payload must name the filter that matched, got "
        f"{body.get('subscriptionFilters')!r}"
    )
    assert body["owner"] == account, (
        f"the payload must name the owning account, got {body.get('owner')!r}"
    )
    events = body.get("logEvents")
    assert isinstance(events, list) and events, (
        f"logEvents must be a non-empty list, got {events!r}"
    )
    assert any(marker in e.get("message", "") for e in events), (
        f"the delivered logEvents must include the emitted line; got "
        f"{[e.get('message') for e in events]}"
    )
    first = events[0]
    assert isinstance(first.get("id"), str) and first["id"], (
        f"each delivered log event carries an id, got {first!r}"
    )
    assert isinstance(first.get("timestamp"), int), (
        f"each delivered log event carries an integer ms timestamp, got {first!r}"
    )


def _emit_until_delivered(
    ctx, logs, group_name, stream_name, queue_url, message, *, attempts=14, poll_s=12.0
) -> dict[str, Any]:
    """Write the log line repeatedly until the subscription delivery lands on the queue.

    A new subscription filter can drop events before the Logs -> Lambda path is live."""
    for _ in range(attempts):
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
        )
        received = _receive_messages(ctx, queue_url, max_count=1, timeout_s=poll_s)
        if received:
            return received[0]["body"]
    raise AssertionError(
        f"subscription filter never delivered a log event to the Lambda -> {queue_url} path "
        f"after {attempts} attempts of {poll_s}s each"
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


def _log_group_with_stream(ctx) -> tuple[str, str]:
    """Create a log group (1-day retention, tagged) plus a stream. Returns (group, stream)."""
    logs = ctx.client("logs")
    group_name = _xname(ctx, "lg")
    logs.create_log_group(logGroupName=group_name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=group_name))
    # Bound stored-data cost even if teardown is interrupted.
    logs.put_retention_policy(logGroupName=group_name, retentionInDays=1)
    stream_name = _xname(ctx, "stream")
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    return group_name, stream_name


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


def _delete_log_group_if_present(ctx, group_name: str) -> None:
    """Delete a log group that may not exist (Lambda creates it lazily, on first log write)."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
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
            # function deletion, so delete it too (best-effort).
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
    """Create a Lambda with an execution role scoped to `permissions`; logs are always allowed."""
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
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
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


def _receive_messages(ctx, queue_url, max_count=1, timeout_s=60.0, delete=True):
    """Receive up to max_count SQS messages within timeout_s; return what arrived (may be empty)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < max_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, max_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
