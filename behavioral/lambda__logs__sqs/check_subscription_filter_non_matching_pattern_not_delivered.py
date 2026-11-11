"""subscription-filter-non-matching-pattern-not-delivered."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscription-filter-non-matching-pattern-not-delivered"

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
    raw = base64.b64decode(event["awslogs"]["data"])
    payload = json.loads(gzip.decompress(raw).decode("utf-8"))
    boto3.client("sqs").send_message(
        QueueUrl="{queue_url}",
        MessageBody=json.dumps(payload),
    )
    return {{"ok": True}}
'''


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subscription filter with pattern ERROR delivers only the matching line of a PutLogEvents batch
    to the destination; its non-matching batch-mates (including lowercase error_count=0) and an
    earlier quiet-only batch never arrive."""
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

    marker = ctx.unique_name("probe-")
    quiet = [
        f"INFO request handled {marker}-q1",
        f"WARN slow response {marker}-q2",
        f"INFO error_count=0 {marker}-q3",
    ]
    quiet_markers = [f"{marker}-q1", f"{marker}-q2", f"{marker}-q3"]
    error_marker = f"{marker}-e1"

    def _emit(messages: list[str]) -> None:
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[
                {"timestamp": now_ms + i, "message": m} for i, m in enumerate(messages)
            ],
        )

    # A quiet-only batch first: if the filter is ignored, these are already in flight.
    _emit(quiet)

    # Then the mixed batch, re-emitted until the MATCHING line lands. Every envelope that arrives on
    # the way is retained as the non-delivery evidence.
    matched, seen = _emit_until_delivered(
        ctx,
        results["url"],
        lambda: _emit(quiet + [f"ERROR sim2real subscription probe {error_marker}"]),
        lambda env: any(
            error_marker in e.get("message", "") for e in env.get("logEvents", [])
        ),
        attempts=14,
        poll_s=12.0,
        description=f"the matching ERROR line {error_marker}",
    )

    assert matched["messageType"] == "DATA_MESSAGE", matched.get("messageType")
    assert matched["subscriptionFilters"] == [filter_name], matched.get(
        "subscriptionFilters"
    )

    delivered = [e.get("message", "") for e in matched.get("logEvents", [])]
    assert delivered, f"the delivered envelope must carry logEvents, got {matched!r}"
    assert all("ERROR" in m for m in delivered), (
        f"every delivered event must match filterPattern 'ERROR'; the envelope carried "
        f"{delivered!r}"
    )
    leaked_in_batch = [m for m in delivered if any(q in m for q in quiet_markers)]
    assert not leaked_in_batch, (
        f"non-matching events written in the SAME PutLogEvents batch as the matching one must not "
        f"be delivered, but the envelope carried {leaked_in_batch!r}"
    )

    # And nothing non-matching may have arrived in any earlier envelope either.
    leaked_earlier = [
        m
        for env in seen
        for m in (e.get("message", "") for e in env.get("logEvents", []))
        if any(q in m for q in quiet_markers)
    ]
    assert not leaked_earlier, (
        f"the subscription must never deliver non-matching events, but {len(leaked_earlier)} "
        f"arrived: {leaked_earlier!r}"
    )


def _emit_until_delivered(
    ctx,
    queue_url,
    emit,
    predicate,
    *,
    attempts=14,
    poll_s=12.0,
    description="subscription delivery",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Emit repeatedly until an envelope satisfying predicate lands; return (matched, all seen).

    A newly created subscription filter can drop events before the Logs -> Lambda path is live, and
    CloudWatch Logs does not retry a dropped subscription delivery. The accumulated `seen` list is
    the non-delivery evidence.
    """
    seen: list[dict[str, Any]] = []
    for _ in range(attempts):
        emit()
        for envelope in _drain(ctx, queue_url, timeout_s=poll_s):
            seen.append(envelope)
            if predicate(envelope):
                return envelope, seen
    raise AssertionError(
        f"{description} was never delivered after {attempts} attempts. Envelopes seen: {seen!r}"
    )


def _drain(ctx, queue_url: str, *, timeout_s: float) -> list[dict[str, Any]]:
    """Receive and delete every available message for up to timeout_s; return parsed bodies."""
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        messages = resp.get("Messages", [])
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(body, dict):
                out.append(body)
        if messages:
            break
    return out


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
