"""eventbridge-to-lambda-blocked-without-resource-policy."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-to-lambda-blocked-without-resource-policy"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Revoking the Lambda resource policy for events.amazonaws.com blocks delivery; granting
    it back on the identical rule/target restores it. A positive control on the same wiring comes
    first, so "blocked" cannot be confused with "this pipe never delivers for any reason"."""
    sink = _create_queue(ctx)

    handler_code = """
import json, boto3, os

sqs = boto3.client("sqs")


def lambda_handler(event, context):
    sqs.send_message(
        QueueUrl=os.environ["SINK_QUEUE_URL"],
        MessageBody=json.dumps(event),
    )
    return {"ok": True}
"""

    fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[{"Action": ["sqs:SendMessage"], "Resource": sink["arn"]}],
        env={"SINK_QUEUE_URL": sink["url"]},
    )

    events = ctx.client("events")
    lam = ctx.client("lambda")
    rule_name = ctx.unique_name("rule")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["sim2real.test"]}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))

    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "lambda-target", "Arn": fn["arn"]}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, Ids=["lambda-target"]
        )
    )

    # --- Positive control, before anything is broken: grant the resource policy and prove this
    # exact rule/target delivers, measuring how long it takes (L). Without this leg, "blocked" is
    # indistinguishable from "this rule/target never invokes Lambda for any reason".
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="eb-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    positive_start = time.monotonic()
    positive_msgs = _put_events_until(
        ctx,
        [
            {
                "Source": "sim2real.test",
                "DetailType": "control",
                "Detail": json.dumps({"leg": "control"}),
            }
        ],
        lambda: _receive_and_drain(ctx, sink["url"]),
        timeout_s=75,
    )
    assert positive_msgs, (
        "positive control: EventBridge must invoke Lambda once the resource policy is granted"
    )
    positive_latency_s = time.monotonic() - positive_start

    # --- Break exactly one thing: revoke the resource policy just granted.
    lam.remove_permission(FunctionName=fn["name"], StatementId="eb-invoke")

    # --- Assert the effect is absent, held for >= 3x the measured positive latency (never a bare
    # sleep), and confirmed via a second independent observable (queue depth, not just a receive).
    window_s = min(120.0, max(15.0, 3 * positive_latency_s))
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.test",
                "DetailType": "blocked",
                "Detail": json.dumps({"leg": "blocked"}),
            }
        ]
    )
    leaked = _receive_messages(ctx, sink["url"], 1, timeout_s=window_s)
    assert not leaked, (
        f"Lambda was invoked despite a revoked resource-based policy for events.amazonaws.com "
        f"(waited {window_s:.0f}s, >= 3x the {positive_latency_s:.1f}s measured control latency)"
    )

    remaining = ctx.client("sqs").get_queue_attributes(
        QueueUrl=sink["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert remaining == "0", (
        f"expected zero queued messages while the resource policy is revoked; sink reports "
        f"{remaining!r}"
    )

    # --- Restore: re-grant the identical policy and prove the identical call succeeds again.
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="eb-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    restored_msgs = _put_events_until(
        ctx,
        [
            {
                "Source": "sim2real.test",
                "DetailType": "restored",
                "Detail": json.dumps({"leg": "restored"}),
            }
        ],
        lambda: _receive_and_drain(ctx, sink["url"]),
        timeout_s=75,
    )
    assert restored_msgs, (
        "restore: re-granting the identical resource policy must make the identical call "
        "succeed again"
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
    # IAM role trust/permission propagation before a service assumes it is handled by
    # _create_function_with_retry's bounded retry on "cannot be assumed" below, not a fixed sleep.
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


def _put_events_until(ctx, entries, probe, timeout_s=75, interval_s=6):
    """PutEvents repeatedly until a downstream effect appears.

    Rule/target creation on the default bus is eventually consistent: an event published
    immediately after PutTargets can be silently dropped. Republishing while polling makes the
    positive path deterministic.
    """
    events = ctx.client("events")

    def attempt():
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, resp
        return probe()

    return _poll_until(
        attempt, lambda r: bool(r), timeout_s=timeout_s, interval_s=interval_s
    )


def _receive_and_drain(ctx, queue_url, max_messages=10):
    """Read and delete whatever is on the queue, so a positive-control message can't linger and
    be mistaken for delivery during the later absence check."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=max_messages,
        WaitTimeSeconds=5,
        MessageAttributeNames=["All"],
    )
    msgs = resp.get("Messages", [])
    for msg in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return msgs


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    messages = _receive_messages(ctx, queue_url, expected_count, timeout_s=timeout_s, delete=delete)
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


def _receive_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive or the deadline passes; return what arrived."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
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
