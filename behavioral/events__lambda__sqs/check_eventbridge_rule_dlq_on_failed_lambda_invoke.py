"""eventbridge-rule-dlq-on-failed-lambda-invoke."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-rule-dlq-on-failed-lambda-invoke"
GROUP = "error-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule-level DeadLetterConfig routes a matched event to the SQS DLQ when EventBridge's own
    invoke of the Lambda target fails (withheld invoke permission, NO_PERMISSIONS) and the function
    is never invoked; once the permission is granted the same rule invokes it and the DLQ stays empty."""
    dlq = _create_queue_with_events_policy(ctx)
    out_queue = _create_plain_queue(ctx)
    role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": out_queue["arn"]}
            ],
        },
    )
    fn = _create_lambda_function(
        ctx,
        role_arn,
        source=(
            "import boto3, json, os\n"
            "def handler(event, context):\n"
            "    boto3.client('sqs').send_message(\n"
            "        QueueUrl=os.environ['OUT_URL'], MessageBody=json.dumps(event)\n"
            "    )\n"
            "    return {'ok': True}\n"
        ),
        env={"OUT_URL": out_queue["url"]},
    )

    rule = _put_rule(
        ctx,
        pattern={"source": ["sim2real.billing"], "detail-type": ["InvoiceFailed"]},
    )
    # No permission granted yet: without a resource policy statement granting
    # events.amazonaws.com permission to invoke this function, EventBridge's invocation
    # attempt fails immediately (no retries possible) and is routed to the DLQ. The restore
    # leg below grants the permission with _add_lambda_permission_for_rule and proves the
    # identical rule/target then actually invokes the function.
    _put_targets(
        ctx,
        rule["name"],
        [
            {
                "Id": "lambda-target",
                "Arn": fn["arn"],
                "RetryPolicy": {"MaximumRetryAttempts": 0},
                "DeadLetterConfig": {"Arn": dlq["arn"]},
            }
        ],
    )

    events = ctx.client("events")

    # A freshly created rule/target can silently drop the first PutEvents before the path is
    # fully live, and EventBridge never retries a dropped event — so re-emit periodically
    # rather than trusting a single call.
    def _emit_and_drain_dlq():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.billing",
                    "DetailType": "InvoiceFailed",
                    "Detail": json.dumps({"invoiceId": "INV-001"}),
                }
            ]
        )
        return _drain_dlq(ctx, dlq["url"], wait_s=5)

    messages = _poll_until(
        _emit_and_drain_dlq,
        lambda msgs: len(msgs) >= 1,
        timeout_s=90.0,
        interval_s=5.0,
        description="DLQ message after EventBridge failed to invoke the target",
    )
    assert len(messages) >= 1, f"expected >=1 DLQ message, got {len(messages)}"
    msg = messages[0]
    body = json.loads(msg["Body"])
    assert body["detail"]["invoiceId"] == "INV-001", (
        f"expected DLQ message detail.invoiceId=INV-001, got {body['detail']!r}"
    )
    assert body["source"] == "sim2real.billing", (
        f"expected DLQ message source=sim2real.billing, got {body['source']!r}"
    )
    # EventBridge stamps DLQ messages with failure metadata as message attributes.
    attrs = msg.get("MessageAttributes", {})
    assert attrs.get("RULE_ARN", {}).get("StringValue") == rule["arn"], (
        f"expected RULE_ARN={rule['arn']}, got {attrs.get('RULE_ARN')!r}"
    )
    assert attrs.get("TARGET_ARN", {}).get("StringValue") == fn["arn"], (
        f"expected TARGET_ARN={fn['arn']}, got {attrs.get('TARGET_ARN')!r}"
    )
    assert attrs.get("ERROR_CODE", {}).get("StringValue") == "NO_PERMISSIONS", (
        f"expected ERROR_CODE=NO_PERMISSIONS, got {attrs.get('ERROR_CODE')!r}"
    )

    # Effect is absent at the real destination: while the permission is missing, EventBridge
    # never actually invoked the function, so nothing was forwarded to the out queue. Without
    # this, a target that routes every DeadLetterConfig-bearing event straight to the DLQ
    # (ignoring whether the target invocation would have succeeded) would pass the assertions
    # above just as well as a target that correctly detects a failed invocation.
    assert _drain_queue(ctx, out_queue["url"], wait_s=5) == [], (
        "the function must not have been invoked while permission was missing"
    )

    # --- Restore leg: grant the permission and prove the identical rule/target now succeeds.
    # Propagation of the new resource-based policy can take a few seconds, so re-emit
    # periodically until the invocation actually goes through rather than trusting a single
    # put_events call landing right after add_permission returns.
    _add_lambda_permission_for_rule(ctx, fn["name"], rule["arn"])

    def _emit_and_drain_out():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.billing",
                    "DetailType": "InvoiceFailed",
                    "Detail": json.dumps({"invoiceId": "INV-002"}),
                }
            ]
        )
        return _drain_queue(ctx, out_queue["url"], wait_s=5)

    out_messages = _poll_until(
        _emit_and_drain_out,
        lambda msgs: len(msgs) >= 1,
        timeout_s=90.0,
        interval_s=5.0,
        description="lambda invocation forwarded to the out queue after permission was granted",
    )
    out_body = json.loads(out_messages[0]["Body"])
    assert out_body["detail"]["invoiceId"] == "INV-002", (
        f"expected forwarded detail.invoiceId=INV-002, got {out_body['detail']!r}"
    )

    # Now that permission has definitely propagated (the invocation above proved it), one more
    # clean emit-and-check shows the two-sided contract at the same instant: the identical call
    # succeeds AND the DLQ receives nothing for it.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.billing",
                "DetailType": "InvoiceFailed",
                "Detail": json.dumps({"invoiceId": "INV-003"}),
            }
        ]
    )
    final_out = _wait_for_messages(ctx, out_queue["url"], expected_count=1, timeout_s=30.0)
    final_body = json.loads(final_out[0]["Body"])
    assert final_body["detail"]["invoiceId"] == "INV-003", (
        f"expected forwarded detail.invoiceId=INV-003, got {final_body['detail']!r}"
    )
    assert _drain_queue(ctx, dlq["url"], wait_s=5) == [], (
        "the DLQ must stay empty once EventBridge can invoke the target successfully"
    )


# ===== helpers =====
_MANAGED_TAG_KEY = "sim2real:managed"
_MANAGED_TAG_VALUE = "true"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: _MANAGED_TAG_VALUE}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _lambda_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_lambda_role(ctx, inline_policy=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ebl-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_lambda_trust_policy(),
        Tags=_resource_tags_kv(),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )
    if inline_policy:
        policy_name = ctx.unique_name("sim2real-ebl-policy-")
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _zip_code(source: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_lambda_function(
    ctx, role_arn, source, handler="index.handler", env=None, timeout=15
) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-ebl-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_code(source)},
        Timeout=timeout,
        Publish=True,
        Tags=_resource_tags(),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    resp = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    # An actually-invoked function auto-creates /aws/lambda/<name>, which outlives the
    # function's own deletion.
    ctx.on_cleanup(lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}"))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue_with_events_policy(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-dlq-")
    url = sqs.create_queue(QueueName=name, tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    account_id = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": arn,
                "Condition": {
                    "ArnEquals": {
                        "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account_id}:rule/*"
                    }
                },
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return {"url": url, "arn": arn}


def _create_plain_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-ebl-outq-")
    url = sqs.create_queue(QueueName=name, tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url, max_messages=10, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    out = []
    while time.monotonic() < deadline and len(out) < expected_count:
        out.extend(_drain_queue(ctx, queue_url, wait_s=5))
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} messages, got {len(out)}")
    return out


def _drain_dlq(ctx, queue_url, wait_s=5):
    """Like _drain_queue, but also fetches DLQ failure-metadata message attributes."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=wait_s,
        MessageAttributeNames=["All"],
    )
    out: list[dict[str, Any]] = []
    for msg in resp.get("Messages", []):
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _put_rule(ctx, pattern=None, schedule=None, state="ENABLED", event_bus_name=None):
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-ebl-rule-")
    kwargs: dict[str, Any] = {"Name": name, "State": state, "Tags": _resource_tags_kv()}
    if pattern is not None:
        kwargs["EventPattern"] = json.dumps(pattern)
    if schedule is not None:
        kwargs["ScheduleExpression"] = schedule
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_rule(**kwargs)
    if event_bus_name:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name, EventBusName=event_bus_name))
    else:
        ctx.on_cleanup(lambda: events.delete_rule(Name=name))
    return {"name": name, "arn": resp["RuleArn"]}


def _put_targets(ctx, rule_name, targets, event_bus_name=None):
    events = ctx.client("events")
    kwargs: dict[str, Any] = {"Rule": rule_name, "Targets": targets}
    if event_bus_name:
        kwargs["EventBusName"] = event_bus_name
    resp = events.put_targets(**kwargs)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failures: {resp['FailedEntries']}")
    ids = [t["Id"] for t in targets]

    def _cleanup():
        kw: dict[str, Any] = {"Rule": rule_name, "Ids": ids}
        if event_bus_name:
            kw["EventBusName"] = event_bus_name
        events.remove_targets(**kw)

    ctx.on_cleanup(_cleanup)


def _add_lambda_permission_for_rule(ctx, function_name, rule_arn, statement_id=None):
    lam = ctx.client("lambda")
    sid = statement_id or ctx.unique_name("sim2real-ebl-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
