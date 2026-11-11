"""lambda-putevents-wrong-event-bus-arn-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-putevents-wrong-event-bus-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_PUT_EVENTS_CODE = """
import boto3

def handler(event, context):
    client = boto3.client("events")
    entry = {
        "Source": event["Source"],
        "DetailType": event["DetailType"],
        "Detail": event["Detail"],
        "EventBusName": event["EventBusName"],
    }
    try:
        resp = client.put_events(Entries=[entry])
        return {
            "ok": True,
            "FailedEntryCount": resp.get("FailedEntryCount", 0),
            "Entries": resp.get("Entries", []),
        }
    except Exception as e:
        code = None
        if hasattr(e, "response"):
            code = e.response.get("Error", {}).get("Code")
        return {"ok": False, "error_code": code}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents to a well-formed but nonexistent event bus ARN returns 200 with FailedEntryCount 0
    and an EventId yet the entry is never delivered, while the identical call to the real bus
    (same Lambda, rule and queue) reaches the queue."""
    ctx.client("events")
    bus_name = ctx.unique_name("sim2real-bus-")
    bus_arn = _create_event_bus(ctx, bus_name)
    # Fabricate a syntactically valid bus ARN under the same account/region that was
    # never created.
    ghost_bus_name = ctx.unique_name("sim2real-ghost-bus-")
    ghost_bus_arn = bus_arn.rsplit("/", 1)[0] + "/" + ghost_bus_name

    queue_url, queue_arn = _create_queue(ctx)
    source_value = ctx.unique_name("sim2real.ghostbus.")
    rule_name = ctx.unique_name("sim2real-rule-")
    _wire_rule_to_queue(ctx, bus_name, rule_name, {"source": [source_value]}, queue_url, queue_arn)

    # Wildcard resource so authorization always passes -- isolates the "bus does not
    # exist" behavior from any IAM resource-scoping boundary.
    role_arn = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-role-"),
        inline_policy_doc={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
        },
    )
    function_name = ctx.unique_name("sim2real-fn-")
    _create_lambda_function(ctx, function_name, role_arn, _PUT_EVENTS_CODE)

    marker_ghost = ctx.unique_name("marker-ghost-")
    marker_good = ctx.unique_name("marker-good-")

    ghost_result = _invoke_lambda(
        ctx,
        function_name,
        {
            "EventBusName": ghost_bus_arn,
            "Source": source_value,
            "DetailType": "sim2real.test",
            "Detail": json.dumps({"marker": marker_ghost}),
        },
    )
    assert ghost_result["ok"] is True, ghost_result
    assert ghost_result["FailedEntryCount"] == 0, ghost_result
    assert ghost_result["Entries"][0].get("EventId"), ghost_result

    good_result = _invoke_lambda(
        ctx,
        function_name,
        {
            "EventBusName": bus_name,
            "Source": source_value,
            "DetailType": "sim2real.test",
            "Detail": json.dumps({"marker": marker_good}),
        },
    )
    assert good_result["ok"] is True, good_result
    assert good_result["FailedEntryCount"] == 0, good_result

    found, seen = _drain_until_marker(ctx, queue_url, marker_good, timeout_s=60.0)
    assert found is not None, "positive control event (real bus) never reached the SQS observer"
    assert not any(m.get("detail", {}).get("marker") == marker_ghost for m in seen), (
        "an entry addressed to a nonexistent event bus was delivered anyway"
    )


# ===== helpers =====

# Tag applied to every resource this check creates, marking it as created by the check.
_MANAGED_TAG_KV = {"Key": "sim2real:managed", "Value": "true"}


def _zip_code(module_name: str, code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{module_name}.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, role_name: str, inline_policy_doc: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[_MANAGED_TAG_KV]
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))

    if inline_policy_doc is not None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(inline_policy_doc)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-perms"))
    return role_arn


def _create_lambda_function(
    ctx, function_name: str, role_arn: str, code: str, env: dict[str, str] | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_code("index", code)},
        Timeout=timeout,
        MemorySize=128,
        Tags={_MANAGED_TAG_KV["Key"]: _MANAGED_TAG_KV["Value"]},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 90
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(5)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    lam.get_waiter("function_active").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _invoke_lambda(ctx, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised an unhandled error: {body}")
    return body


def _create_event_bus(ctx, name: str) -> str:
    events = ctx.client("events")
    resp = events.create_event_bus(Name=name, Tags=[_MANAGED_TAG_KV])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=name))
    return resp["EventBusArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-obs-"),
        tags={_MANAGED_TAG_KV["Key"]: _MANAGED_TAG_KV["Value"]},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _wire_rule_to_queue(
    ctx, bus_name: str, rule_name: str, event_pattern: dict[str, Any], queue_url: str, queue_arn: str
) -> str:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[_MANAGED_TAG_KV],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))
    rule_arn = rule["RuleArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventsToSendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    events.put_targets(Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["sqs-target"]))
    return rule_arn


def _drain_until_marker(
    ctx, queue_url: str, target_marker: str, timeout_s: float = 60.0
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    # Drains for the *entire* window rather than returning as soon as target_marker
    # is seen: the ghost entry (invoked before the good one) could still be in flight
    # when the good entry's marker arrives, and stopping early would bound the
    # ghost-absence check by whatever the good entry's latency happened to be
    # instead of by the full observation window.
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    found: dict[str, Any] | None = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("detail", {}).get("marker") == target_marker and found is None:
                found = body
    return found, seen


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
