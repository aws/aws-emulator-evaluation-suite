"""lambda-putevents-triggers-downstream-rule-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-putevents-triggers-downstream-rule-positive"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "events", "lambda"]

_PRODUCER_CODE = """
import boto3

def handler(event, context):
    client = boto3.client("events")
    entry = {
        "Source": event["Source"],
        "DetailType": event["DetailType"],
        "Detail": event["Detail"],
        "EventBusName": event["EventBusName"],
    }
    resp = client.put_events(Entries=[entry])
    return {
        "FailedEntryCount": resp.get("FailedEntryCount", 0),
        "Entries": resp.get("Entries", []),
    }
"""

_CONSUMER_CODE = """
import boto3
import json
import os

def handler(event, context):
    sqs = boto3.client("sqs")
    sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(event))
    return {"forwarded": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event a producer Lambda emits via PutEvents matches an EventBridge rule
    that invokes a second, downstream Lambda -- observed via the downstream Lambda's
    own side effect (forwarding the event to an SQS queue it owns)."""
    events = ctx.client("events")
    lam = ctx.client("lambda")

    bus_name = ctx.unique_name("sim2real-bus-")
    bus_arn = _create_event_bus(ctx, bus_name)

    queue_url, queue_arn = _create_queue(ctx)

    consumer_role_arn = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-role-consumer-"),
        inline_policy_doc={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        },
    )
    consumer_name = ctx.unique_name("sim2real-fn-consumer-")
    consumer_arn = _create_lambda_function(
        ctx, consumer_name, consumer_role_arn, _CONSUMER_CODE, env={"QUEUE_URL": queue_url}
    )

    source_value = ctx.unique_name("sim2real.chain.")
    rule_name = ctx.unique_name("sim2real-rule-")
    rule = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source_value]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))
    rule_arn = rule["RuleArn"]

    lam.add_permission(
        FunctionName=consumer_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "lambda-target", "Arn": consumer_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["lambda-target"]))

    producer_role_arn = _create_lambda_role(
        ctx,
        ctx.unique_name("sim2real-role-producer-"),
        inline_policy_doc={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}],
        },
    )
    producer_name = ctx.unique_name("sim2real-fn-producer-")
    _create_lambda_function(ctx, producer_name, producer_role_arn, _PRODUCER_CODE)

    marker = ctx.unique_name("marker-")
    payload = {
        "EventBusName": bus_name,
        "Source": source_value,
        "DetailType": "sim2real.chain.test",
        "Detail": json.dumps({"marker": marker}),
    }
    result = _invoke_lambda(ctx, producer_name, payload)
    assert result["FailedEntryCount"] == 0, result

    found, _seen = _drain_until_marker(ctx, queue_url, marker, timeout_s=60.0)
    assert found is not None, "downstream Lambda invocation via EventBridge never forwarded the event"
    forwarded_event = found  # this is the full EventBridge event envelope forwarded by the consumer Lambda
    assert forwarded_event["source"] == source_value, (
        f"expected forwarded event source {source_value!r}, got {forwarded_event['source']!r}"
    )
    assert forwarded_event["detail"]["marker"] == marker, (
        f"expected forwarded detail marker {marker!r}, got {forwarded_event['detail'].get('marker')!r}"
    )
    assert forwarded_event["detail-type"] == "sim2real.chain.test", (
        f"expected forwarded detail-type 'sim2real.chain.test', got {forwarded_event['detail-type']!r}"
    )


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    resp = events.create_event_bus(Name=name)
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=name))
    return resp["EventBusArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-obs-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _drain_until_marker(
    ctx, queue_url: str, target_marker: str, timeout_s: float = 60.0
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    found: dict[str, Any] | None = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and found is None:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("detail", {}).get("marker") == target_marker:
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
