"""lambda-sdk-putevents-triggers-rule."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-putevents-triggers-rule"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]

_HANDLER_SRC = """
import json, os, boto3

def handler(event, context):
    eb = boto3.client('events')
    resp = eb.put_events(Entries=[{
        'Source': 'sim2real.custom',
        'DetailType': event.get('detail_type', 'sim2real-test-event'),
        'Detail': json.dumps(event.get('detail', {})),
        'EventBusName': os.environ.get('BUS_NAME', 'default'),
    }])
    return {
        'FailedEntryCount': resp['FailedEntryCount'],
        'EventId': resp['Entries'][0].get('EventId'),
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler calling events.put_events emits an event that a matching EventBridge
    rule actually delivers to its target (observed as a real SQS message with the emitted
    detail), not merely a put_events call that returns FailedEntryCount=0."""
    detail_type = "sim2real-test-event"
    queue_url, queue_arn = _create_queue_target(ctx)
    rule_name = _put_rule_with_sqs_target(
        ctx,
        {"source": ["sim2real.custom"], "detail-type": [detail_type]},
        queue_arn,
        queue_url,
    )

    lambda_role_arn = _create_lambda_role(
        ctx,
        inline_policies={
            "put-events": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
            }
        },
    )
    fn_name, _ = _create_lambda(ctx, lambda_role_arn, _HANDLER_SRC)

    marker = ctx.unique_name("sim2real-marker-")
    result = _invoke_lambda(
        ctx, fn_name, {"detail_type": detail_type, "detail": {"marker": marker}}
    )
    assert result["FailedEntryCount"] == 0, f"expected 0 failed entries, got {result}"
    assert result["EventId"], f"expected put_events to return an EventId, got {result}"

    messages = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60)
    matching = [m for m in messages if m["body"].get("detail", {}).get("marker") == marker]
    assert len(matching) == 1, f"expected the emitted event to reach the queue, got {messages}"
    assert matching[0]["body"]["detail-type"] == detail_type, (
        f"expected detail-type {detail_type!r}, got {matching[0]['body'].get('detail-type')!r}"
    )
    assert matching[0]["body"]["source"] == "sim2real.custom", (
        f"expected source 'sim2real.custom', got {matching[0]['body'].get('source')!r}"
    )
    _ = rule_name


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_policies: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_arn


def _create_lambda(ctx, role_arn: str, handler_src: str, env: dict[str, str] | None = None, timeout: int = 30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    code = _zip_code(handler_src)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env or {}},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    return name, resp["FunctionArn"]


def _invoke_lambda(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload).encode("utf-8"), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {body}")
    return body


def _create_queue_target(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _put_rule_with_sqs_target(ctx, event_pattern: dict[str, Any], queue_arn: str, queue_url: str) -> str:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_name = ctx.unique_name("sim2real-rule-")
    events.put_rule(Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target1"]))
    return rule_name


def _wait_for_messages(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0):
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


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
