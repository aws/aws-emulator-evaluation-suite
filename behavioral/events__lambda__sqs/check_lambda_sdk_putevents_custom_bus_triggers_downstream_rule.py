"""lambda-sdk-putevents-custom-bus-triggers-downstream-rule."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-putevents-custom-bus-triggers-downstream-rule"
GROUP = "sdk-call"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """
import json
import boto3

def handler(event, context):
    client = boto3.client('events')
    try:
        resp = client.put_events(Entries=[{
            'Source': event['source'],
            'DetailType': event['detail_type'],
            'Detail': json.dumps(event['detail']),
            'EventBusName': event['bus_name'],
        }])
        entries = resp.get('Entries', [])
        return {
            'ok': resp.get('FailedEntryCount', 0) == 0,
            'failed': resp.get('FailedEntryCount', 0),
            'event_id': entries[0].get('EventId') if entries else None,
        }
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', str(e))
        return {'ok': False, 'code': code}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function's PutEvents call to a custom bus triggers a rule fanning out to SQS."""
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"), tags=_tags_map()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    source_value = "sim2real.lambda.putevents.test"
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source_value]}),
        State="ENABLED",
        Tags=_tags_kv(),
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

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

    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "sqs-target", "Arn": queue_arn}],
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["sqs-target"])
    )

    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}],
        "putevents-ok",
    )
    fn_name = _create_function(ctx, role_arn, _HANDLER, "putevents-ok")

    detail = {"orderId": "sim2real-42", "amount": 7}
    body = _poll_until(
        lambda: _invoke(ctx, fn_name, {
            "bus_name": bus_name,
            "source": source_value,
            "detail_type": "sim2real.test.event",
            "detail": detail,
        }),
        lambda b: b.get("ok") is True,
        timeout_s=40.0,
        interval_s=3.0,
    )
    assert body["failed"] == 0
    assert body["event_id"]

    messages = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert len(messages) == 1
    payload = json.loads(messages[0]["Body"])
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
    assert payload["source"] == source_value
    assert payload["detail-type"] == "sim2real.test.event"
    assert payload["detail"] == detail


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _tags_map() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_role(ctx: Any, statements: list, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-role-{suffix}-")
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY, Tags=_tags_kv()
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LOGS_POLICY_ARN)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-under-test",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_handler(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_code: str, suffix: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{suffix}-")
    zip_bytes = _zip_handler(handler_code)
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_tags_map(),
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"function {name} never became creatable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    return json.loads(resp["Payload"].read())


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
