"""lambda-async-invoke-destination-eventbridge-onfailure-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-async-invoke-destination-eventbridge-onfailure-positive"
GROUP = "notification"
SERVICES = ["dynamodb", "events", "lambda"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]


def _managed_tags_dict() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An always-failing async invoke delivers a "Lambda Function Invocation Result - Failure" event (source lambda)
    to the OnFailure bus with the request payload, condition RetriesExhausted, the function's ARN and its error.
    """
    events = ctx.client("events")
    lam = ctx.client("lambda")

    bus_name = ctx.unique_name("sim2real-bus-")
    events.create_event_bus(Name=bus_name, Tags=_managed_tags_kv())
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))
    bus_arn = f"arn:aws:events:{ctx.region}:{_account_id(ctx)}:event-bus/{bus_name}"

    queue_url, queue_arn = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = json.dumps(
        {"source": ["lambda"], "detail-type": ["Lambda Function Invocation Result - Failure"]}
    )
    rule_arn = events.put_rule(
        Name=rule_name, EventBusName=bus_name, EventPattern=pattern, Tags=_managed_tags_kv()
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    _allow_events_to_send_to_queue(ctx, queue_url, queue_arn, rule_arn)
    events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "queue-target", "Arn": queue_arn}]
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["queue-target"])
    )

    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn},
        ],
    )

    fn_name = ctx.unique_name("sim2real-fn-")
    code = "def handler(event, context):\n    raise RuntimeError('boom-' + str(event.get('marker')))\n"
    _create_function(ctx, fn_name, role_arn, code)

    lam.put_function_event_invoke_config(
        FunctionName=fn_name,
        MaximumRetryAttempts=0,
        DestinationConfig={"OnFailure": {"Destination": bus_arn}},
    )

    marker = ctx.unique_name("marker-")
    lam.invoke(
        FunctionName=fn_name, InvocationType="Event", Payload=json.dumps({"marker": marker}).encode()
    )

    body = _poll_until(
        lambda: _receive_one(ctx, queue_url),
        lambda m: m is not None,
        timeout_s=120.0,
        interval_s=3.0,
    )
    envelope = json.loads(body)
    assert envelope["source"] == "lambda", f"expected source=lambda, got {envelope['source']!r}"
    assert envelope["detail-type"] == "Lambda Function Invocation Result - Failure", (
        f"expected detail-type='Lambda Function Invocation Result - Failure', "
        f"got {envelope['detail-type']!r}"
    )
    detail = envelope["detail"]
    assert detail["requestPayload"] == {"marker": marker}, (
        f"expected requestPayload={{'marker': {marker!r}}}, got {detail['requestPayload']!r}"
    )
    assert detail["requestContext"]["condition"] == "RetriesExhausted", (
        f"expected condition=RetriesExhausted, got {detail['requestContext']['condition']!r}"
    )
    assert fn_name in detail["requestContext"]["functionArn"], (
        f"expected functionArn to contain {fn_name!r}, got "
        f"{detail['requestContext']['functionArn']!r}"
    )
    assert "boom-" + marker in detail["responsePayload"]["errorMessage"], (
        f"expected errorMessage to contain 'boom-{marker}', got "
        f"{detail['responsePayload']['errorMessage']!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]], suffix: str = "role") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{suffix}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=_managed_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_arn


def _create_function(ctx, name: str, role_arn: str, code: str, env=None, timeout=30) -> str:
    lam = ctx.client("lambda")
    zip_bytes = _make_zip(code)
    deadline = time.monotonic() + 90
    resp = None
    while True:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Publish=True,
                Tags=_managed_tags_dict(),
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags=_managed_tags_dict()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_events_to_send_to_queue(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
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


def _receive_one(ctx, queue_url: str):
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    messages = resp.get("Messages", [])
    if not messages:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
    return messages[0]["Body"]


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
