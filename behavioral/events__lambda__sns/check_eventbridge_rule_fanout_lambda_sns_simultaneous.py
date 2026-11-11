"""eventbridge-rule-fanout-lambda-sns-simultaneous."""

from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-fanout-lambda-sns-simultaneous"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sns"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A single PutEvents call matching one rule with two targets invokes the Lambda function
    and publishes to the SNS topic simultaneously (fan-out delivery)."""
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_echo_function(ctx, role_arn)
    topic_arn = _create_topic(ctx)
    queue_url = _create_queue_subscribed_to_topic(ctx, topic_arn)

    source = ctx.unique_name("sim2real.evtfan.src-")
    rule_name, rule_arn = _create_rule(ctx, source)
    _allow_events_to_invoke(ctx, fn_name, rule_arn)
    _allow_events_to_publish(ctx, topic_arn, rule_arn)

    events = ctx.client("events")
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "1", "Arn": fn_arn}, {"Id": "2", "Arn": topic_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1", "2"]))

    marker = ctx.unique_name("marker-")
    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "sim2real.test",
                "Detail": json.dumps({"marker": marker}),
            }
        ]
    )

    log_events = _wait_for_log_marker(ctx, fn_name, marker, timeout_s=90.0)
    assert log_events, f"expected lambda fan-out invocation with marker {marker}"
    payload = json.loads(log_events[0]["message"].split("EVENT_RECEIVED::", 1)[1])
    assert payload["detail"]["marker"] == marker, (
        f"lambda-delivered event carried marker {payload['detail'].get('marker')!r}, "
        f"expected {marker!r}"
    )

    messages = _wait_for_matching_message(ctx, queue_url, marker, timeout_s=90.0)
    assert messages, f"expected sns fan-out delivery with marker {marker}"
    event_obj = json.loads(messages[0]["Message"])
    assert event_obj["detail"]["marker"] == marker, (
        f"sns-delivered event carried marker {event_obj['detail'].get('marker')!r}, "
        f"expected {marker!r}"
    )


_LAMBDA_ECHO_CODE = """
import json

def handler(event, context):
    print("EVENT_RECEIVED::" + json.dumps(event))
    return {"received": True}
"""


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evtfan-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_echo_function(ctx, role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-evtfan-fn-")
    code = _zip_code(_LAMBDA_ECHO_CODE)
    resp = None
    last_err = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"function creation never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return name, resp["FunctionArn"]


def _create_topic(ctx):
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-evtfan-topic-")
    arn = sns.create_topic(Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])[
        "TopicArn"
    ]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue_subscribed_to_topic(ctx, topic_arn):
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    q_name = ctx.unique_name("sim2real-evtfan-queue-")
    url = sqs.create_queue(QueueName=q_name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return url


def _allow_events_to_invoke(
    ctx, function_name, rule_arn, statement_id="AllowEventBridgeInvoke"
):
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _allow_events_to_publish(ctx, topic_arn, rule_arn):
    sns = ctx.client("sns")
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    policy_doc = json.loads(attrs["Policy"])
    policy_doc["Statement"].append(
        {
            "Sid": "AllowEventBridgePublish",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "SNS:Publish",
            "Resource": topic_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }
    )
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(policy_doc),
    )


def _create_rule(ctx, source):
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-evtfan-rule-")
    pattern = json.dumps({"source": [source]})
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    rule_arn = resp["RuleArn"]

    def _cleanup():
        try:
            targets = events.list_targets_by_rule(Rule=rule_name).get("Targets", [])
            if targets:
                events.remove_targets(Rule=rule_name, Ids=[t["Id"] for t in targets])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup)
    return rule_name, rule_arn


def _wait_for_log_marker(ctx, function_name, marker, timeout_s=90.0, interval_s=5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(
                logGroupName=log_group, filterPattern=f'"{marker}"'
            )
            found = resp.get("events", [])
            if found:
                return found
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(interval_s)
    return []


def _wait_for_matching_message(ctx, queue_url, marker, timeout_s=90.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    matched = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for msg in resp.get("Messages", []):
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in envelope.get("Message", ""):
                matched.append(envelope)
        if matched:
            return matched
    return matched


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
