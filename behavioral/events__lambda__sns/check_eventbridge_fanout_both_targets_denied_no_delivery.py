"""eventbridge-fanout-both-targets-denied-no-delivery."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-fanout-both-targets-denied-no-delivery"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matching fan-out rule whose Lambda and SNS targets grant events.amazonaws.com nothing
    invokes and publishes nothing, while direct invoke and publish controls show both observers
    detect delivery."""
    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_echo_function(ctx, role_arn)
    topic_arn = _create_topic(ctx)
    queue_url = _create_queue_subscribed_to_topic(ctx, topic_arn)

    # Positive control 1: invoke the function directly (not via EventBridge) to prove the
    # log-observation mechanism would have caught an invocation had one occurred.
    lam = ctx.client("lambda")
    control_marker = ctx.unique_name("control-lambda-marker-")
    lam.invoke(
        FunctionName=fn_name,
        InvocationType="Event",
        Payload=json.dumps({"detail": {"marker": control_marker}}).encode("utf-8"),
    )
    control_log_events = _wait_for_log_marker(ctx, fn_name, control_marker, timeout_s=60.0)
    assert control_log_events, "positive control direct invoke was never observed in logs"

    # Positive control 2: publish directly to the topic (as owner) to prove the SQS
    # observation mechanism would have caught a publish had one occurred.
    sns = ctx.client("sns")
    control_sns_marker = ctx.unique_name("control-sns-marker-")
    sns.publish(TopicArn=topic_arn, Message=json.dumps({"marker": control_sns_marker}))
    control_messages = _wait_for_matching_message(
        ctx, queue_url, control_sns_marker, timeout_s=60.0
    )
    assert control_messages, "positive control direct publish was never observed on queue"

    source = ctx.unique_name("sim2real.evtbothdeny.src-")
    rule_name, rule_arn = _create_rule(ctx, source)
    # Deliberately break both things: no lambda resource-policy grant, no topic-policy grant.
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

    log_events = _wait_for_log_marker(ctx, fn_name, marker, timeout_s=45.0)
    assert log_events == [], f"lambda was invoked despite missing resource policy: {log_events!r}"

    messages = _wait_for_matching_message(ctx, queue_url, marker, timeout_s=45.0)
    assert messages == [], f"sns received a publish despite missing topic policy: {messages!r}"


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evtbd-role-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    name = ctx.unique_name("sim2real-evtbd-fn-")
    code = _zip_code(_LAMBDA_ECHO_CODE)
    resp = None
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": CHECK},
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
    name = ctx.unique_name("sim2real-evtbd-topic-")
    arn = sns.create_topic(
        Name=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue_subscribed_to_topic(ctx, topic_arn):
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    q_name = ctx.unique_name("sim2real-evtbd-queue-")
    url = sqs.create_queue(QueueName=q_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
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
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    return url


def _create_rule(ctx, source):
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-evtbd-rule-")
    pattern = json.dumps({"source": [source]})
    resp = events.put_rule(Name=rule_name, EventPattern=pattern, State="ENABLED")
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
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
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
