"""eventbridge-sqs-target-missing-queue-policy-dlq."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-sqs-target-missing-queue-policy-dlq"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SQS target without a queue policy never receives the event; it goes to the target DLQ
    with ERROR_CODE NO_RESOURCE, its exact message and the target ARN, and the policy then lets
    the next event through."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    target_queue = _create_queue(ctx)
    dlq = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.sqsdlqtest"], "detail-type": ["Attempt"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern))["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": dlq["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=dlq["url"], Attributes={"Policy": json.dumps(dlq_policy)})

    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "t1", "Arn": target_queue["arn"], "DeadLetterConfig": {"Arn": dlq["arn"]}}
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # --- Negative path: target queue has no policy granting EventBridge access yet.
    # The DLQ's own policy was just set and its propagation exposes no condition to poll other than
    # delivery itself, so each poll re-sends a fresh event until one is dead-lettered.
    sent = {"n": 0}

    def _send_and_drain():
        sent["n"] += 1
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.sqsdlqtest",
                    "DetailType": "Attempt",
                    "Detail": json.dumps({"attempt": 1, "send": sent["n"]}),
                }
            ]
        )
        return _drain(sqs, dlq["url"], wait=5)

    dlq_messages = _poll_until(
        _send_and_drain,
        lambda msgs: len(msgs) >= 1,
        timeout_s=180.0,
        interval_s=0.0,
    )
    attrs = dlq_messages[0]["MessageAttributes"]
    error_code = attrs["ERROR_CODE"]["StringValue"]
    # The message embeds SQS's per-request id (environment-dependent), so only that id is masked.
    error_message = re.sub(r"Request ID: [0-9a-f-]+;", "Request ID: <id>;",
                           attrs["ERROR_MESSAGE"]["StringValue"])
    expected_message = (
        "The specified queue does not exist or you do not have access to it. (Service: AmazonSQS; "
        "Status Code: 400; Error Code: AWS.SimpleQueueService.NonExistentQueue; "
        "Request ID: <id>; Proxy: null)"
    )
    assert (error_code, error_message) == ("NO_RESOURCE", expected_message), (
        f"expected DLQ message attributes ERROR_CODE=NO_RESOURCE / ERROR_MESSAGE={expected_message!r} "
        f"for a target queue with no resource policy, got {error_code!r} / {error_message!r}"
    )
    target_arn = attrs["TARGET_ARN"]["StringValue"]
    assert target_arn == target_queue["arn"], (
        f"expected DLQ message TARGET_ARN to name the unreachable target {target_queue['arn']!r}, "
        f"got {target_arn!r}"
    )

    # Effect is absent: the target queue never received the event.
    leaked = _drain(sqs, target_queue["url"], wait=5)
    assert leaked == [], (
        f"target queue with no resource policy should never receive the event; got {leaked!r}"
    )

    # --- Positive control: attach the queue policy and retry with a distinct payload.
    target_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": target_queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(
        QueueUrl=target_queue["url"], Attributes={"Policy": json.dumps(target_policy)}
    )

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.sqsdlqtest",
                "DetailType": "Attempt",
                "Detail": json.dumps({"attempt": 2}),
            }
        ]
    )

    delivered = _poll_until(
        lambda: _drain(sqs, target_queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    body = json.loads(delivered[0]["Body"])
    assert body["detail"] == {"attempt": 2}, (
        f"expected the target queue to receive the retried event detail after the policy fix, "
        f"got {body.get('detail')!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(
        QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait, MessageAttributeNames=["All"]
    )
    return resp.get("Messages", [])


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
