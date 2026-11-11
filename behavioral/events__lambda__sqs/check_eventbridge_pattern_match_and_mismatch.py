"""eventbridge-pattern-match-and-mismatch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-pattern-match-and-mismatch"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule's EventPattern is selective: a PutEvents entry that matches is delivered to the
    target queue, and a distinct non-matching entry sent on the same bus/rule is never
    delivered."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue = _create_queue(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": ["sim2real.selective"], "detail-type": ["Matched"]}
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue["url"], Attributes={"Policy": json.dumps(policy)})

    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    # A freshly-applied SQS resource policy is not immediately effective, and EventBridge drops
    # (never retries) what it cannot yet deliver -- which would look exactly like the absence
    # below for the wrong reason. Warm the path up on the SAME rule/target/queue until a
    # matching event actually lands, so the absence assertion is attributable to the pattern.
    _warm_up_delivery(events, sqs, queue["url"], timeout_s=90.0, interval_s=3.0)

    # Non-matching entry: different detail-type -> must not be delivered.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.selective",
                "DetailType": "NotMatched",
                "Detail": json.dumps({"tag": "mismatch"}),
            }
        ]
    )
    _assert_no_message(sqs, queue["url"], timeout_s=20.0)

    # Matching entry -> must be delivered.
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.selective",
                "DetailType": "Matched",
                "Detail": json.dumps({"tag": "match"}),
            }
        ]
    )
    messages = _poll_until(
        lambda: _drain(sqs, queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    body = json.loads(messages[0]["Body"])
    assert body["detail-type"] == "Matched", (
        f"expected the delivered message's detail-type to be 'Matched', got {body['detail-type']!r}"
    )
    assert body["detail"] == {"tag": "match"}, (
        f"expected the delivered message's detail to be {{'tag': 'match'}}, got {body['detail']!r}"
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
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _warm_up_delivery(events, sqs, url, timeout_s=90.0, interval_s=3.0):
    """Publish throwaway matching events until one actually lands on the queue, proving the
    rule/target/queue-policy path is live. Raises AssertionError if it never comes up."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.selective",
                    "DetailType": "Matched",
                    "Detail": json.dumps({"tag": "warmup"}),
                }
            ]
        )
        msgs = _drain(sqs, url, wait=int(interval_s))
        if msgs:
            for m in msgs:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"no warm-up event reached {url} within {timeout_s}s; the rule/target/queue-policy path "
        f"never came up, so no later absence could be attributed to pattern matching"
    )


def _assert_no_message(sqs, url, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = _drain(sqs, url, wait=5)
        if msgs:
            raise AssertionError(f"unexpected delivery of non-matching event: {msgs}")
        time.sleep(1)


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
