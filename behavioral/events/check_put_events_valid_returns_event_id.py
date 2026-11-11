"""put-events-valid-returns-event-id."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "put-events-valid-returns-event-id"
GROUP = 'put-events'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents with a well-formed entry succeeds, returns a real EventId, and that
    exact id shows up on an independent read at the destination -- the id a rule-matched
    SQS target receives, not merely the value the mutating call echoed back."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    source = ctx.unique_name("sim2real.valid.")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps({"source": [source]})
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
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
            )
        },
    )

    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    resp = events.put_events(
        Entries=[{"Source": source, "DetailType": "test", "Detail": "{}"}]
    )
    assert resp.get("FailedEntryCount", 0) == 0, f"expected success, got {resp}"
    entry = resp["Entries"][0]
    event_id = entry.get("EventId")
    assert event_id, "successful entry must have an EventId"

    envelope = _poll_for_id(sqs, queue_url, event_id, timeout_s=60.0)
    assert envelope["id"] == event_id, (
        f"delivered envelope id {envelope.get('id')!r} != returned EventId {event_id!r}"
    )
    assert envelope["source"] == source, f"expected source {source!r}, got {envelope.get('source')!r}"


def _poll_for_id(sqs, queue_url: str, event_id: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("id") == event_id:
                return body
    raise AssertionError(f"event {event_id} was never delivered to {queue_url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
