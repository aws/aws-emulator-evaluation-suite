"""put-events-unicode-detail-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-events-unicode-detail-round-trip"
GROUP = "representation"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutEvents Detail with multi-byte unicode (Japanese, Cyrillic, emoji, accented Latin) is
    delivered to a rule-matched SQS target with every string preserved exactly."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    source = ctx.unique_name("sim2real.unicode.")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source]}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

    targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert any(t["Arn"] == queue_arn for t in targets), (
        f"expected target {queue_arn!r} in rule targets, got {[t.get('Arn') for t in targets]!r}"
    )

    nonce = ctx.unique_name("n-")
    detail = {
        "nonce": nonce,
        "japanese": "こんにちは世界",
        "cyrillic": "Привет мир",
        "emoji": "🚀🎉✨",
        "accented": "Café résumé naïve",
        "mixed": "AWS-イベント-🔥-тест",
    }
    resp = events.put_events(
        Entries=[{"Source": source, "DetailType": "sim2real-unicode-test", "Detail": json.dumps(detail)}]
    )
    assert resp["FailedEntryCount"] == 0, resp["Entries"]

    delivered = _wait_for_detail(sqs, queue_url, nonce, timeout_s=30.0)
    for key, value in detail.items():
        assert delivered[key] == value, f"field {key!r} drifted: sent {value!r} got {delivered[key]!r}"


def _wait_for_detail(sqs: Any, queue_url: str, nonce: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        for msg in received:
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = body.get("detail", {})
            if detail.get("nonce") == nonce:
                return detail
        time.sleep(0.5)
    raise AssertionError("unicode-detail event was never delivered to the queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
