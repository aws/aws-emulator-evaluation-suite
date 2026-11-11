"""put-events-numeric-precision-preserved."""
from __future__ import annotations

import decimal
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-events-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents Detail integers beyond float64 precision (±int64 max) and the double nearest pi
    reach a rule-matched SQS target with their exact values, not rounded through a float."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    source = ctx.unique_name("sim2real.numeric.")
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

    nonce = ctx.unique_name("n-")
    # int64 max fits a signed 64-bit integer but exceeds the 53-bit float64 mantissa, so any
    # float round-trip truncates it. repr(math.pi) round-trips exactly through a double.
    big_int_text = "9223372036854775807"
    big_decimal_text = "3.141592653589793"
    detail_json = (
        '{"nonce": "%s", "big_int": %s, "big_decimal": %s, "negative_big_int": -%s}'
        % (nonce, big_int_text, big_decimal_text, big_int_text)
    )
    assert big_int_text != str(int(float(big_int_text))), (
        f"fixture is not a precision test: {big_int_text!r} round-trips through float64 unchanged"
    )

    resp = events.put_events(
        Entries=[{"Source": source, "DetailType": "sim2real-numeric-test", "Detail": detail_json}]
    )
    assert resp["FailedEntryCount"] == 0, resp["Entries"]

    delivered = _wait_for_detail(sqs, queue_url, nonce, timeout_s=30.0)

    assert delivered["big_int"] == decimal.Decimal(big_int_text), (
        f"big_int drifted: sent {big_int_text!r}, delivered {delivered['big_int']!r}"
    )
    assert delivered["negative_big_int"] == -decimal.Decimal(big_int_text), (
        f"negative_big_int drifted: sent -{big_int_text!r}, delivered {delivered['negative_big_int']!r}"
    )
    assert delivered["big_decimal"] == decimal.Decimal(big_decimal_text), (
        f"big_decimal drifted: sent {big_decimal_text!r}, delivered {delivered['big_decimal']!r}"
    )



def _wait_for_detail(sqs: Any, queue_url: str, nonce: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        for msg in received:
            body = json.loads(msg["Body"], parse_float=decimal.Decimal, parse_int=decimal.Decimal)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = body.get("detail", {})
            if detail.get("nonce") == nonce:
                return detail
        time.sleep(0.5)
    raise AssertionError("numeric-precision event was never delivered to the queue")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
