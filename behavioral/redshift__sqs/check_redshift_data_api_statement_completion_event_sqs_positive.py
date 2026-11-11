"""redshift-data-api-statement-completion-event-sqs-positive."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-data-api-statement-completion-event-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift Data statement-completion event injected with PutEvents is delivered by the matching
    rule to SQS with statementId, state FINISHED, rows 1 and statementName intact."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_name = ctx.unique_name("sim2real-rs-dataapi-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-dataapi-rule-")
    pattern = {
        "source": ["sim2real.redshift-data"],
        "detail-type": ["Redshift Data Statement Status Change"],
        "detail": {"state": ["FINISHED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]

    def _cleanup_rule():
        events.remove_targets(Rule=rule_name, Ids=["1"])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_cleanup_rule)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])

    cluster_id = ctx.unique_name("sim2real-rs-cluster-")
    statement_id = str(uuid.uuid4())
    detail = {
        "principal": f"arn:aws:iam::{account_id}:user/sim2real-test",
        "statementName": "sim2real.testtable",
        "statementId": statement_id,
        "redshiftQueryId": -1,
        "state": "FINISHED",
        "rows": 1,
        "expireAt": int(time.time()) + 86400,
    }
    entry = {
        "Source": "sim2real.redshift-data",

        "DetailType": "Redshift Data Statement Status Change",
        "Detail": json.dumps(detail),
        "Resources": [
            f"arn:aws:redshift:{ctx.region}:{account_id}:cluster:{cluster_id}"
        ],
        "EventBusName": "default",
    }

    msg = _send_and_wait(
        events,
        sqs,
        queue_url,
        entry,
        lambda d: d.get("detail", {}).get("statementId") == statement_id,
        attempts=4,
        poll_s=30,
    )
    assert msg is not None, "Data API statement-completion event was never delivered to SQS"
    assert msg["detail"]["statementId"] == statement_id, (
        f"delivered message carries statementId={msg['detail'].get('statementId')!r}, "
        f"expected {statement_id!r}"
    )
    assert msg["detail"]["state"] == "FINISHED", (
        f"expected state FINISHED, got {msg['detail'].get('state')!r}"
    )
    assert msg["detail"]["rows"] == 1, f"expected rows == 1, got {msg['detail'].get('rows')!r}"
    assert msg["detail"]["statementName"] == "sim2real.testtable", (
        f"expected statementName 'sim2real.testtable', got {msg['detail'].get('statementName')!r}"
    )


def _wait_for_matching_message(sqs, queue_url, predicate, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body: dict[str, Any] = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if predicate(body):
                return body
    return None


def _send_and_wait(events, sqs, queue_url, entry, predicate, attempts=4, poll_s=30):
    """EventBridge rule/target/queue-policy wiring is eventually consistent on
    real AWS (propagation can lag well past a single short poll window).
    Re-inject the same event across several windows instead of guessing one
    fixed delay -- each re-send is a no-op from the assertion's perspective
    since the predicate matches on a unique id embedded in the event."""
    for _ in range(attempts):
        events.put_events(Entries=[entry])
        msg = _wait_for_matching_message(sqs, queue_url, predicate, timeout_s=poll_s)
        if msg is not None:
            return msg
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
