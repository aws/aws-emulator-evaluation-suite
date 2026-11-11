"""redshift-parameter-group-event-sqs-notification-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "redshift-parameter-group-event-sqs-notification-positive"
GROUP = "event-propagation"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Redshift-shaped ModifyClusterParameterGroup event injected with PutEvents is delivered to SQS
    with its eventName, requestParameters and parameterGroupStatus "applying" intact."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_name = ctx.unique_name("sim2real-rs-pg-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-rs-pg-rule-")
    pattern = {
        "source": ["sim2real.redshift"],

        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["redshift.amazonaws.com"],
            "eventName": ["ModifyClusterParameterGroup"],
        },
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
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

    pg_name = ctx.unique_name("sim2real-rs-pg-")
    detail = {
        "eventVersion": "1.08",
        "eventSource": "redshift.amazonaws.com",
        "eventName": "ModifyClusterParameterGroup",
        "awsRegion": ctx.region,
        "requestParameters": {
            "parameterGroupName": pg_name,
            "parameters": [
                {"parameterName": "wlm_json_configuration", "parameterValue": "[]"}
            ],
        },
        "responseElements": {
            "parameterGroupName": pg_name,
            "parameterGroupStatus": "applying",
        },
    }
    entry = {
        "Source": "sim2real.redshift",

        "DetailType": "AWS API Call via CloudTrail",
        "Detail": json.dumps(detail),
        "Resources": [
            f"arn:aws:redshift:{ctx.region}:{account_id}:parametergroup:{pg_name}"
        ],
        "EventBusName": "default",
    }

    msg = _send_and_wait(
        events,
        sqs,
        queue_url,
        entry,
        lambda d: d.get("detail", {}).get("requestParameters", {}).get(
            "parameterGroupName"
        )
        == pg_name,
        attempts=4,
        poll_s=30,
    )
    assert msg is not None, "parameter-group modification event was never delivered to SQS"
    assert msg["detail"]["eventName"] == "ModifyClusterParameterGroup", (
        f"expected eventName ModifyClusterParameterGroup, got {msg['detail'].get('eventName')!r}"
    )
    assert (
        msg["detail"]["requestParameters"]["parameters"][0]["parameterName"]
        == "wlm_json_configuration"
    ), (
        "expected requestParameters.parameters[0].parameterName wlm_json_configuration, got "
        f"{msg['detail']['requestParameters']['parameters'][0].get('parameterName')!r}"
    )
    assert msg["detail"]["responseElements"]["parameterGroupStatus"] == "applying", (
        "expected responseElements.parameterGroupStatus applying, got "
        f"{msg['detail']['responseElements'].get('parameterGroupStatus')!r}"
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
