"""eventbridge-cloudfront-event-source-pattern-mismatch-suppressed."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-event-source-pattern-mismatch-suppressed"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule requiring source=sim2real.cloudfront delivers nothing for the same CloudTrail-shaped event with source
    sim2real.s3, while the event with the required source is delivered with its callerReference intact. (PutEvents
    refuses "aws."-prefixed sources, so "sim2real." sources stand in for aws.cloudfront and aws.s3.)"""
    account_id = _account_id(ctx)
    nonce = ctx.unique_name("cfsrcmismatch-")
    queue = _create_queue(ctx)

    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": ["CreateDistribution"],
            "requestParameters": {"distributionConfig": {"callerReference": [nonce]}},
        },
    }
    rule = _put_rule(ctx, pattern)
    _allow_events_to_sqs(ctx, queue["url"], queue["arn"], rule["arn"])
    _put_sqs_target(ctx, rule["name"], queue["arn"])

    request_parameters = {"distributionConfig": {"callerReference": nonce, "enabled": True}}
    response_elements = {"distribution": {"id": "E" + nonce.upper().replace("-", "")[:10]}}

    mismatched_detail = _cloudfront_event_detail(
        "CreateDistribution", request_parameters, response_elements, account_id
    )
    matching_detail = _cloudfront_event_detail(
        "CreateDistribution", request_parameters, response_elements, account_id
    )

    # Twin control in the same instant: the mismatched-source event is sent immediately
    # before the matching one, and absence is asserted over every message observed during
    # the SAME wait used to confirm the positive control's delivery -- not a fixed window
    # measured before that latency is known. A fixed window shorter than genuine
    # EventBridge/SQS delivery latency would score a target that eventually (and wrongly)
    # delivers the mismatched event as having correctly suppressed it, merely for being slow.
    _put_event(ctx, "sim2real.s3", mismatched_detail)  # wrong source: sim2real.s3 instead of sim2real.cloudfront
    _put_event(ctx, "sim2real.cloudfront", matching_detail)

    seen_messages: list[dict[str, Any]] = []

    def _probe():
        msgs = _receive_all(ctx, queue["url"], max_messages=5, wait_s=5)
        seen_messages.extend(msgs)
        match = next(
            (m for m in msgs if json.loads(m["Body"]).get("source") == "sim2real.cloudfront"), None
        )
        if match is None:
            # SQS queue-policy propagation can lag briefly; resend so a dropped first
            # delivery attempt (while the policy was still propagating) doesn't fail the check.
            _put_event(ctx, "sim2real.cloudfront", matching_detail)
        return match

    delivered = _wait_for_effect(
        _probe,
        lambda m: m is not None,
        timeout_s=90,
        interval_s=10,
        description="correctly-sourced event delivered to SQS",
    )
    body = json.loads(delivered["Body"])
    assert body["source"] == "sim2real.cloudfront", (
        f"expected delivered event source 'sim2real.cloudfront', got {body['source']!r}"
    )
    caller_ref = body["detail"]["requestParameters"]["distributionConfig"]["callerReference"]
    assert caller_ref == nonce, f"expected callerReference {nonce!r}, got {caller_ref!r}"

    mismatched_seen = [
        m["Body"] for m in seen_messages if json.loads(m["Body"]).get("source") == "sim2real.s3"
    ]
    assert mismatched_seen == [], f"rule delivered an event with a mismatched source: {mismatched_seen}"


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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cfevt-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _receive_all(ctx, queue_url, max_messages=5, wait_s=5) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


def _put_rule(ctx, pattern, bus_name="default") -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        EventBusName=bus_name,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))
    rule_arn = events.describe_rule(Name=rule_name, EventBusName=bus_name)["Arn"]
    return {"name": rule_name, "arn": rule_arn}


def _put_sqs_target(ctx, rule_name, queue_arn, bus_name="default") -> None:
    events = ctx.client("events")
    events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "target-1", "Arn": queue_arn}]
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["target-1"])
    )


def _allow_events_to_sqs(ctx, queue_url, queue_arn, rule_arn) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _cloudfront_event_detail(
    event_name, request_parameters, response_elements, account_id, recipient_account_id=None
) -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": f"arn:aws:iam::{account_id}:user/sim2real-behav",
            "accountId": account_id,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "userName": "sim2real-behav",
        },
        "eventTime": now,
        "eventSource": "cloudfront.amazonaws.com",
        "eventName": event_name,
        # CloudFront is a global service; CloudTrail always records its management-event
        # API calls as originating in us-east-1, regardless of the caller's region.
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0",
        "requestParameters": request_parameters,
        "responseElements": response_elements,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": recipient_account_id or account_id,
        "eventCategory": "Management",
    }


def _put_event(ctx, source, detail, bus_name="default") -> None:
    events = ctx.client("events")
    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(detail),
                "EventBusName": bus_name,
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
