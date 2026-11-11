"""eventbridge-cloudfront-event-wrong-account-id-not-matched."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-event-wrong-account-id-not-matched"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c1", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule filtering on detail.recipientAccountId delivers nothing for a CloudFront event naming another account,
    while the same event naming the caller's account is delivered with that account id. (PutEvents refuses
    "aws."-prefixed sources, so sim2real.cloudfront stands in for aws.cloudfront.)"""
    real_account = _account_id(ctx)
    fake_account = "999999999999" if real_account != "999999999999" else "888888888888"
    nonce = ctx.unique_name("cfacct-")
    queue = _create_queue(ctx)

    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": ["CreateDistribution"],
            "requestParameters": {"distributionConfig": {"callerReference": [nonce]}},
            "recipientAccountId": [real_account],
        },
    }
    rule = _put_rule(ctx, pattern)
    _allow_events_to_sqs(ctx, queue["url"], queue["arn"], rule["arn"])
    _put_sqs_target(ctx, rule["name"], queue["arn"])

    request_parameters = {"distributionConfig": {"callerReference": nonce, "enabled": True}}
    response_elements = {"distribution": {"id": "E" + nonce.upper().replace("-", "")[:10]}}

    mismatched_detail = _cloudfront_event_detail(
        "CreateDistribution",
        request_parameters,
        response_elements,
        real_account,
        recipient_account_id=fake_account,
    )
    _put_event(ctx, "sim2real.cloudfront", mismatched_detail)

    absence = _poll_for_absence(ctx, queue["url"], window_s=40, wait_s=5)
    assert absence == [], f"rule delivered an event with a mismatched recipientAccountId: {absence}"

    matching_detail = _cloudfront_event_detail(
        "CreateDistribution",
        request_parameters,
        response_elements,
        real_account,
        recipient_account_id=real_account,
    )
    _put_event(ctx, "sim2real.cloudfront", matching_detail)

    delivered = _wait_for_effect(
        lambda: _first_message(ctx, queue["url"]),
        lambda m: m is not None,
        timeout_s=60,
        interval_s=5,
        description="matching-account event delivered to SQS",
    )
    body = json.loads(delivered["Body"])
    assert body["detail"]["recipientAccountId"] == real_account, (
        f"expected delivered event's recipientAccountId to be {real_account}, "
        f"got {body['detail'].get('recipientAccountId')}"
    )


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
        QueueName=ctx.unique_name("sim2real-cfevt-q-"), tags={"sim2real": CHECK}
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


def _first_message(ctx, queue_url):
    msgs = _receive_all(ctx, queue_url, max_messages=5, wait_s=5)
    return msgs[0] if msgs else None


def _poll_for_absence(ctx, queue_url, window_s=40.0, wait_s=5) -> list[dict[str, Any]]:
    deadline = time.monotonic() + window_s
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        seen.extend(_receive_all(ctx, queue_url, max_messages=5, wait_s=wait_s))
        if seen:
            break
    return seen


def _put_rule(ctx, pattern, bus_name="default") -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        EventBusName=bus_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        # CloudFront's management API is global; CloudTrail always attributes its events to
        # us-east-1 regardless of the caller's region, so this is pinned rather than ctx.region.
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
