"""eventbridge-cloudfront-event-detail-preserves-request-parameters."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "eventbridge-cloudfront-event-detail-preserves-request-parameters"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nested CloudTrail-shaped CreateDistribution event reaches an SQS target with requestParameters and
    responseElements equal to what was published: EventBridge does not truncate, flatten or alter nested detail."""
    account_id = _account_id(ctx)
    nonce = ctx.unique_name("cfformat-")
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

    request_parameters = {
        "distributionConfig": {
            "callerReference": nonce,
            "comment": "behavioral-fidelity-check",
            "enabled": True,
            "origins": {
                "quantity": 2,
                "items": [
                    {
                        "id": "origin-primary",
                        "domainName": "primary.example.com",
                        "customOriginConfig": {"httpPort": 80, "httpsPort": 443, "originProtocolPolicy": "https-only"},
                    },
                    {
                        "id": "origin-secondary",
                        "domainName": "secondary.example.com",
                        "customOriginConfig": {"httpPort": 80, "httpsPort": 443, "originProtocolPolicy": "https-only"},
                    },
                ],
            },
            "defaultCacheBehavior": {"targetOriginId": "origin-primary", "viewerProtocolPolicy": "redirect-to-https"},
            "priceClass": "PriceClass_100",
        }
    }
    distribution_id = "E" + nonce.upper().replace("-", "")[:13]
    response_elements = {
        "distribution": {
            "id": distribution_id,
            "aRN": f"arn:aws:cloudfront::{account_id}:distribution/{distribution_id}",
            "status": "InProgress",
            "lastModifiedTime": "2024-01-01T00:00:00.000Z",
            "inProgressInvalidationBatches": 0,
        }
    }

    detail = _cloudfront_event_detail(
        "CreateDistribution", request_parameters, response_elements, account_id
    )
    _put_event(ctx, "sim2real.cloudfront", detail)

    def _probe():
        msg = _first_message(ctx, queue["url"])
        if msg is None:
            # SQS queue-policy propagation can lag briefly; resend so a dropped first
            # delivery attempt (while the policy was still propagating) doesn't fail the check.
            _put_event(ctx, "sim2real.cloudfront", detail)
        return msg

    delivered = _wait_for_effect(
        _probe,
        lambda m: m is not None,
        timeout_s=90,
        interval_s=10,
        description="event delivered verbatim to SQS",
    )
    body = json.loads(delivered["Body"])
    assert body["detail"]["requestParameters"] == request_parameters, (
        f"requestParameters mutated in transit: expected {request_parameters!r}, "
        f"got {body['detail']['requestParameters']!r}"
    )
    assert body["detail"]["responseElements"] == response_elements, (
        f"responseElements mutated in transit: expected {response_elements!r}, "
        f"got {body['detail']['responseElements']!r}"
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
        # CloudFront is a global service; real CloudTrail always records its
        # management events with awsRegion "us-east-1", regardless of where this
        # check runs.
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
