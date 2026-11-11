"""send-email-to-success-simulator-returns-message-id-and-a-delivery-event."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-email-to-success-simulator-returns-message-id-and-a-delivery-event"
GROUP = "eventing"
SERVICES = ["sesv2", "sns", "sqs"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_SUCCESS = "success@simulator.amazonses.com"

# ===== helpers =====


def _dns_baseline_domain(ctx, route53, sesv2):
    """The target's DNS baseline domain (its tagged public hosted zone, verified in SES); an account without one fails the check."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}; "
                    "verify it in SES before running this check"
                )
                return domain
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the baseline "
        "tag, verified in SES) and so no sending domain; the check requires one"
    )


def _drain_until(sqs, queue_url, want, timeout_s):
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and not want <= set(seen):
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("eventType"):
                seen.setdefault(event["eventType"], event)
    missing = want - set(seen)
    assert not missing, f"events {sorted(missing)} never arrived in {timeout_s}s; got {sorted(seen)}"
    return seen


# ===== end helpers =====


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """SendEmail to the simulator's success@ address returns a MessageId that reaches a configuration
    set's SNS->SQS destination twice, as the Send event and as the Delivery event carrying the
    SMTP response and delivered recipient: notifications published after the call returned.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-ses-success-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-ses-success-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub = sns.subscribe(
        TopicArn=topic_arn,
        Protocol="sqs",
        Endpoint=queue_arn,
        Attributes={"RawMessageDelivery": "true"},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub))

    config_set = ctx.unique_name("sim2real-xsvc-ses-success-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "DELIVERY"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [_SUCCESS]},
        Content={
            "Simple": {
                "Subject": {"Data": f"sim2real {CHECK}"},
                "Body": {"Text": {"Data": "sim2real success-simulator probe"}},
            }
        },
        ConfigurationSetName=config_set,
    )["MessageId"]
    assert len(message_id) > 10, f"SendEmail returned an implausible MessageId: {message_id!r}"

    events = _drain_until(sqs, queue_url, {"Send", "Delivery"}, timeout_s=180)

    send_mail = events["Send"]["mail"]
    assert send_mail["messageId"] == message_id, (
        f"the Send event names messageId {send_mail['messageId']!r}, not the one SendEmail "
        f"returned ({message_id!r})"
    )
    assert send_mail["destination"] == [_SUCCESS], (
        f"the Send event's destination is {send_mail['destination']!r}, expected [{_SUCCESS!r}]"
    )

    delivery = events["Delivery"]
    assert delivery["mail"]["messageId"] == message_id, (
        f"the Delivery event names messageId {delivery['mail']['messageId']!r}, not {message_id!r}"
    )
    assert delivery["delivery"]["recipients"] == [_SUCCESS], (
        f"Delivery.recipients is {delivery['delivery']['recipients']!r}, expected [{_SUCCESS!r}]"
    )
    assert delivery["delivery"]["smtpResponse"] == "250 Ok", (
        f"expected the mailbox simulator's documented '250 Ok' smtpResponse for success@, got "
        f"{delivery['delivery'].get('smtpResponse')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
