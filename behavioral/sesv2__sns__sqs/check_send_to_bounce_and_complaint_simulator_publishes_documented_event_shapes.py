"""send-to-bounce-and-complaint-simulator-publishes-documented-event-shapes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-to-bounce-and-complaint-simulator-publishes-documented-event-shapes"
GROUP = "eventing"
SERVICES = ["sesv2", "sns", "sqs"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_BOUNCE = "bounce@simulator.amazonses.com"
_COMPLAINT = "complaint@simulator.amazonses.com"

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
    "concern:representation",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """Sends to the simulator's bounce@ and complaint@ addresses publish, on one SNS->SQS
    destination, a Bounce event matching the documented 550 5.1.1 permanent bounce and a Complaint
    event naming an abuse feedback type with the simulator's userAgent.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-ses-bc-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-ses-bc-"))["QueueUrl"]
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

    config_set = ctx.unique_name("sim2real-xsvc-ses-bc-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["BOUNCE", "COMPLAINT"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    def _send(to_address: str, subject: str) -> str:
        return sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [to_address]},
            Content={"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": "x"}}}},
            ConfigurationSetName=config_set,
        )["MessageId"]

    bounce_message_id = _send(_BOUNCE, f"sim2real {CHECK} bounce")
    complaint_message_id = _send(_COMPLAINT, f"sim2real {CHECK} complaint")

    events = _drain_until(sqs, queue_url, {"Bounce", "Complaint"}, timeout_s=180)

    bounce_evt = events["Bounce"]
    assert bounce_evt["mail"]["messageId"] == bounce_message_id, (
        f"the Bounce event names messageId {bounce_evt['mail']['messageId']!r}, not "
        f"{bounce_message_id!r}"
    )
    bounce = bounce_evt["bounce"]
    assert bounce["bounceType"] == "Permanent", (
        f"expected bounceType 'Permanent' for bounce@, got {bounce.get('bounceType')!r}"
    )
    assert bounce["bounceSubType"] == "General", (
        f"expected bounceSubType 'General' for bounce@, got {bounce.get('bounceSubType')!r}"
    )
    recipients = bounce["bouncedRecipients"]
    assert len(recipients) == 1, f"expected exactly 1 bounced recipient, got {recipients!r}"
    recipient = recipients[0]
    assert recipient["emailAddress"] == _BOUNCE, (
        f"bouncedRecipients[0].emailAddress is {recipient.get('emailAddress')!r}, expected {_BOUNCE!r}"
    )
    assert recipient["status"] == "5.1.1", (
        f"expected bounce status '5.1.1', got {recipient.get('status')!r}"
    )
    assert "550" in recipient["diagnosticCode"], (
        f"expected the documented SMTP 550 in diagnosticCode, got {recipient.get('diagnosticCode')!r}"
    )

    complaint_evt = events["Complaint"]
    assert complaint_evt["mail"]["messageId"] == complaint_message_id, (
        f"the Complaint event names messageId {complaint_evt['mail']['messageId']!r}, not "
        f"{complaint_message_id!r}"
    )
    complaint = complaint_evt["complaint"]
    assert complaint["complaintFeedbackType"] == "abuse", (
        f"expected complaintFeedbackType 'abuse' for complaint@, got "
        f"{complaint.get('complaintFeedbackType')!r}"
    )
    assert complaint["userAgent"] == "Amazon SES Mailbox Simulator", (
        f"expected userAgent 'Amazon SES Mailbox Simulator', got {complaint.get('userAgent')!r}"
    )
    complained = complaint["complainedRecipients"]
    assert len(complained) == 1, f"expected exactly 1 complained recipient, got {complained!r}"
    assert complained[0]["emailAddress"] == _COMPLAINT, (
        f"complainedRecipients[0].emailAddress is {complained[0].get('emailAddress')!r}, expected "
        f"{_COMPLAINT!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
