"""send-raw-email-preserves-custom-headers-exactly-in-the-published-event."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-raw-email-preserves-custom-headers-exactly-in-the-published-event"
GROUP = "data-format"
SERVICES = ["sesv2", "sns", "sqs"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_SUCCESS = "success@simulator.amazonses.com"



def _dns_baseline_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
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
                    f"the DNS baseline domain {domain!r} is not verified in {ctx.region}"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
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



_CUSTOM_HEADER_NAME = "X-SimParity-Probe"
_CUSTOM_HEADER_VALUE = "sim2real-raw-mime-exactness-probe"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A raw-MIME SendEmail's headers, including a custom X- header, reach the published Send
    event (SNS -> SQS) with the exact values, order and casing the caller wrote.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-ses-rawmime-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-ses-rawmime-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
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

    config_set = ctx.unique_name("sim2real-xsvc-ses-rawmime-")
    sesv2.create_configuration_set(
        ConfigurationSetName=config_set,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"
    subject = f"sim2real {CHECK}"
    raw_mime = (
        f"From: {sender}\r\n"
        f"To: {_SUCCESS}\r\n"
        f"Subject: {subject}\r\n"
        f"{_CUSTOM_HEADER_NAME}: {_CUSTOM_HEADER_VALUE}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=UTF-8\r\n"
        f"\r\n"
        f"sim2real raw mime probe body\r\n"
    )
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [_SUCCESS]},
        Content={"Raw": {"Data": raw_mime.encode("utf-8")}},
        ConfigurationSetName=config_set,
    )["MessageId"]
    assert len(message_id) > 10, f"SendEmail returned an implausible MessageId: {message_id!r}"

    events = _drain_until(sqs, queue_url, {"Send"}, timeout_s=120)
    mail = events["Send"]["mail"]
    assert mail["messageId"] == message_id, (
        f"the Send event names messageId {mail['messageId']!r}, not {message_id!r}"
    )

    # SES may add headers of its own (Message-ID, Date); the caller's six keep their relative
    # order and their exact casing among whatever else is published.
    written = ["From", "To", "Subject", _CUSTOM_HEADER_NAME, "MIME-Version", "Content-Type"]
    published_order = [h["name"] for h in mail["headers"] if h["name"] in written]
    assert published_order == written, (
        f"the caller's headers were not published in the order and casing written: expected "
        f"{written!r}, got {published_order!r} from {[h['name'] for h in mail['headers']]!r}"
    )

    headers = {h["name"]: h["value"] for h in mail["headers"]}
    assert headers.get(_CUSTOM_HEADER_NAME) == _CUSTOM_HEADER_VALUE, (
        f"custom header {_CUSTOM_HEADER_NAME!r} was not preserved exactly: published headers were "
        f"{mail['headers']!r}"
    )
    assert headers.get("Subject") == subject, (
        f"Subject header was not preserved exactly: got {headers.get('Subject')!r}, "
        f"expected {subject!r}"
    )
    assert headers.get("Content-Type") == "text/plain; charset=UTF-8", (
        f"Content-Type header was not preserved exactly: got {headers.get('Content-Type')!r}"
    )

    common = mail["commonHeaders"]
    assert common["subject"] == subject, (
        f"commonHeaders.subject is {common.get('subject')!r}, expected {subject!r}"
    )
    assert common["messageId"] == message_id, (
        f"commonHeaders.messageId is {common.get('messageId')!r}, expected {message_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
