"""send-bulk-email-per-entry-replacement-headers-override-the-template-default."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-bulk-email-per-entry-replacement-headers-override-the-template-default"
GROUP = "eventing"
SERVICES = ["sesv2", "sns", "sqs"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_RECIPIENT_OVERRIDE = "success@simulator.amazonses.com"
_RECIPIENT_DEFAULT = "ooto@simulator.amazonses.com"



def _sending_domain(ctx, route53, sesv2):
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
                    f"the DNS baseline domain {domain!r} is not verified for sending in "
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r})"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


def _drain_by_recipient(sqs, queue_url, want_recipients, timeout_s):
    """Collect one Send event per recipient in ``want_recipients``; RAISE on deadline with
    what did arrive. Keyed by destination rather than by count, since SendBulkEmail fans out
    one Send event per entry and this check must tell the two entries apart."""
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and not want_recipients <= set(seen):
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                continue
            if not isinstance(event, dict) or event.get("eventType") != "Send":
                continue
            destinations = event.get("mail", {}).get("destination", [])
            for recipient in want_recipients:
                if recipient in destinations:
                    seen[recipient] = event
    missing = want_recipients - set(seen)
    assert not missing, (
        f"Send events for {sorted(missing)} never arrived in {timeout_s}s; got {sorted(seen)}"
    )
    return seen


def _header_value(event, name):
    for h in event["mail"].get("headers", []):
        if h.get("name") == name:
            return h.get("value")
    return None




@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """In SendBulkEmail, one entry's ReplacementHeaders override the template's default header for
    that message only; a sibling entry keeps the default, as seen in each entry's Send event.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _sending_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-ses-bulkhdr-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-ses-bulkhdr-"),
        tags={"sim2real": "true"},
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

    config_set = ctx.unique_name("sim2real-ses-bulkhdr-")
    sesv2.create_configuration_set(
        ConfigurationSetName=config_set, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-bulkhdr",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    resp = sesv2.send_bulk_email(
        FromEmailAddress=sender,
        ConfigurationSetName=config_set,
        DefaultContent={
            "Template": {
                "TemplateContent": {
                    "Subject": f"sim2real {CHECK}",
                    "Text": "bulk body",
                },
                "TemplateData": "{}",
                "Headers": [{"Name": "X-Mailer", "Value": "default"}],
            }
        },
        BulkEmailEntries=[
            {
                "Destination": {"ToAddresses": [_RECIPIENT_OVERRIDE]},
                "ReplacementHeaders": [{"Name": "X-Mailer", "Value": "override"}],
            },
            {
                "Destination": {"ToAddresses": [_RECIPIENT_DEFAULT]},
            },
        ],
    )["BulkEmailEntryResults"]
    assert len(resp) == 2 and all(r.get("Status") == "SUCCESS" for r in resp), (
        f"expected both bulk entries to succeed, got {resp!r}"
    )

    events = _drain_by_recipient(
        sqs, queue_url, {_RECIPIENT_OVERRIDE, _RECIPIENT_DEFAULT}, timeout_s=300
    )

    override_header = _header_value(events[_RECIPIENT_OVERRIDE], "X-Mailer")
    assert override_header == "override", (
        f"the entry with its own ReplacementHeaders must carry X-Mailer=override in its "
        f"resolved mail.headers; got {override_header!r}"
    )

    default_header = _header_value(events[_RECIPIENT_DEFAULT], "X-Mailer")
    assert default_header == "default", (
        f"the sibling entry with no ReplacementHeaders must keep the template's default "
        f"X-Mailer=default in its resolved mail.headers; got {default_header!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
