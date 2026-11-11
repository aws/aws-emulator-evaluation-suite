"""event-destination-disabled-publishes-no-events."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "event-destination-disabled-publishes-no-events"
GROUP = "eventing"
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


def _drain_once(sqs, queue_url, timeout_s):
    """Collect every SES event visible within ``timeout_s``; never raises -- an empty result is
    a legitimate (and here, the expected) outcome."""
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", [])
        if not messages:
            continue
        for m in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("eventType"):
                seen.append(event)
    return seen


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
    assert not missing, (
        f"events {sorted(missing)} never arrived in {timeout_s}s; got {sorted(seen)}"
    )
    return seen




@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """An event destination with Enabled=False publishes no event for a send, and the same
    destination re-enabled publishes the Send event for the next send through that set.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-ses-evtgate-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-ses-evtgate-"))["QueueUrl"]
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

    config_set = ctx.unique_name("sim2real-xsvc-ses-evtgate-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-gate",
        EventDestination={
            "Enabled": False,
            "MatchingEventTypes": ["SEND", "DELIVERY"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    def _send(subject: str) -> str:
        return sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [_SUCCESS]},
            Content={"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": "x"}}}},
            ConfigurationSetName=config_set,
        )["MessageId"]

    disabled_message_id = _send(f"sim2real {CHECK} disabled")
    assert len(disabled_message_id) > 10, (
        f"SendEmail must still return a real MessageId while the destination is disabled; got "
        f"{disabled_message_id!r}"
    )

    # SES reads Enabled at publish time, so a bounded wait for absence is not racing propagation.
    # The SNS topic-validation notice has no eventType and is dropped by _drain_once.
    leaked = _drain_once(sqs, queue_url, timeout_s=45)
    assert leaked == [], (
        f"a disabled event destination must publish nothing; got {len(leaked)} event(s): "
        f"{[e.get('eventType') for e in leaked]!r}"
    )

    # Positive control: re-enable the SAME destination and repeat the SAME send. If the queue
    # were simply unreachable (a bad policy, a dead subscription) rather than genuinely gated by
    # Enabled, this would also see nothing -- so this leg proves the wiring was live all along.
    sesv2.update_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-gate",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "DELIVERY"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )
    enabled_message_id = _send(f"sim2real {CHECK} enabled")
    events = _drain_until(sqs, queue_url, {"Send"}, timeout_s=120)
    assert events["Send"]["mail"]["messageId"] == enabled_message_id, (
        f"after re-enabling, the Send event must name the re-enabled send "
        f"({enabled_message_id!r}), not the earlier disabled one ({disabled_message_id!r}); got "
        f"{events['Send']['mail']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
