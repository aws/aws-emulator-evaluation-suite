"""account-suppression-from-a-hard-bounce-blocks-the-next-send."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "account-suppression-from-a-hard-bounce-blocks-the-next-send"
GROUP = "state-machine"
SERVICES = ["sesv2", "sns", "sqs"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_SUCCESS = "success@simulator.amazonses.com"
_SUPPRESSED_DIAGNOSTIC = (
    "Amazon SES did not send the message to this address because it is on the suppression list "
    "for your account. For more information about removing addresses from the suppression list, "
    "see the Amazon SES Developer Guide at "
    "https://docs.aws.amazon.com/ses/latest/dg/sending-email-suppression-list.html"
)



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


def _drain_collect(sqs, queue_url, min_count, timeout_s):
    """Collect every body visible within timeout_s, stopping early once min_count SES events arrived.

    Returns ``(events, others)``. ``others`` keeps every body that is not an SES event (no JSON
    object with an ``eventType``), such as the plain-text topic-validation notice SES publishes when
    the destination is created, so the caller asserts none of them names a send and quotes them.
    """
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    others: list[str] = []
    while time.monotonic() < deadline and len(seen) < min_count:
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                event = None
            if isinstance(event, dict) and event.get("eventType"):
                seen.append(event)
            else:
                others.append(m["Body"])
    return seen, others


def _delete_suppressed_destination(sesv2, address):
    """Remove ``address`` from the account suppression list; already absent is fine."""
    try:
        sesv2.delete_suppressed_destination(EmailAddress=address)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise




@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """A simulator hard bounce puts its address on the account suppression list by itself; the
    next send there is accepted but bounces OnAccountSuppressionList, while a control address
    through the same configuration set still gets a plain Send event.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    original_reasons = sesv2.get_account()["SuppressionAttributes"]["SuppressedReasons"]
    ctx.on_cleanup(
        lambda: sesv2.put_account_suppression_attributes(SuppressedReasons=original_reasons)
    )
    sesv2.put_account_suppression_attributes(SuppressedReasons=["BOUNCE", "COMPLAINT"])
    assert set(sesv2.get_account()["SuppressionAttributes"]["SuppressedReasons"]) == {
        "BOUNCE",
        "COMPLAINT",
    }, "failed to enable account-level BOUNCE suppression as a precondition for this check"

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-ses-acctsupp-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-ses-acctsupp-"),
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

    config_set = ctx.unique_name("sim2real-xsvc-ses-acctsupp-")
    sesv2.create_configuration_set(
        ConfigurationSetName=config_set, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "BOUNCE"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"
    # Any address at simulator.amazonses.com other than a documented simulator alias triggers the
    # same deterministic "unknown user" hard bounce bounce@ does; unique per run so this check
    # never races a sibling over the same suppression-list entry.
    target = f"{ctx.unique_name('sim2real-acctsupp-')}@simulator.amazonses.com"

    def _send(to_address: str, subject: str) -> str:
        return sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [to_address]},
            Content={"Simple": {"Subject": {"Data": subject}, "Body": {"Text": {"Data": "x"}}}},
            ConfigurationSetName=config_set,
        )["MessageId"]

    first_message_id = _send(target, f"sim2real {CHECK} trigger-bounce")
    # The bounce adds the entry asynchronously, so the teardown is registered now: a failing
    # assert below must not leave the address on the account suppression list.
    ctx.on_cleanup(lambda: _delete_suppressed_destination(sesv2, target))

    not_yet_suppressed_message = f"Email address {target} does not exist on your suppression list."
    deadline = time.monotonic() + 180.0
    suppressed = None
    while time.monotonic() < deadline:
        try:
            suppressed = sesv2.get_suppressed_destination(EmailAddress=target)
            break
        except ClientError as err:
            error = err.response["Error"]
            assert error["Code"] == "NotFoundException", (
                f"unexpected error polling GetSuppressedDestination: {error!r}"
            )
            assert error["Message"] == not_yet_suppressed_message, (
                f"expected message {not_yet_suppressed_message!r}, got {error['Message']!r}"
            )
            time.sleep(5)
    assert suppressed is not None, (
        f"{target!r} never appeared on the account suppression list within 180s after a hard bounce"
    )
    entry = suppressed["SuppressedDestination"]
    assert entry["Reason"] == "BOUNCE", (
        f"expected the auto-added entry's Reason to be 'BOUNCE', got {entry.get('Reason')!r}"
    )
    assert entry["Attributes"]["MessageId"] == first_message_id, (
        f"the suppression entry names MessageId {entry['Attributes'].get('MessageId')!r}, not the "
        f"bounced send's {first_message_id!r}"
    )

    second_message_id = _send(target, f"sim2real {CHECK} blocked-by-suppression")
    assert len(second_message_id) > 10, (
        f"SendEmail to an already-suppressed destination must still be ACCEPTED with a real "
        f"MessageId, got {second_message_id!r}"
    )
    assert second_message_id != first_message_id, "the second send must be a distinct message"

    control_message_id = _send(_SUCCESS, f"sim2real {CHECK} control")

    # Each of the 3 sends fires a Send event (MatchingEventTypes includes SEND); the first two
    # additionally fire a Bounce event (trigger, then block) -- 5 events in total.
    events, others = _drain_collect(sqs, queue_url, min_count=5, timeout_s=180)
    sent = (first_message_id, second_message_id, control_message_id)
    unparsed = [b for b in others if any(mid in b for mid in sent)]
    assert unparsed == [], (
        f"{len(unparsed)} queue bodies name one of this check's sends but are not SES events (a JSON "
        f"object with an eventType) under RawMessageDelivery: {unparsed!r}"
    )
    by_message_id: dict[str, list[dict]] = {}
    for e in events:
        by_message_id.setdefault(e["mail"]["messageId"], []).append(e)

    second_events = {e["eventType"] for e in by_message_id.get(second_message_id, [])}
    assert "Bounce" in second_events, (
        f"the second send to a suppressed destination never produced a Bounce event; saw "
        f"{second_events!r} for {second_message_id!r} (all events: "
        f"{[(e['eventType'], e['mail']['messageId']) for e in events]!r}; non-event bodies: "
        f"{others!r})"
    )
    second_bounce = next(
        e for e in by_message_id[second_message_id] if e["eventType"] == "Bounce"
    )["bounce"]
    assert second_bounce["bounceSubType"] == "OnAccountSuppressionList", (
        f"expected bounceSubType 'OnAccountSuppressionList' for the blocked send, got "
        f"{second_bounce.get('bounceSubType')!r}"
    )
    diagnostic = second_bounce["bouncedRecipients"][0].get("diagnosticCode")
    assert diagnostic == _SUPPRESSED_DIAGNOSTIC, (
        f"expected the blocked send's diagnosticCode {_SUPPRESSED_DIAGNOSTIC!r}, got {diagnostic!r}"
    )

    control_events = {e["eventType"] for e in by_message_id.get(control_message_id, [])}
    assert control_events == {"Send"}, (
        f"the control send (never suppressed) through the same configuration set produced "
        f"{control_events!r}, expected exactly a Send event -- the wiring must still be live and "
        f"unaffected by the other address's suppression (non-event bodies: {others!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
