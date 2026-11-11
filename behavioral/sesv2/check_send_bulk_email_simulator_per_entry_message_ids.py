"""send-bulk-email-simulator-per-entry-message-ids."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-bulk-email-simulator-per-entry-message-ids"
GROUP = 'sending'
# SERVICES names the suite directory (corpus convention), not every client the check opens.
SERVICES = ['sesv2']

# The SES mailbox simulator is the ONLY permitted destination, and `success@` is the only simulator
# address used here: a simulated bounce or complaint feeds the account's reputation metrics, and
# nothing in this check needs one. `success@` mail never leaves AWS and reaches no human inbox.
_SIMULATOR_TO = 'success@simulator.amazonses.com'


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


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


def _event_witness(ctx, sesv2, sns, sqs, event_types):
    """A configuration set whose event destination publishes ``event_types`` to an SNS topic
    delivering raw to an SQS queue: ``(configuration set name, queue url)``."""
    base = ctx.unique_name("sim2real-xsvc-ses-wit-")
    topic_arn = sns.create_topic(
        Name=base, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=base, tags={"sim2real": CHECK})["QueueUrl"]
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
    sesv2.create_configuration_set(
        ConfigurationSetName=base, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=base))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=base,
        EventDestinationName="sim2real-dest",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": event_types,
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )
    return base, queue_url


def _events_for(sqs, queue_url, event_type, message_ids, timeout_s):
    """``{messageId: event}`` of the ``event_type`` events published for ``message_ids``; FAILS
    naming the ids still missing at the deadline."""
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and not set(message_ids) <= set(seen):
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            try:
                event = json.loads(m["Body"])
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("eventType") == event_type:
                seen.setdefault(event["mail"]["messageId"], event)
    missing = set(message_ids) - set(seen)
    assert not missing, f"{event_type} events for {sorted(missing)} never arrived in {timeout_s}s"
    return seen




@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "requires:dns-baseline")
def run(ctx) -> None:
    """SendBulkEmail returns one SUCCESS BulkEmailEntryResult with a distinct MessageId per entry, and
    each id is a sent message: the configuration set's SNS->SQS destination receives a Delivery event
    for every one, rendered with its own entry's replacement data."""
    route53 = ctx.client('route53')
    ses = ctx.client('sesv2')
    sns = ctx.client('sns')
    sqs = ctx.client('sqs')
    domain = _dns_baseline_domain(ctx, route53, ses)
    sender = f"{ctx.unique_name('sim2real-behav-')}@{domain}"
    config_set, queue_url = _event_witness(ctx, ses, sns, sqs, ["DELIVERY"])

    template = ctx.unique_name('sim2real-behav-bulk-')
    ses.create_email_template(
        TemplateName=template,
        TemplateContent={
            'Subject': 'sim2real bulk probe {{slot}}',
            'Text': 'slot={{slot}}',
            'Html': '<p>slot={{slot}}</p>',
        },
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _t=template: ses.delete_email_template(TemplateName=_t))

    resp = ses.send_bulk_email(
        FromEmailAddress=sender,
        DefaultContent={'Template': {'TemplateName': template, 'TemplateData': '{"slot": "default"}'}},
        BulkEmailEntries=[
            {'Destination': {'ToAddresses': [_SIMULATOR_TO]},
             'ReplacementEmailContent': {
                 'ReplacementTemplate': {'ReplacementTemplateData': '{"slot": "one"}'}}},
            {'Destination': {'ToAddresses': [_SIMULATOR_TO]},
             'ReplacementEmailContent': {
                 'ReplacementTemplate': {'ReplacementTemplateData': '{"slot": "two"}'}}},
        ],
        ConfigurationSetName=config_set,
    )

    results = resp.get('BulkEmailEntryResults')
    assert isinstance(results, list), (
        f"SendBulkEmail must return BulkEmailEntryResults, got response keys {sorted(resp)}"
    )
    assert len(results) == 2, (
        f"BulkEmailEntryResults must carry exactly one entry per BulkEmailEntries element (2), got "
        f"{len(results)}: {results!r}"
    )
    message_ids = []
    for idx, res in enumerate(results):
        assert res.get('Status') == 'SUCCESS', (
            f"entry {idx} to the mailbox simulator must be accepted; got Status={res.get('Status')!r} "
            f"Error={res.get('Error')!r}"
        )
        mid = res.get('MessageId') or ''
        assert mid.strip(), f"entry {idx} succeeded but carries no MessageId: {res!r}"
        message_ids.append(mid)
    assert len(set(message_ids)) == 2, (
        f"each accepted entry is a separate message and must get its own MessageId, got {message_ids!r}"
    )

    # Effect present: SES sent and delivered every entry under the id it returned for that entry.
    delivered = _events_for(sqs, queue_url, "Delivery", message_ids, timeout_s=300)
    for idx, slot in enumerate(("one", "two")):
        event = delivered[message_ids[idx]]
        assert event["delivery"]["recipients"] == [_SIMULATOR_TO], (
            f"entry {idx}'s Delivery event names recipients {event['delivery']['recipients']!r}"
        )
        subject = event["mail"]["commonHeaders"]["subject"]
        assert subject == f"sim2real bulk probe {slot}", (
            f"entry {idx} must be rendered with its own replacement data ({slot!r}), got subject {subject!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
