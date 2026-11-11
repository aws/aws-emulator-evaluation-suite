"""templated-send-with-missing-variable-publishes-rendering-failure."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "templated-send-with-missing-variable-publishes-rendering-failure"
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
                    f"the DNS baseline domain {domain!r} is not verified for sending in "
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r})"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


def _drain(sqs, queue_url, want, timeout_s):
    """Collect SES events from the queue until every eventType in ``want`` arrived; RAISE on
    deadline with what did arrive."""
    deadline = time.monotonic() + timeout_s
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and not want <= set(seen):
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            # SES first publishes a plain-text "Successfully validated SNS topic" notice to a new
            # event destination; only JSON bodies are events.
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
    "cap:c7",
    "concern:eventing",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
)
def run(ctx) -> None:
    """A templated SendEmail whose TemplateData omits a referenced variable is accepted, and the
    configuration set's SNS destination later receives a Rendering Failure naming the template;
    the same send with the variable supplied produces no Rendering Failure.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    domain = _dns_baseline_domain(ctx, route53, sesv2)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-ses-render-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    queue_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-ses-render-"))["QueueUrl"]
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

    config_set = ctx.unique_name("sim2real-ses-render-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))
    sesv2.create_configuration_set_event_destination(
        ConfigurationSetName=config_set,
        EventDestinationName="sim2real-render",
        EventDestination={
            "Enabled": True,
            "MatchingEventTypes": ["SEND", "RENDERING_FAILURE"],
            "SnsDestination": {"TopicArn": topic_arn},
        },
    )

    template_name = ctx.unique_name("sim2real-ses-render-")
    sesv2.create_email_template(
        TemplateName=template_name,
        TemplateContent={
            "Subject": "sim2real {{name}}",
            "Text": "Hello {{name}}, this is a rendering probe.",
        },
    )
    ctx.on_cleanup(lambda: sesv2.delete_email_template(TemplateName=template_name))

    sender = f"{ctx.unique_name('sim2real-')}@{domain}"

    # positive control first: TemplateData supplies the variable the body references, so this
    # send must clear the rendering gate entirely.
    control_message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [_SUCCESS]},
        Content={
            "Template": {
                "TemplateName": template_name,
                "TemplateData": json.dumps({"name": "control"}),
            }
        },
        ConfigurationSetName=config_set,
    )["MessageId"]
    assert control_message_id, "positive control: SendEmail must return a MessageId"

    control_events = _drain(sqs, queue_url, {"Send"}, timeout_s=120)
    assert control_events["Send"]["mail"]["messageId"] == control_message_id, (
        f"positive control's Send event must name {control_message_id!r}; got "
        f"{control_events['Send']['mail']['messageId']!r}"
    )

    # the probe: TemplateData is `{}`, omitting the "name" variable the template body references.
    message_id = sesv2.send_email(
        FromEmailAddress=sender,
        Destination={"ToAddresses": [_SUCCESS]},
        Content={"Template": {"TemplateName": template_name, "TemplateData": "{}"}},
        ConfigurationSetName=config_set,
    )["MessageId"]
    assert message_id, "SendEmail with a template missing a referenced variable must still be accepted"
    assert message_id != control_message_id, "the probe send must mint its own MessageId"

    events = _drain(sqs, queue_url, {"Send", "Rendering Failure"}, timeout_s=120)
    failure_event = events["Rendering Failure"]
    assert failure_event["mail"]["messageId"] == message_id, (
        f"the Rendering Failure event must name the message SendEmail accepted ({message_id!r}); "
        f"got {failure_event['mail']['messageId']!r}"
    )
    assert failure_event["failure"]["templateName"] == template_name, (
        f"the Rendering Failure event must name the template {template_name!r}; got "
        f"{failure_event['failure'].get('templateName')!r}"
    )
    assert "name" in failure_event["failure"].get("errorMessage", ""), (
        f"the Rendering Failure error message should name the missing variable; got "
        f"{failure_event['failure'].get('errorMessage')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
