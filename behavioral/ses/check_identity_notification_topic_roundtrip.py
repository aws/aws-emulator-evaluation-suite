"""identity-notification-topic-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "identity-notification-topic-roundtrip"
GROUP = 'identity'
SERVICES = ['ses']

def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _account_id(ctx):
    if not hasattr(ctx, "_ses_account_id"):
        ctx._ses_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._ses_account_id


def _notification_attributes(ses, identity):
    return ses.get_identity_notification_attributes(
        Identities=[identity]
    ).get("NotificationAttributes", {}).get(identity)


def _create_sns_topic(ctx):
    """Create an SNS topic SES is allowed to publish to; register teardown; return its ARN."""
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSESPublish",
                "Effect": "Allow",
                "Principal": {"Service": "ses.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": arn,
                "Condition": {"StringEquals": {"AWS:SourceAccount": _account_id(ctx)}},
            }
        ],
    }
    try:
        sns.set_topic_attributes(
            TopicArn=arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
        )
    except Exception:
        pass
    return arn


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIdentityNotificationTopic attaches/detaches a real SNS topic, and headers-in-notifications toggles independently."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    topic_arn = _create_sns_topic(ctx)
    ses.set_identity_notification_topic(
        Identity=email, NotificationType="Bounce", SnsTopic=topic_arn
    )
    attrs = _notification_attributes(ses, email)
    assert attrs is not None, "no NotificationAttributes entry after SetIdentityNotificationTopic"
    assert attrs.get("BounceTopic") == topic_arn, (
        f"BounceTopic not reflected after set: {attrs.get('BounceTopic')!r} != {topic_arn!r}"
    )
    # Setting the Bounce topic must not leak into the Complaint/Delivery slots.
    assert not attrs.get("ComplaintTopic"), f"ComplaintTopic unexpectedly set: {attrs}"
    assert not attrs.get("DeliveryTopic"), f"DeliveryTopic unexpectedly set: {attrs}"

    # Headers-in-notifications is a separate flag, default false, toggled per type.
    assert attrs.get("HeadersInBounceNotificationsEnabled") in (False, None), (
        f"expected HeadersInBounceNotificationsEnabled to default false, got {attrs.get('HeadersInBounceNotificationsEnabled')!r}"
    )
    ses.set_identity_headers_in_notifications_enabled(
        Identity=email, NotificationType="Bounce", Enabled=True
    )
    attrs_hdr = _notification_attributes(ses, email)
    assert attrs_hdr.get("HeadersInBounceNotificationsEnabled") is True, (
        f"headers-in-bounce-notifications flag not persisted: {attrs_hdr}"
    )
    assert attrs_hdr.get("HeadersInComplaintNotificationsEnabled") in (False, None), (
        "enabling headers for Bounce must not enable them for Complaint"
    )

    # Omitting SnsTopic clears the topic.
    ses.set_identity_notification_topic(Identity=email, NotificationType="Bounce")
    attrs_after = _notification_attributes(ses, email)
    assert attrs_after is None or not attrs_after.get("BounceTopic"), (
        f"BounceTopic still set after clearing: {attrs_after}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
