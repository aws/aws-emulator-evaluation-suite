"""identity-notification-topic-bogus-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-notification-topic-bogus-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


def _account_id(ctx):
    if not hasattr(ctx, "_ses_account_id"):
        ctx._ses_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._ses_account_id


def _create_sns_topic(ctx):
    """Create an SNS topic SES is allowed to publish to; register teardown; return its ARN."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetIdentityNotificationTopic must reject an SNS topic ARN that does not exist
    (InvalidParameterValue), leaving a real, already-attached topic untouched."""
    ses = ctx.client("ses")
    email = _unique_email(ctx, "notif-bad-")
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    # Positive control: a real, SES-publishable SNS topic is accepted and stored.
    topic_arn = _create_sns_topic(ctx)
    ses.set_identity_notification_topic(
        Identity=email, NotificationType="Bounce", SnsTopic=topic_arn
    )
    attrs = ses.get_identity_notification_attributes(Identities=[email])["NotificationAttributes"][email]
    assert attrs.get("BounceTopic") == topic_arn, (
        f"positive control failed: expected BounceTopic {topic_arn!r}, got {attrs.get('BounceTopic')!r}"
    )

    # Well-formed ARN in the caller's own account/region, but no such topic exists.
    bogus = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:{ctx.unique_name('sim2real-behav-no-such-topic-')}"
    err, msg = _err(
        lambda: ses.set_identity_notification_topic(
            Identity=email, NotificationType="Bounce", SnsTopic=bogus
        )
    )
    assert err == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a non-existent SNS topic, got {err!r}: {msg!r}"
    )
    expected_msg = f"SNS topic {bogus} is invalid."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The rejected call must not have clobbered the real topic already in place.
    attrs_after = ses.get_identity_notification_attributes(Identities=[email])["NotificationAttributes"][email]
    assert attrs_after.get("BounceTopic") == topic_arn, (
        f"rejected SetIdentityNotificationTopic call altered the existing BounceTopic: "
        f"expected unchanged {topic_arn!r}, got {attrs_after.get('BounceTopic')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
