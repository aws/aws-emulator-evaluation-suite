"""subscribe-email-pending-confirmation."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "subscribe-email-pending-confirmation"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

_SCENARIO = "subscribe-email-pending-confirmation"


def _tags_kv():
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Subscribing an email endpoint stays PendingConfirmation until ConfirmSubscription."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(
        ev, ctx, ctx.unique_name("sim2real-behav-sns-subemail-"), tags=_tags_kv()
    )
    resp = ev.subscribe(
        TopicArn=topic_arn, Protocol="email", Endpoint="fidelity-check@example.com"
    )
    sub_arn = resp["SubscriptionArn"]
    assert sub_arn == "pending confirmation", (
        f"expected literal 'pending confirmation' SubscriptionArn for email protocol, got {sub_arn!r}"
    )
    subs = ev.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    email_entries = [s for s in subs if s.get("Protocol") == "email"]
    assert len(email_entries) == 1, f"expected exactly one email subscription, got {email_entries}"
    listed_arn = email_entries[0].get("SubscriptionArn")
    assert listed_arn == "PendingConfirmation", (
        "expected ListSubscriptionsByTopic to report the PascalCase literal 'PendingConfirmation' "
        f"for the unconfirmed subscription, got {listed_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
