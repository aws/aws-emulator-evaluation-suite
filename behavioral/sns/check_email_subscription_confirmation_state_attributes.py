"""email-subscription-confirmation-state-attributes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "email-subscription-confirmation-state-attributes"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unconfirmed email subscription gets a real ARN reading PendingConfirmation=true and
    ConfirmationWasAuthenticated=false (an sqs one reads false/true), yet ListSubscriptionsByTopic
    still lists it under the PendingConfirmation placeholder."""
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-confstate-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    region, account = topic_arn.split(":")[3:5]

    sqs_sub = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", ReturnSubscriptionArn=True,
        Endpoint=f"arn:aws:sqs:{region}:{account}:{ctx.unique_name('sim2real-behav-sns-confstate-q-')}",
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sqs_sub))
    # example.com is IANA-reserved; nothing about the email itself is asserted.
    email = f"{ctx.unique_name('sim2real-behav-sns')}@example.com"
    pending = sns.subscribe(
        TopicArn=topic_arn, Protocol="email", Endpoint=email, ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    # A pending subscription cannot be unsubscribed; DeleteTopic (registered above) removes it.
    assert pending.startswith(topic_arn + ":"), (
        "with ReturnSubscriptionArn an email subscription must get a real ARN under its topic, "
        f"not a placeholder; got {pending if not pending.startswith('arn:') else 'another ARN'!r}"
    )

    p = sns.get_subscription_attributes(SubscriptionArn=pending)["Attributes"]
    got = {k: p.get(k) for k in ("PendingConfirmation", "ConfirmationWasAuthenticated", "Protocol", "Endpoint")}
    assert got == {"PendingConfirmation": "true", "ConfirmationWasAuthenticated": "false",
                   "Protocol": "email", "Endpoint": email}, f"pending email subscription attributes: {got!r}"

    c = sns.get_subscription_attributes(SubscriptionArn=sqs_sub)["Attributes"]
    got = {k: c.get(k) for k in ("PendingConfirmation", "ConfirmationWasAuthenticated")}
    assert got == {"PendingConfirmation": "false", "ConfirmationWasAuthenticated": "true"}, (
        f"auto-confirmed sqs subscription attributes: {got!r}"
    )

    listed = {x["SubscriptionArn"]: x for x in sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]}
    assert listed.get("PendingConfirmation", {}).get("Endpoint") == email, (
        "ListSubscriptionsByTopic must still list the email subscription under the "
        "PendingConfirmation placeholder even though Subscribe returned its real ARN"
    )
    assert sqs_sub in listed, "ListSubscriptionsByTopic must list the confirmed sqs subscription by its ARN"
    assert pending not in listed, "the pending subscription's real ARN must not be listed before confirmation"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
