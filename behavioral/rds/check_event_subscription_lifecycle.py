"""event-subscription-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-subscription-lifecycle"
GROUP = 'events'
SERVICES = ['rds']

ERR_SUBSCRIPTION_NOT_FOUND = "SubscriptionNotFound"

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventSubscription -> active; ModifyEventSubscription flips Enabled;
    then DeleteEventSubscription removes it, and the id is gone and unusable
    afterward. Requires an SNS topic as the notification target.
    """
    rds = ctx.client("rds")
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_name = ctx.unique_name("sim2real-behav-evsub-")
    rds.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-instance",
        Enabled=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subscription(rds, sub_name))

    def _describe():
        # DescribeEventSubscriptions(SubscriptionName=...) raises SubscriptionNotFound rather
        # than returning an empty list when the name isn't (yet, or any longer) visible -- right
        # after CreateEventSubscription it can take a few seconds to become describable, and
        # after DeleteEventSubscription this is the "gone" signal we poll for.
        try:
            subs = rds.describe_event_subscriptions(SubscriptionName=sub_name).get(
                "EventSubscriptionsList", []
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == ERR_SUBSCRIPTION_NOT_FOUND:
                return None
            raise
        return subs[0] if subs else None

    deadline = time.monotonic() + 120
    sub = None
    while time.monotonic() < deadline:
        sub = _describe()
        if sub is not None and sub.get("Status") == "active":
            break
        time.sleep(3)
    else:
        raise AssertionError(f"event subscription {sub_name} did not become active in time")
    assert sub["Enabled"] is True, f"expected Enabled=True on creation, got {sub['Enabled']!r}"

    rds.modify_event_subscription(SubscriptionName=sub_name, Enabled=False)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        sub = _describe()
        if sub is not None and sub.get("Enabled") is False:
            break
        time.sleep(3)
    else:
        raise AssertionError(f"event subscription {sub_name} did not disable in time")
    assert sub["Enabled"] is False, f"expected Enabled=False after modify, got {sub['Enabled']!r}"

    rds.delete_event_subscription(SubscriptionName=sub_name)

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if _describe() is None:
            break
        time.sleep(3)
    else:
        raise AssertionError(f"event subscription {sub_name} was not deleted within time")
    assert _describe() is None, f"expected {sub_name} absent from DescribeEventSubscriptions after delete"

    code, message = _error_code(lambda: rds.modify_event_subscription(SubscriptionName=sub_name, Enabled=True))
    assert code == ERR_SUBSCRIPTION_NOT_FOUND, (
        f"expected {ERR_SUBSCRIPTION_NOT_FOUND} modifying a deleted subscription, got {code!r}"
    )
    assert message == f"Event Subscription {sub_name} not found.", message


def _safe_delete_subscription(rds, sub_name: str) -> None:
    try:
        rds.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != ERR_SUBSCRIPTION_NOT_FOUND:
            raise


def _error_code(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
