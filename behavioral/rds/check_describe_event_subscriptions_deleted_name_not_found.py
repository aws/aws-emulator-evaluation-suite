"""describe-event-subscriptions-deleted-name-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-event-subscriptions-deleted-name-not-found"
GROUP = 'events'
SERVICES = ['rds']


def _describe_outcome(rds, sub_name):
    """DescribeEventSubscriptions for sub_name: its error (code, message), or ("listed", rows) while it still lists."""
    try:
        rows = rds.describe_event_subscriptions(SubscriptionName=sub_name)["EventSubscriptionsList"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "listed", rows


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An active event subscription is listed by name and unfiltered; once deleted, describing it
    by name fails SubscriptionNotFound rather than returning an empty list.
    """
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sub_name = ctx.unique_name("sim2real-behav-evtsub-")
    rds.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-instance",
        Enabled=True,
    )
    ctx.on_cleanup(lambda: _safe_delete_subscription(rds, sub_name))

    def _by_name():
        subs = rds.describe_event_subscriptions(SubscriptionName=sub_name).get(
            "EventSubscriptionsList", []
        )
        return subs[0] if subs else None

    sub = _poll_until(
        _by_name,
        lambda s: s is not None and s.get("Status") == "active",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"event subscription {sub_name} active",
    )
    assert sub["CustSubscriptionId"] == sub_name

    unfiltered_names = {
        s["CustSubscriptionId"] for s in rds.describe_event_subscriptions()["EventSubscriptionsList"]
    }
    assert sub_name in unfiltered_names, f"expected {sub_name} in unfiltered list, got {unfiltered_names!r}"

    rds.delete_event_subscription(SubscriptionName=sub_name)

    code, message = _poll_until(
        lambda: _describe_outcome(rds, sub_name),
        lambda outcome: outcome[0] == "SubscriptionNotFound",
        timeout_s=120.0,
        interval_s=5.0,
        description=f"event subscription {sub_name} rejected as not-found",
    )
    assert code == "SubscriptionNotFound", f"unexpected error code after delete: {code!r}"
    assert message == f"Event Subscription {sub_name} not found.", message


def _safe_delete_subscription(rds, sub_name: str) -> None:
    try:
        rds.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "SubscriptionNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
