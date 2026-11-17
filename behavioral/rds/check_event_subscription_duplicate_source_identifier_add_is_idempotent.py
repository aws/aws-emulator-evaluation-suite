"""event-subscription-duplicate-source-identifier-add-is-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-subscription-duplicate-source-identifier-add-is-idempotent"
GROUP = "events"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding a source identifier that is already on an event subscription leaves its
    SourceIdsList holding that identifier exactly once, not twice.
    """
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"), Tags=[{"Key": "sim2real", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    sg_name = ctx.unique_name("sim2real-behav-dbsg-")
    rds.create_db_security_group(
        DBSecurityGroupName=sg_name,
        DBSecurityGroupDescription="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=sg_name))

    sub_name = ctx.unique_name("sim2real-behav-evsub-")
    rds.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-security-group",
        SourceIds=[sg_name],
        Enabled=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subscription(rds, sub_name))

    sub = _wait_subscription_status(rds, sub_name, {"active"})
    assert sub["SourceIdsList"] == [sg_name], (
        f"expected only {sg_name!r} at creation, got {sub['SourceIdsList']!r}"
    )

    rds.add_source_identifier_to_subscription(SubscriptionName=sub_name, SourceIdentifier=sg_name)
    sub = _wait_subscription_status(rds, sub_name, {"active"})
    assert sub["SourceIdsList"] == [sg_name], (
        f"re-adding {sg_name!r}, which was already on the subscription, must leave the list "
        f"holding it exactly once, got {sub['SourceIdsList']!r}"
    )

    rds.remove_source_identifier_from_subscription(SubscriptionName=sub_name, SourceIdentifier=sg_name)
    sub = _wait_subscription_status(rds, sub_name, {"active"})
    assert sub.get("SourceIdsList", []) == [], (
        f"expected an empty source list after removing the only source id, got {sub.get('SourceIdsList')!r}"
    )


def _safe_delete_subscription(rds, sub_name: str) -> None:
    try:
        rds.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "SubscriptionNotFound":
            raise


def _wait_subscription_status(rds, sub_name: str, statuses: set, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            subs = rds.describe_event_subscriptions(SubscriptionName=sub_name).get("EventSubscriptionsList", [])
        except ClientError as e:
            if e.response["Error"]["Code"] != "SubscriptionNotFound":
                raise
            subs = []
        if subs:
            last = subs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"subscription {sub_name} did not reach {statuses} within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
