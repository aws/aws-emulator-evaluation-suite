"""event-subscription-source-management."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-subscription-source-management"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Event subscription: create -> add/remove source ids -> modify -> delete."""
    rds = ctx.client("rds")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"), Tags=[{"Key": "sim2real", "Value": "true"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    pg_a = ctx.unique_name("sim2real-behav-pga-")
    pg_b = ctx.unique_name("sim2real-behav-pgb-")
    for pg in (pg_a, pg_b):
        rds.create_db_parameter_group(
            DBParameterGroupName=pg,
            DBParameterGroupFamily="mysql8.0",
            Description="sim2real behavioral check",
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        ctx.on_cleanup(lambda pg=pg: rds.delete_db_parameter_group(DBParameterGroupName=pg))

    sub_name = ctx.unique_name("sim2real-behav-sub-")
    rds.create_event_subscription(
        SubscriptionName=sub_name,
        SnsTopicArn=topic_arn,
        SourceType="db-parameter-group",
        SourceIds=[pg_a],
        Enabled=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subscription(rds, sub_name))
    sub = _wait_subscription_status(ctx, sub_name, {"active"})
    assert sub["SourceIdsList"] == [pg_a], f"expected only {pg_a!r} at creation, got {sub['SourceIdsList']!r}"
    assert sub["Enabled"] is True, f"expected Enabled=True at creation, got {sub['Enabled']!r}"

    rds.add_source_identifier_to_subscription(SubscriptionName=sub_name, SourceIdentifier=pg_b)
    sub = _wait_subscription_status(ctx, sub_name, {"active"})
    assert set(sub["SourceIdsList"]) == {pg_a, pg_b}, f"expected both source ids, got {sub['SourceIdsList']!r}"

    rds.remove_source_identifier_from_subscription(SubscriptionName=sub_name, SourceIdentifier=pg_a)
    sub = _wait_subscription_status(ctx, sub_name, {"active"})
    assert sub["SourceIdsList"] == [pg_b], f"expected only pg_b left, got {sub['SourceIdsList']!r}"

    rds.modify_event_subscription(SubscriptionName=sub_name, Enabled=False)
    sub = _wait_subscription_status(ctx, sub_name, {"active"})
    assert sub["Enabled"] is False, f"expected Enabled=False after modify, got {sub['Enabled']!r}"

    # Negative: adding a source id for a resource that doesn't exist is rejected. Real AWS raises
    # the generic "SourceNotFound" fault (note: no "Fault" suffix on the wire code, unlike most
    # other RDS faults) rather than a parameter-group-specific not-found fault.
    bogus_source_id = "sim2real-behav-does-not-exist"
    code, message = _error(
        lambda: rds.add_source_identifier_to_subscription(
            SubscriptionName=sub_name, SourceIdentifier=bogus_source_id
        )
    )
    assert code == "SourceNotFound", f"expected SourceNotFound, got {code!r}"
    expected = f"Could not find source :{bogus_source_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sub = _wait_subscription_status(ctx, sub_name, {"active"})
    assert sub["SourceIdsList"] == [pg_b], (
        f"rejected add_source_identifier_to_subscription must not mutate the source list, "
        f"expected [{pg_b!r}], got {sub['SourceIdsList']!r}"
    )

    rds.delete_event_subscription(SubscriptionName=sub_name)
    _wait_subscription_gone(ctx, sub_name)

    # A mutation on the now-dead subscription also fails, with the same not-found code the
    # teardown-tolerant helper above expects.
    dead_code, dead_message = _error(
        lambda: rds.modify_event_subscription(SubscriptionName=sub_name, Enabled=True)
    )
    assert dead_code == "SubscriptionNotFound", (
        f"expected a mutation on the deleted subscription to fail with SubscriptionNotFound, got {dead_code!r}"
    )
    expected_dead = f"Event Subscription {sub_name} not found."
    assert dead_message == expected_dead, f"expected message {expected_dead!r}, got {dead_message!r}"


def _safe_delete_subscription(rds, sub_name: str) -> None:
    try:
        rds.delete_event_subscription(SubscriptionName=sub_name)
    except ClientError as e:
        # The wire code for this fault is "SubscriptionNotFound" -- unlike most other RDS
        # faults, it does NOT carry a "Fault" suffix (the exception CLASS is named
        # SubscriptionNotFoundFault, but e.response["Error"]["Code"] is the bare wire string).
        if e.response["Error"]["Code"] != "SubscriptionNotFound":
            raise


def _error(fn) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it must raise."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_subscription_status(ctx, sub_name: str, statuses: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        try:
            return rds.describe_event_subscriptions(SubscriptionName=sub_name)["EventSubscriptionsList"][0]
        except ClientError as e:
            # Wire code is "SubscriptionNotFound" (no "Fault" suffix) -- see _safe_delete_subscription.
            if e.response["Error"]["Code"] == "SubscriptionNotFound":
                # Right after CreateEventSubscription (or right after an add/remove/modify call),
                # the subscription can take a few seconds to become describable by name -- treat
                # that as "not ready yet" and keep polling instead of letting a transient
                # not-found blow up the whole check.
                return {"Status": "__not_yet_describable__"}
            raise

    return _poll_until(probe, lambda s: s["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_subscription_gone(ctx, sub_name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_event_subscriptions(SubscriptionName=sub_name)
        except ClientError as e:
            # Wire code is "SubscriptionNotFound" (no "Fault" suffix) -- see _safe_delete_subscription.
            if e.response["Error"]["Code"] == "SubscriptionNotFound":
                return
            raise
        if not resp["EventSubscriptionsList"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"event subscription {sub_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
