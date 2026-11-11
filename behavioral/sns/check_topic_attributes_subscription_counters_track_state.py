"""topic-attributes-subscription-counters-track-state."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-attributes-subscription-counters-track-state"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']

def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(client, ctx, name, attributes=None):
    """CreateTopic (tagged, so a tag search finds it) + register best-effort
    DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name, "Tags": _tags_kv()}
    if attributes:
        kwargs["Attributes"] = attributes
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn


def _error(fn) -> tuple[str, str]:
    """The AWS error (Code, Message) raised by fn(). Raises if fn SUCCEEDS -- an unexpected success
    is the strongest possible signal."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call was expected to be rejected but SUCCEEDED, returning {result!r}")


def _fake_queue_arn(topic_arn, name=None):
    """A well-formed SQS queue ARN in the topic's account/region (SNS confirms sqs
    subscriptions without verifying the queue exists, keeping this single-service)."""
    parts = topic_arn.split(":")
    name = name or f"sim2real-behav-sns-q-{uuid.uuid4().hex[:8]}"
    return f"arn:aws:sqs:{parts[3]}:{parts[4]}:{name}"


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Poll fn() until pred(val); raise AssertionError on deadline miss (never a bare sleep)."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: condition not met within {timeout_s}s, last value {val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _cleanup_unsubscribe(client, sub_arn):
    """A subscription-first teardown callable that tolerates ONLY 'already gone'.

    The check itself unsubscribes as part of the assertion, and DeleteTopic removes any
    survivors, so teardown must not fail on absence -- but it must still surface any other
    error rather than swallowing it.
    """
    def _fn():
        try:
            client.unsubscribe(SubscriptionArn=sub_arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("NotFound", "InvalidParameter"):
                raise
    return _fn


def _counters(client, topic_arn):
    """The three computed subscription counters, as ints. A missing counter is a defect,
    so a KeyError here is the right failure rather than a silent 0 default."""
    attrs = client.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    missing = [k for k in ("SubscriptionsConfirmed", "SubscriptionsPending", "SubscriptionsDeleted")
               if k not in attrs]
    assert not missing, (
        f"GetTopicAttributes must report the computed counters {missing} on every topic; got {sorted(attrs)}"
    )
    return {
        "confirmed": int(attrs["SubscriptionsConfirmed"]),
        "pending": int(attrs["SubscriptionsPending"]),
        "deleted": int(attrs["SubscriptionsDeleted"]),
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTopicAttributes' SubscriptionsConfirmed, SubscriptionsPending and SubscriptionsDeleted
    start at 0 and follow an auto-confirmed sqs Subscribe, a pending email Subscribe and an
    Unsubscribe, whose ARN is then rejected with NotFound."""
    sns = ctx.client("sns")
    # The counters are computed at read time and may lag a write, so each transition is polled.
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-counters-"))

    start = _counters(sns, topic_arn)
    assert start == {"confirmed": 0, "pending": 0, "deleted": 0}, (
        f"a freshly created topic must report all three counters at 0, got {start}"
    )

    # An sqs subscription auto-confirms, so Confirmed goes to 1 and Pending stays 0.
    sqs_endpoint = _fake_queue_arn(topic_arn, ctx.unique_name("sim2real-behav-sns-counters-q-"))
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=sqs_endpoint)["SubscriptionArn"]
    ctx.on_cleanup(_cleanup_unsubscribe(sns, sub_arn))

    after_confirm = _poll(
        lambda: _counters(sns, topic_arn),
        lambda c: c["confirmed"] == 1,
        timeout_s=60.0,
        interval_s=2.0,
        what="SubscriptionsConfirmed reaches 1 after an auto-confirming sqs Subscribe",
    )
    assert after_confirm["pending"] == 0, (
        f"an auto-confirmed sqs subscription must not be counted as pending, got {after_confirm}"
    )
    assert after_confirm["deleted"] == 0, (
        f"nothing has been unsubscribed yet, so SubscriptionsDeleted must still be 0, got {after_confirm}"
    )

    # An email subscription requires out-of-band confirmation, so Pending goes to 1 while
    # Confirmed holds at 1. `@example.com` is IANA-reserved; the confirmation email itself
    # is never read and nothing about it is asserted.
    sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint="sim2real-behav-sns@example.com")
    after_pending = _poll(
        lambda: _counters(sns, topic_arn),
        lambda c: c["pending"] == 1,
        timeout_s=60.0,
        interval_s=2.0,
        what="SubscriptionsPending reaches 1 after a confirmation-requiring Subscribe",
    )
    assert after_pending["confirmed"] == 1, (
        "a new PENDING subscription must not be counted as confirmed; expected confirmed=1, "
        f"got {after_pending}"
    )

    # Unsubscribing the confirmed one moves it out of Confirmed and into Deleted.
    sns.unsubscribe(SubscriptionArn=sub_arn)
    after_delete = _poll(
        lambda: _counters(sns, topic_arn),
        lambda c: c["confirmed"] == 0,
        timeout_s=60.0,
        interval_s=2.0,
        what="SubscriptionsConfirmed returns to 0 after Unsubscribe",
    )
    assert after_delete["pending"] == 1, (
        f"unsubscribing the confirmed subscription must not disturb the pending one, got {after_delete}"
    )

    code, message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn))
    assert code == "NotFound", (
        f"GetSubscriptionAttributes on the unsubscribed ARN must be rejected with NotFound, got {code!r}"
    )
    assert message == "Subscription does not exist", (
        f"unexpected NotFound message for GetSubscriptionAttributes: {message!r}"
    )

    deleted_seen = _poll(
        lambda: _counters(sns, topic_arn),
        lambda c: c["deleted"] >= 1,
        timeout_s=60.0,
        interval_s=2.0,
        what="SubscriptionsDeleted increments after Unsubscribe",
    )
    assert deleted_seen["deleted"] >= 1, (
        f"SubscriptionsDeleted must account for the unsubscribed subscription, got {deleted_seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
