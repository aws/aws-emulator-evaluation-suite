"""event-subscription-missing-topic-fails."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        _retrying(fn)
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")

CHECK = "event-subscription-missing-topic-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSubscription is refused while its SNS topic does not exist; once that topic is created
    the identical call succeeds, so the refusal is about the missing topic.
    """
    rs = ctx.client("redshift")
    sns = ctx.client("sns")
    subscription_name = ctx.unique_name("sim2real-behav-rs-subbad-")
    topic_name = ctx.unique_name("sim2real-behav-rs-subbad-topic-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    topic_arn = f"arn:aws:sns:{ctx.region}:{account}:{topic_name}"
    MSG_TOPIC = f"Failed to create Subscription. Topic: {topic_arn} not found."
    MSG_SUB = f"Event Subscription {subscription_name} not found"

    def _create():
        return rs.create_event_subscription(
            SubscriptionName=subscription_name,
            SnsTopicArn=topic_arn,
            SourceType="cluster",
            Severity="INFO",
            Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        )

    code, message = _refusal(_create)
    assert code == "SNSTopicArnNotFound", f"expected SNSTopicArnNotFound, got {code}"
    assert message == MSG_TOPIC, f"expected {MSG_TOPIC!r}, got {message!r}"

    lookup, lookup_message = _refusal(
        lambda: rs.describe_event_subscriptions(SubscriptionName=subscription_name)
    )
    assert lookup == "SubscriptionNotFound", (
        f"the rejected subscription must not exist, got {lookup}"
    )
    assert lookup_message == MSG_SUB, f"expected {MSG_SUB!r}, got {lookup_message!r}"

    # restore: create the exact topic the rejected call named, then repeat the identical call.
    created_arn = _retrying(
        lambda: sns.create_topic(
            Name=topic_name, Tags=[{"Key": "sim2real-behavioral", "Value": "true"}]
        )
    )["TopicArn"]
    assert created_arn == topic_arn, (
        f"topic ARN mismatch: created {created_arn!r}, expected {topic_arn!r}"
    )
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    _retrying(_create)
    ctx.on_cleanup(lambda: rs.delete_event_subscription(SubscriptionName=subscription_name))

    restored = _retrying(
        lambda: rs.describe_event_subscriptions(SubscriptionName=subscription_name)
    )["EventSubscriptionsList"]
    assert len(restored) == 1 and restored[0]["SnsTopicArn"] == topic_arn, (
        f"expected exactly one subscription visible with topic {topic_arn!r}, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
