"""unsubscribe-nonexistent-is-idempotent."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsubscribe-nonexistent-is-idempotent"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']



def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_topic(ctx, name=None):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _fake_subscription_arn(topic_arn):
    """Return a well-formed but nonexistent SubscriptionArn for a topic."""
    return f"{topic_arn}:{uuid.uuid4()}"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unsubscribe on a well-formed but nonexistent SubscriptionArn of an existing topic succeeds,
    repeatably, and later reads show no subscription was fabricated and the topic is undisturbed.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    fake_sub = _fake_subscription_arn(topic_arn)

    sns.unsubscribe(SubscriptionArn=fake_sub)
    sns.unsubscribe(SubscriptionArn=fake_sub)

    get_code, get_message = _error(lambda: sns.get_subscription_attributes(SubscriptionArn=fake_sub))
    assert get_code == "NotFound", (
        f"GetSubscriptionAttributes on the never-existent ARN should be NotFound, got {get_code!r}"
    )
    assert get_message == "Subscription does not exist", (
        f"unexpected NotFound message for the never-existent ARN: {get_message!r}"
    )
    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert subs == [], (
        f"Unsubscribe on a bogus ARN must not leave a fabricated subscription record, got {subs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
