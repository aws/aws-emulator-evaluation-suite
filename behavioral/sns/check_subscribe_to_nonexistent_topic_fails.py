"""subscribe-to-nonexistent-topic-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscribe-to-nonexistent-topic-fails"
GROUP = 'subscription-lifecycle'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError was raised, else raise."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Subscribe against a nonexistent TopicArn must fail with NotFound, while the
    identical Subscribe call against the identical TopicArn succeeds once the topic is recreated under
    the same name."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-topic-")

    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    # Positive control: the live topic accepts a subscription before anything is broken.
    control_sub = sns.subscribe(
        TopicArn=arn, Protocol="email", Endpoint="probe-control@example.com"
    )["SubscriptionArn"]
    assert control_sub == "pending confirmation", (
        f"expected literal 'pending confirmation' SubscriptionArn, got {control_sub!r}"
    )

    # Break: delete the topic, then probe the now-nonexistent TopicArn.
    sns.delete_topic(TopicArn=arn)
    code, message = _error(
        lambda: sns.subscribe(TopicArn=arn, Protocol="email", Endpoint="probe-broken@example.com")
    )
    assert code == "NotFound", f"expected NotFound, got {code!r}"
    assert message == "Topic does not exist", f"unexpected NotFound message for Subscribe: {message!r}"

    # Effect absent: an independent read (a different operation) sees no such topic either.
    list_code, list_message = _error(lambda: sns.list_subscriptions_by_topic(TopicArn=arn))
    assert list_code == "NotFound", (
        f"expected NotFound listing subscriptions on deleted topic, got {list_code!r}"
    )
    assert list_message == "Topic does not exist", (
        f"unexpected NotFound message listing subscriptions on deleted topic: {list_message!r}"
    )

    # Restore: recreating the topic under the identical name reuses the identical ARN...
    restored_arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=restored_arn))
    assert restored_arn == arn, f"expected the recreated topic to reuse {arn!r}, got {restored_arn!r}"

    # ...and the identical Subscribe call now succeeds again.
    restored_sub = sns.subscribe(
        TopicArn=restored_arn, Protocol="email", Endpoint="probe-restored@example.com"
    )["SubscriptionArn"]
    assert restored_sub == "pending confirmation", (
        f"expected literal 'pending confirmation' SubscriptionArn on restore, got {restored_sub!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
