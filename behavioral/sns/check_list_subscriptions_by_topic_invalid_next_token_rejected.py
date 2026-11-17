"""list-subscriptions-by-topic-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-subscriptions-by-topic-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["sns"]


def _error(fn):
    """(Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSubscriptionsByTopic with a NextToken that was never issued is rejected with
    InvalidParameter instead of returning an arbitrary page, and an ordinary call on the same
    topic still works before and after the rejected one.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-lsbt-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # Positive control: an ordinary, token-less call on the real topic succeeds.
    before = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert before.get("Subscriptions") == [], (
        f"expected an empty subscription list on a fresh topic, got {before.get('Subscriptions')!r}"
    )

    # Break exactly one thing: a NextToken that could never have been issued by SNS.
    code, message = _error(
        lambda: sns.list_subscriptions_by_topic(TopicArn=topic_arn, NextToken="not-a-real-token==")
    )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a NextToken that was never issued, got {code!r}"
    )
    assert message == "Invalid parameter: NextToken", (
        f"unexpected message for an unissued NextToken: {message!r}"
    )

    # The rejected call left the topic's own listing unaffected.
    after = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert after.get("Subscriptions") == [], (
        f"expected the listing unchanged after the rejected call, got {after.get('Subscriptions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
