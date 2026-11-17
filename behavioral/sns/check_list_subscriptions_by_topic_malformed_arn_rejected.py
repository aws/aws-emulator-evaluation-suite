"""list-subscriptions-by-topic-malformed-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-subscriptions-by-topic-malformed-arn-rejected"
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
    """ListSubscriptionsByTopic with a TopicArn that is not ARN-shaped at all is rejected with
    InvalidParameter, distinct from the NotFound a well-formed but deleted topic ARN draws, and
    the real topic's listing is unaffected.
    """
    sns = ctx.client("sns")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-lsbtarn-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # Positive control: the real topic's ARN lists fine.
    before = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert before.get("Subscriptions") == [], (
        f"expected an empty subscription list on a fresh topic, got {before.get('Subscriptions')!r}"
    )

    # Break: the identifier is well-typed but has none of an ARN's colon-separated structure,
    # so SNS cannot even parse it far enough to look the topic up.
    code, message = _error(lambda: sns.list_subscriptions_by_topic(TopicArn="not-an-arn"))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a non-ARN TopicArn, got {code!r}"
    )
    assert message == "Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not 1", (
        f"unexpected message for a non-ARN TopicArn: {message!r}"
    )

    # The real topic's listing is unaffected by the rejected call.
    after = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
    assert after.get("Subscriptions") == [], (
        f"expected the listing unchanged after the rejected call, got {after.get('Subscriptions')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
