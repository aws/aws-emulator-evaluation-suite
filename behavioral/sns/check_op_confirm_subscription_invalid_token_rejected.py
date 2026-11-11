"""op-confirm-subscription-invalid-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-confirm-subscription-invalid-token-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmSubscription must reject a token that was never issued and create no subscription."""
    sns = ctx.client("sns")
    topic_arn = _create_topic(sns, ctx, ctx.unique_name("sim2real-behav-sns-confirm-"), tags=_tags_kv())

    code, message = _error(lambda: sns.confirm_subscription(TopicArn=topic_arn, Token="a" * 64))
    assert code == "InvalidParameter", f"expected InvalidParameter for a bogus token, got {code}"
    expected = 'Invalid parameter: Token'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert subs == [], f"a rejected ConfirmSubscription must not create a subscription, got {subs}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
