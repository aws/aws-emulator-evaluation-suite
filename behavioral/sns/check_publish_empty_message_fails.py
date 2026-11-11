"""publish-empty-message-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-empty-message-fails"
GROUP = 'publish'
SERVICES = ['sns']


def _client_error(fn):
    """Return the Error dict of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_topic(ctx, name=None):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(
        Name=name, Tags=[{"Key": "sim2real", "Value": "behavioral"}]
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Publish with an empty Message is refused with InvalidParameter, while a non-empty publish
    to the same topic succeeds (so the refusal is due to the empty Message).
    """
    sns = ctx.client("sns")
    arn = _create_topic(ctx)

    message_id = sns.publish(TopicArn=arn, Message="positive control")["MessageId"]
    assert message_id, "the positive control publish did not return a MessageId"

    error = _client_error(lambda: sns.publish(TopicArn=arn, Message=""))
    assert error.get("Code") == "InvalidParameter", (
        f"expected InvalidParameter for an empty Message, got {error.get('Code')!r}"
    )
    assert error.get('Message') == 'Invalid parameter: Empty message', (
        f"expected the exact message 'Invalid parameter: Empty message', got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
