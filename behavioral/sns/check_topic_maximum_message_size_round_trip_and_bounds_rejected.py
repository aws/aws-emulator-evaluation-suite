"""topic-maximum-message-size-round-trip-and-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-maximum-message-size-round-trip-and-bounds-rejected"
GROUP = 'topic-attributes'
SERVICES = ['sns']

_MIN = 1024
_MAX = 1048576


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _attrs(sns, arn):
    return sns.get_topic_attributes(TopicArn=arn)["Attributes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaximumMessageSize is absent until set and round-trips inside [1024, 1048576]; a value
    outside is refused InvalidParameter and leaves the last accepted value and DisplayName intact.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-maxmsg-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    base = _attrs(sns, arn)
    assert "MaximumMessageSize" not in base, (
        f"a new topic must report no MaximumMessageSize until one is set, got "
        f"{base.get('MaximumMessageSize')!r}"
    )

    sibling = ctx.unique_name("sim2real-sns-maxmsg-display-")
    sns.set_topic_attributes(TopicArn=arn, AttributeName="DisplayName", AttributeValue=sibling)

    good = 300000
    sns.set_topic_attributes(TopicArn=arn, AttributeName="MaximumMessageSize", AttributeValue=str(good))
    got = _attrs(sns, arn)
    assert got.get("MaximumMessageSize") == str(good), (
        f"MaximumMessageSize must read back as set; expected {good}, got "
        f"{got.get('MaximumMessageSize')!r}"
    )
    assert got.get("DisplayName") == sibling, (
        f"setting MaximumMessageSize must not disturb DisplayName; expected {sibling!r}, got "
        f"{got.get('DisplayName')!r}"
    )

    for bad, label in ((_MIN - 1, "below the minimum"), (_MAX + 1, "above the maximum")):
        code, message = _error(lambda bad=bad: sns.set_topic_attributes(
            TopicArn=arn, AttributeName="MaximumMessageSize", AttributeValue=str(bad)))
        assert code == "InvalidParameter", (
            f"a MaximumMessageSize of {bad} ({label}) must be refused InvalidParameter, got "
            f"{code!r}: {message!r}"
        )
        expected_message = (
            f"Invalid parameter: MaximumMessageSize: {bad} is not an integer between "
            f"{_MIN} and {_MAX} bytes"
        )
        assert message == expected_message, (
            f"expected the exact message {expected_message!r} for {bad} ({label}), got "
            f"{message!r}"
        )
        still = _attrs(sns, arn)
        assert still.get("MaximumMessageSize") == str(good), (
            f"a rejected MaximumMessageSize write ({bad}, {label}) must leave the prior value "
            f"{good} in place, got {still.get('MaximumMessageSize')!r}"
        )
        assert still.get("DisplayName") == sibling, (
            f"a rejected MaximumMessageSize write ({bad}, {label}) must not disturb "
            f"DisplayName either, got {still.get('DisplayName')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
