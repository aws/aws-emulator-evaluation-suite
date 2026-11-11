"""get-topic-attributes-malformed-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-topic-attributes-malformed-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTopicAttributes must reject a malformed TopicArn with InvalidParameter (not
    NotFound), never leaking any attributes; a well-formed ARN for the same topic still
    resolves correctly, both before and after the bad call."""
    ev = ctx.client("sns")
    tag_set = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]
    topic_arn = ev.create_topic(Name=ctx.unique_name("sim2real-behav-gta-arn-"), Tags=tag_set)["TopicArn"]
    ctx.on_cleanup(lambda: ev.delete_topic(TopicArn=topic_arn))

    # Positive control: a well-formed ARN resolves attributes.
    before = ev.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert before["TopicArn"] == topic_arn, (
        f"expected positive control to resolve {topic_arn!r}, got {before.get('TopicArn')!r}"
    )

    # Break exactly one thing: a TopicArn that isn't even ARN-shaped.
    malformed_arn = "this-is-not-an-arn"
    result = {}
    code, message = _error(lambda: result.update(ev.get_topic_attributes(TopicArn=malformed_arn)))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for a malformed TopicArn, got {code}"
    )
    expected = 'Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not 1'
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # Effect absent: nothing was returned by the rejected call.
    assert "Attributes" not in result, f"rejected call leaked attributes: {result}"

    # The rejected call left service state untouched: the valid ARN still resolves.
    after = ev.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert after["TopicArn"] == topic_arn, (
        f"expected valid ARN to still resolve after the rejected call, got {after.get('TopicArn')!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so a target that accepts what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
