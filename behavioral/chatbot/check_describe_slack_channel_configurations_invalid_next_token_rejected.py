"""describe-slack-channel-configurations-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-slack-channel-configurations-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSlackChannelConfigurations with NextToken "invalid!token!!" fails with InvalidRequestException
    "Invalid request body", while the same call without a NextToken returns SlackChannelConfigurations."""
    chatbot = ctx.client("chatbot")

    code, message = _error(
        lambda: chatbot.describe_slack_channel_configurations(NextToken="invalid!token!!")
    )
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    # Positive control: call without a NextToken succeeds.
    result = chatbot.describe_slack_channel_configurations()
    assert "SlackChannelConfigurations" in result, (
        f"expected SlackChannelConfigurations key in successful response, got keys={list(result)!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
