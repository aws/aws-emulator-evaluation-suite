"""topic-feedback-sample-rate-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-feedback-sample-rate-out-of-range-rejected"
GROUP = 'topic-attributes'
SERVICES = ['sns']


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
    """SQSSuccessFeedbackSampleRate outside [0, 100], or not a number, is refused InvalidParameter
    and leaves the attribute unset (not clamped), while the boundary 100 is accepted and read back.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-fbrate-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    for bad in ("101", "-1", "abc"):
        code, message = _error(lambda bad=bad: sns.set_topic_attributes(
            TopicArn=arn, AttributeName="SQSSuccessFeedbackSampleRate", AttributeValue=bad))
        assert code == "InvalidParameter", (
            f"a SQSSuccessFeedbackSampleRate of {bad!r} must be refused InvalidParameter, got "
            f"{code!r}: {message!r}"
        )
        expected_message = (
            f"Invalid parameter: SQSSuccessFeedbackSampleRate: {bad} value provided is not an "
            f"integer between 0-100"
        )
        assert message == expected_message, (
            f"expected the exact message {expected_message!r} for {bad!r}, got {message!r}"
        )
        still = _attrs(sns, arn)
        assert "SQSSuccessFeedbackSampleRate" not in still, (
            f"a rejected sample rate must leave the attribute unset, got "
            f"{still.get('SQSSuccessFeedbackSampleRate')!r}"
        )

    # Positive control: the boundary value itself is accepted.
    sns.set_topic_attributes(TopicArn=arn, AttributeName="SQSSuccessFeedbackSampleRate", AttributeValue="100")
    final = _attrs(sns, arn)
    assert final.get("SQSSuccessFeedbackSampleRate") == "100", (
        f"a sample rate of 100 must be accepted and read back exactly, got "
        f"{final.get('SQSSuccessFeedbackSampleRate')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
