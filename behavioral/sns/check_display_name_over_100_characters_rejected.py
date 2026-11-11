"""display-name-over-100-characters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "display-name-over-100-characters-rejected"
GROUP = 'topic-attributes'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _display(sns, arn):
    return sns.get_topic_attributes(TopicArn=arn)["Attributes"].get("DisplayName")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes refuses a 101-character DisplayName and keeps the earlier value, while
    a 100-character DisplayName, the documented maximum, is accepted and read back."""
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-longdn-"),
                           Attributes={"DisplayName": "before"},
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=arn, AttributeName="DisplayName", AttributeValue="d" * 101))
    assert code == "InvalidParameter", f"a 101-character DisplayName gave {code!r}"
    assert message == "Invalid parameter: DisplayName", f"unexpected message for a 101-character DisplayName: {message!r}"
    assert _display(sns, arn) == "before", f"the refused write must keep DisplayName, got {_display(sns, arn)!r}"

    sns.set_topic_attributes(TopicArn=arn, AttributeName="DisplayName", AttributeValue="d" * 100)
    assert _display(sns, arn) == "d" * 100, "a 100-character DisplayName must be stored"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
