"""create-topic-invalid-attribute-creates-nothing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-topic-invalid-attribute-creates-nothing"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopic with a malformed Policy is refused and creates no topic (GetTopicAttributes on
    its ARN is NotFound), while the same name without attributes then creates normally."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-badcreate-")
    arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{name}"
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    code, message = _error(lambda: sns.create_topic(Name=name, Attributes={"Policy": "{not json"}))
    assert code == "InvalidParameter", f"CreateTopic with a malformed Policy gave {code!r}"
    assert message == "Invalid parameter: Policy Error: null", f"unexpected message for a malformed Policy at create: {message!r}"
    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=arn))
    assert code == "NotFound", f"the refused CreateTopic must create nothing, GetTopicAttributes gave {code!r}"
    assert message == "Topic does not exist", f"unexpected NotFound message: {message!r}"

    created = sns.create_topic(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    assert created == arn, "the same name without the bad attribute must create the topic"
    assert sns.get_topic_attributes(TopicArn=arn)["Attributes"]["TopicArn"] == arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
