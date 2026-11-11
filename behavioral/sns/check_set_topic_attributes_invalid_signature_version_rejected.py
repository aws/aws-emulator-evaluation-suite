"""set-topic-attributes-invalid-signature-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-topic-attributes-invalid-signature-version-rejected"
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


def _value(sns, arn):
    return sns.get_topic_attributes(TopicArn=arn)["Attributes"].get("SignatureVersion")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetTopicAttributes refuses SignatureVersion=3, a value outside its closed vocabulary,
    and stores nothing; the legal value 2 is then accepted and read back.
    """
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-badsignatureversion-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    assert _value(sns, arn) is None, f"a new topic reports no SignatureVersion until one is set, got {_value(sns, arn)!r}"

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=arn, AttributeName="SignatureVersion", AttributeValue="3"))
    assert code == "InvalidParameter", f"SignatureVersion=3 gave {code!r}"
    assert message == "Invalid parameter: SignatureVersion: Invalid value '[3]'. Must be 1 or 2.", f"unexpected message for SignatureVersion=3: {message!r}"
    assert _value(sns, arn) is None, (
        f"the refused write must store nothing, but SignatureVersion reads {_value(sns, arn)!r}"
    )

    sns.set_topic_attributes(TopicArn=arn, AttributeName="SignatureVersion", AttributeValue="2")
    assert _value(sns, arn) == "2", f"SignatureVersion=2 must be stored, got {_value(sns, arn)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
