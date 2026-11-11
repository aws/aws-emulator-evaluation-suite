"""create-topic-idempotent-and-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-topic-idempotent-and-conflict"
GROUP = 'topic-lifecycle'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises, so an over-permissive target cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTopic is idempotent for identical name+attributes but rejects a name reused with different attributes."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-idem-")
    tags_kv = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]
    resp1 = sns.create_topic(Name=name, Attributes={"DisplayName": "first"}, Tags=tags_kv)
    arn1 = resp1["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn1))

    resp2 = sns.create_topic(Name=name, Attributes={"DisplayName": "first"})
    assert resp2["TopicArn"] == arn1, "re-creating with identical attributes must return the same TopicArn"

    code, message = _error(
        lambda: sns.create_topic(Name=name, Attributes={"DisplayName": "different"})
    )
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for name reused with different attributes, got {code}"
    )
    assert message == "Invalid parameter: Attributes Reason: Topic already exists with different attributes", (
        f"unexpected InvalidParameter message for a name reused with different attributes: {message!r}"
    )

    attrs = sns.get_topic_attributes(TopicArn=arn1)["Attributes"]
    assert attrs["DisplayName"] == "first", (
        "rejected conflicting CreateTopic must not mutate the existing topic's attributes, "
        f"got DisplayName={attrs.get('DisplayName')!r}"
    )

    sns.delete_topic(TopicArn=arn1)
    resp3 = sns.create_topic(Name=name, Attributes={"DisplayName": "different"})
    assert resp3["TopicArn"] == arn1, (
        f"freeing the conflicting name should let it be recreated at the same ARN, got {resp3['TopicArn']}"
    )
    attrs3 = sns.get_topic_attributes(TopicArn=arn1)["Attributes"]
    assert attrs3["DisplayName"] == "different", (
        "once the conflicting name is freed, the identical call that was rejected must now succeed "
        f"with its own attributes, got DisplayName={attrs3.get('DisplayName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
