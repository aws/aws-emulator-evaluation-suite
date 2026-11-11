"""create-topic-with-different-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-topic-with-different-tags-rejected"
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


def _tags(sns, arn):
    return {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=arn)["Tags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-running CreateTopic on an existing name with different Tags is refused and leaves the
    tags untouched; identical Tags or no Tags is idempotent and returns the same TopicArn."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-tagconf-")
    original = [{"Key": "sim2real", "Value": CHECK}, {"Key": "team", "Value": "alpha"}]
    arn = sns.create_topic(Name=name, Tags=original)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    same = sns.create_topic(Name=name, Tags=original)["TopicArn"]
    assert same == arn, "CreateTopic with identical Tags must return the existing TopicArn"
    bare = sns.create_topic(Name=name)["TopicArn"]
    assert bare == arn, "CreateTopic with no Tags on an existing name must return the existing TopicArn"

    changed = [{"Key": "sim2real", "Value": CHECK}, {"Key": "team", "Value": "beta"}]
    code, message = _error(lambda: sns.create_topic(Name=name, Tags=changed))
    assert code == "InvalidParameter", f"CreateTopic with different Tags gave {code!r}"
    assert message == "Invalid parameter: Tags Reason: Topic already exists with different tags", (
        f"unexpected message for CreateTopic with different Tags: {message!r}"
    )

    stored = _tags(sns, arn)
    assert stored == {"sim2real": CHECK, "team": "alpha"}, (
        f"the refused CreateTopic must not change the topic's tags, got {stored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
