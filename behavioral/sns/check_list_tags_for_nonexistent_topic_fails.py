"""list-tags-for-nonexistent-topic-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-nonexistent-topic-fails"
GROUP = 'tagging'
SERVICES = ['sns']


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _deleted_topic_arn(ctx):
    """Create a topic, prove ListTagsForResource works on it live, delete it, and return its TopicArn."""
    sns = ctx.client("sns")
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-sns-topic-"),
        Tags=[{"Key": "sim2real", "Value": "behav-sns-list-tags-nonexistent"}],
    )["TopicArn"]
    # Registered anyway so a failure between create and delete cannot leak.
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    live_tags = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert {t["Key"]: t["Value"] for t in live_tags}.get("sim2real") == "behav-sns-list-tags-nonexistent", (
        f"positive control failed: expected the sim2real tag on the live topic, got {live_tags}"
    )

    sns.delete_topic(TopicArn=arn)
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a deleted topic fails with ResourceNotFound, after succeeding on
    the same topic while it was live (so a blanket refusal cannot pass).
    """
    sns = ctx.client("sns")
    arn = _deleted_topic_arn(ctx)
    code, message = _error(lambda: sns.list_tags_for_resource(ResourceArn=arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = 'Resource does not exist'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
