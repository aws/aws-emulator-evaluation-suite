"""tag-resource-lifecycle-and-limit."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle-and-limit"
GROUP = 'tagging'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource mutate the tag set as expected, and exceeding 50 tags is rejected."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-topic-tags-")
    arn = sns.create_topic(Name=name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))

    sns.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "test"}])
    tags = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert {"Key": "env", "Value": "test"} in tags, f"expected tag env=test present, got {tags}"

    sns.untag_resource(ResourceArn=arn, TagKeys=["env"])
    tags = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert all(t["Key"] != "env" for t in tags), f"expected tag 'env' removed, still present in {tags}"

    too_many = [{"Key": f"k{i}", "Value": "v"} for i in range(51)]
    code, message = _error(lambda: sns.tag_resource(ResourceArn=arn, Tags=too_many))
    assert code == "TagLimitExceeded", f"expected TagLimitExceeded for >50 tags, got {code}"
    assert message == "Could not complete request: tag quota of per resource exceeded", f"unexpected TagLimitExceeded message: {message!r}"

    surviving = sns.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert not any(t["Key"].startswith("k") for t in surviving), (
        f"rejected tag_resource must not partially apply tags, found {surviving}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
