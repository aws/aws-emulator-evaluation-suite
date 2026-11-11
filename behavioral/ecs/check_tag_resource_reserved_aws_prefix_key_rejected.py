"""tag-resource-reserved-aws-prefix-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key using the reserved 'aws:' prefix rather than persisting it."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-tag-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    code, message = _error(lambda: ecs.tag_resource(
        resourceArn=cluster_arn, tags=[{"key": "aws:sim2real-test", "value": "x"}],
    ))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Tag key must not start with aws:", f"unexpected error message: {message!r}"

    # effect absent: the reserved-prefix tag was not persisted
    current_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert not any(t["key"] == "aws:sim2real-test" for t in current_tags), (
        f"reserved-prefix tag leaked into current_tags: {current_tags}"
    )

    # positive control: a normal tag key is accepted and persisted
    ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": "sim2real-env", "value": "test"}])
    current_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert any(t["key"] == "sim2real-env" and t["value"] == "test" for t in current_tags), (
        f"expected sim2real-env=test in current_tags, got {current_tags}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
