"""tag-nonexistent-task-definition-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-nonexistent-task-definition-rejected"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a nonexistent task definition revision ARN is rejected with ClientException and
    records no tag, while the same call on the existing revision succeeds and shows in
    ListTagsForResource, so the rejection is specific to the missing resource.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-tagnf-")

    register = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
            }
        ],
    )
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]
    revision = register["taskDefinition"]["revision"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[task_def_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=task_def_arn))

    # Build a well-formed ARN for a revision that was never registered.
    bogus_arn = task_def_arn.rsplit(":", 1)[0] + f":{revision + 5000}"

    # TagResource's documented error surface for an invalid/nonexistent identifier
    # is ClientException (not a dedicated ResourceNotFoundException), per the ECS
    # API reference.
    code, message = _error(
        lambda: ecs.tag_resource(resourceArn=bogus_arn, tags=[{"key": "k", "value": "v"}])
    )
    assert code == "ClientException", f"TagResource on nonexistent revision {bogus_arn}: expected ClientException, got {code!r}"
    assert message == "Unable to describe task definition.", f"TagResource on nonexistent revision {bogus_arn}: unexpected message {message!r}"

    # Effect absent: the nonexistent revision cannot be described (DescribeTaskDefinition
    # reports the same ClientException family for an unresolvable identifier).
    nf_code, nf_message = _error(lambda: ecs.describe_task_definition(taskDefinition=bogus_arn))
    assert nf_code == "ClientException", f"DescribeTaskDefinition on nonexistent revision {bogus_arn}: expected ClientException, got {nf_code!r}"
    assert nf_message == "Unable to describe task definition.", f"DescribeTaskDefinition on nonexistent revision {bogus_arn}: unexpected message {nf_message!r}"

    # Positive control: the identical shape of call against the real resource succeeds.
    ecs.tag_resource(resourceArn=task_def_arn, tags=[{"key": "k", "value": "v"}])
    tags_by_key = {
        t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=task_def_arn)["tags"]
    }
    assert tags_by_key.get("k") == "v", f"expected tag k=v on real task definition {task_def_arn}, got {tags_by_key!r}"


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
