"""op-contract-list-tags-for-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-tags-for-resource"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns exactly the tags applied at RegisterTaskDefinition time;
    ClusterNotFoundException when the resourceArn's cluster segment doesn't exist."""
    ecs = ctx.client("ecs")
    sts = ctx.client("sts")

    family = ctx.unique_name("sim2real-ecs-ltfr-td-")
    reg = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
        tags=[{"key": "sim2real-owner", "value": "behavioral-check"}],
    )
    td_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    tag_list = ecs.list_tags_for_resource(resourceArn=td_arn)["tags"]
    assert {"key": "sim2real-owner", "value": "behavioral-check"} in tag_list, (
        f"expected tag sim2real-owner=behavioral-check in {tag_list!r}"
    )
    assert len(tag_list) == 1, f"expected exactly 1 tag on the task definition, got {tag_list!r}"

    account_id = sts.get_caller_identity()["Account"]
    bogus_cluster_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/sim2real-nonexistent-cluster-7712"
    code, message = _error(lambda: ecs.list_tags_for_resource(resourceArn=bogus_cluster_arn))
    assert code == "ClusterNotFoundException", (
        f"ListTagsForResource on a nonexistent cluster ARN returned {code!r}, "
        f"expected 'ClusterNotFoundException'"
    )
    expected_message = 'Cluster not found.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
