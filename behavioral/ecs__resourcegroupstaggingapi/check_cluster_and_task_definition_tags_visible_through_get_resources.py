"""cluster-and-task-definition-tags-visible-through-get-resources."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-and-task-definition-tags-visible-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["ecs", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at creation on an ECS cluster and a task definition are both found by GetResources,
    ResourceTypeFilters separates ecs:cluster from ecs:task-definition, and a deregistered
    (INACTIVE) revision keeps its tags and stays in the tagging index.
    """
    ecs = ctx.client("ecs")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": key, "value": value}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-behav-td-")
    td = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[{
            "name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
            "essential": True, "command": ["sleep", "3600"],
        }],
        tags=[{"key": key, "value": value}],
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister_and_delete(ecs, td_arn))

    found = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["ecs:cluster", "ecs:task-definition"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: {m["ResourceARN"] for m in mappings} == {cluster_arn, td_arn},
        timeout_s=120.0,
    )
    arns = {m["ResourceARN"] for m in found}
    assert arns == {cluster_arn, td_arn}, (
        f"tag filter {key}={value!r} with ResourceTypeFilters=[ecs:cluster, "
        f"ecs:task-definition] returned {sorted(arns)!r}, expected exactly the cluster "
        f"{cluster_arn!r} and the task definition {td_arn!r}"
    )

    # ResourceTypeFilters narrows: a cluster-only filter must not surface the task definition.
    cluster_only = rgt.get_resources(
        ResourceTypeFilters=["ecs:cluster"],
        TagFilters=[{"Key": key, "Values": [value]}],
    )["ResourceTagMappingList"]
    cluster_only_arns = {m["ResourceARN"] for m in cluster_only}
    assert cluster_only_arns == {cluster_arn}, (
        f"ResourceTypeFilters=[ecs:cluster] returned {sorted(cluster_only_arns)!r}, expected "
        f"exactly the cluster {cluster_arn!r} and NOT the task definition"
    )

    deregistered = ecs.deregister_task_definition(taskDefinition=td_arn)["taskDefinition"]
    assert deregistered["status"] == "INACTIVE", (
        f"DeregisterTaskDefinition left status={deregistered['status']!r}, expected 'INACTIVE'"
    )

    # The deregistered revision is a state transition, not an erasure: DescribeTaskDefinition
    # still resolves it, and its tags are unchanged.
    described = ecs.describe_task_definition(taskDefinition=td_arn, include=["TAGS"])
    assert described["taskDefinition"]["status"] == "INACTIVE", (
        f"DescribeTaskDefinition on a deregistered revision reports status="
        f"{described['taskDefinition']['status']!r}, expected 'INACTIVE'"
    )
    native_tag_map = {t["key"]: t["value"] for t in described.get("tags", [])}
    assert native_tag_map.get(key) == value, (
        f"a deregistered task definition's own tags are {native_tag_map!r}, missing "
        f"{key}={value!r} -- deregistering must not strip tags"
    )

    # And the tagging-api index still reports the deregistered revision's ARN: INACTIVE is a
    # lifecycle state visible through DescribeTaskDefinition, not a removal from the index.
    still_indexed = rgt.get_resources(
        ResourceTypeFilters=["ecs:task-definition"],
        TagFilters=[{"Key": key, "Values": [value]}],
    )["ResourceTagMappingList"]
    still_indexed_arns = {m["ResourceARN"] for m in still_indexed}
    assert td_arn in still_indexed_arns, (
        f"after DeregisterTaskDefinition, GetResources(ResourceTypeFilters=[ecs:task-definition]) "
        f"returned {sorted(still_indexed_arns)!r}, which no longer includes the INACTIVE "
        f"revision {td_arn!r} -- deregistering is a state transition, not a removal from the index"
    )


# ===== helpers =====
def _deregister_and_delete(ecs, td_arn):
    """DeregisterTaskDefinition only marks a revision INACTIVE -- it is not a delete.
    DeleteTaskDefinitions is the real teardown and requires INACTIVE first."""
    from botocore.exceptions import ClientError

    try:
        ecs.deregister_task_definition(taskDefinition=td_arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
        ):
            raise
    ecs.delete_task_definitions(taskDefinitions=[td_arn])


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
