"""service-tag-empty-string-vs-absent-key-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-tag-empty-string-vs-absent-key-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag with an empty-string value is returned as an empty string (not dropped or nulled),
    while a never-set key is absent from ListTagsForResource, so the two states stay distinct."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-ecs-svctag-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    family = ctx.unique_name("sim2real-ecs-svctag-td-")
    task_def_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = ctx.unique_name("sim2real-ecs-svctag-svc-")
    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=0,
        launchType="EC2",
    )["service"]["serviceArn"]

    def _cleanup_service() -> None:
        ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
        _wait_service_inactive(ctx, cluster_arn, service_arn)

    ctx.on_cleanup(_cleanup_service)

    ecs.tag_resource(
        resourceArn=service_arn,
        tags=[
            {"key": "EmptyValue", "value": ""},
            {"key": "NonEmpty", "value": "present"},
        ],
    )

    tags = ecs.list_tags_for_resource(resourceArn=service_arn)["tags"]
    tags_by_key = {t["key"]: t["value"] for t in tags}

    assert "EmptyValue" in tags_by_key, (
        f"expected an explicit empty-string tag to be present as a key, got {tags_by_key}"
    )
    assert tags_by_key["EmptyValue"] == "", (
        f"expected EmptyValue to round-trip as '', got {tags_by_key['EmptyValue']!r}"
    )
    assert tags_by_key["NonEmpty"] == "present", (
        f"expected NonEmpty == 'present', got {tags_by_key.get('NonEmpty')!r}"
    )
    assert "NeverSet" not in tags_by_key, (
        f"a key that was never tagged must be genuinely absent, got {tags_by_key}"
    )
    assert len(tags_by_key) == 2, (
        f"expected exactly the 2 tags this check applied, got {len(tags_by_key)}: {tags_by_key}"
    )


def _wait_service_inactive(ctx, cluster_arn: str, service_arn: str, timeout_s: float = 40.0) -> None:
    # ctx.run_cleanups() bounds ALL registered cleanups to 60s total, and this callback runs
    # before the task-def/cluster cleanups it must not starve, so its own budget stays well
    # under that ceiling.
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
        services = resp.get("services", [])
        if not services or services[0]["status"] == "INACTIVE":
            return
        time.sleep(2.0)
    raise TimeoutError(f"service {service_arn} did not reach INACTIVE within {timeout_s}s")


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
