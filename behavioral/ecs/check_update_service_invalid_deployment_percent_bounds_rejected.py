"""update-service-invalid-deployment-percent-bounds-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-service-invalid-deployment-percent-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService rejects a deploymentConfiguration whose minimumHealthyPercent (150) is above
    both maximumPercent (100) and the 100 ceiling; ECS names the ceiling in its message."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-ecs-taskdef-")
    taskdef_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "memory": 64,
            "essential": True,
        }],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))

    # desiredCount=0 so the service never needs cluster capacity to place a task
    service_name = ctx.unique_name("sim2real-ecs-svc-")
    ecs.create_service(
        cluster=cluster_name, serviceName=service_name, taskDefinition=taskdef_arn,
        desiredCount=0, launchType="EC2",
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    code, message = _error(lambda: ecs.update_service(
        cluster=cluster_name, service=service_name,
        deploymentConfiguration={"minimumHealthyPercent": 150, "maximumPercent": 100},
    ))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException, got {code}"
    )
    expected_message = "minimumHealthyPercent must be at most 100"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the invalid bounds were not persisted onto the service
    svc = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    depcfg = svc["deploymentConfiguration"]
    assert not (depcfg.get("minimumHealthyPercent") == 150 and depcfg.get("maximumPercent") == 100)

    # positive control: a valid bound (min <= max) is accepted and persisted
    ecs.update_service(
        cluster=cluster_name, service=service_name,
        deploymentConfiguration={"minimumHealthyPercent": 50, "maximumPercent": 150},
    )
    svc = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    depcfg = svc["deploymentConfiguration"]
    assert depcfg["minimumHealthyPercent"] == 50
    assert depcfg["maximumPercent"] == 150


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
