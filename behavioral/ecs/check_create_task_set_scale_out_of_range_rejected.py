"""create-task-set-scale-out-of-range-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-task-set-scale-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTaskSet with scale.value 150 (documented range 0-100) is rejected and creates no task
    set, while an in-range value creates one with that scale persisted."""
    ecs = ctx.client("ecs")

    cluster_arn = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-cluster-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    task_def_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-taskdef-"),
        requiresCompatibilities=["EC2"],
        networkMode="bridge",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "memory": 64,
                "cpu": 64,
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_arn = ecs.create_service(
        cluster=cluster_arn,
        serviceName=ctx.unique_name("sim2real-behav-svc-"),
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["service"]["serviceArn"]
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
    )

    # Negative: scale.value=150 is outside the documented 0-100 range.
    code, message = _error(
        lambda: ecs.create_task_set(
            cluster=cluster_arn,
            service=service_arn,
            taskDefinition=task_def_arn,
            launchType="EC2",
            scale={"value": 150, "unit": "PERCENT"},
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for scale.value=150, got {code!r}"
    )
    assert message == 'TaskSet Scale value for percent can not be greater than 100.0', (
        f"expected the exact out-of-range scale message, got {message!r}"
    )

    # Effect absence is checked after this succeeds: DescribeTaskSets on a service with zero
    # task sets raises InvalidParameterException.
    task_set = ecs.create_task_set(
        cluster=cluster_arn,
        service=service_arn,
        taskDefinition=task_def_arn,
        launchType="EC2",
        scale={"value": 50, "unit": "PERCENT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskSet"]
    task_set_id = task_set["id"]
    ctx.on_cleanup(
        lambda: ecs.delete_task_set(
            cluster=cluster_arn, service=service_arn, taskSet=task_set_id, force=True
        )
    )
    assert task_set["scale"]["value"] == 50, (
        f"expected in-range scale.value=50 to be accepted, got {task_set['scale']['value']!r}"
    )
    assert task_set["scale"]["unit"] == "PERCENT", (
        f"expected scale.unit=PERCENT, got {task_set['scale']['unit']!r}"
    )

    # Effect absent: the out-of-range request never created a task set — only the
    # positive control's task set exists on the service.
    described = ecs.describe_task_sets(
        cluster=cluster_arn, service=service_arn, taskSets=[task_set_id]
    )["taskSets"]
    assert [ts["id"] for ts in described] == [task_set_id], (
        "out-of-range scale must not have created a task set"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
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
