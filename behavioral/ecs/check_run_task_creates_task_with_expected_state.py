"""run-task-creates-task-with-expected-state."""

from __future__ import annotations


from behavioral_harness import tags

CHECK = "run-task-creates-task-with-expected-state"
GROUP = "task-execution"
SERVICES = ["ecs"]

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]

# Prefix for failures where no task was placed: ECS RunTask needs a real container runtime
# to place a task, so such a failure is a data-plane gap rather than a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RunTask produces a task whose desiredStatus is RUNNING and whose
    lastStatus starts somewhere in the provisioning pipeline."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    _vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if not _vpcs:
        raise AssertionError("no shared network VPC available for Fargate tasks")
    subnets = [
        s["SubnetId"]
        for s in ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [_vpcs[0]["VpcId"]]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        ).get("Subnets", [])
    ]
    if not subnets:
        raise AssertionError("shared network has no network subnets")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(
            taskDefinitions=[a]
        )
    )
    ctx.on_cleanup(
        lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(
            taskDefinition=a
        )
    )
    resp = ecs.run_task(
        cluster=cluster["clusterName"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
    )
    for _t in resp.get("tasks", []):
        ctx.on_cleanup(
            lambda cl=cluster["clusterName"], ta=_t["taskArn"]: ecs.stop_task(
                cluster=cl, task=ta
            )
        )
    assert not resp.get("failures"), f"unexpected failures: {resp.get('failures')}"
    tasks = resp.get("tasks", [])
    assert len(tasks) == 1, f"expected exactly 1 task from RunTask, got {len(tasks)}: {tasks}"
    task = tasks[0]
    # Placing a task needs a real container runtime; a target that records the API call but places
    # nothing reports a different desiredStatus.
    assert task["desiredStatus"] == "RUNNING", (
        f"{DATAPLANE_MARKER}: "
        f"expected desiredStatus RUNNING, got {task['desiredStatus']}"
    )
    assert task["lastStatus"] in (
        "PROVISIONING",
        "PENDING",
        "ACTIVATING",
        "RUNNING",
    ), f"unexpected lastStatus {task['lastStatus']}"
    assert td["taskDefinitionArn"] == task["taskDefinitionArn"], (
        f"expected taskDefinitionArn {td['taskDefinitionArn']}, got {task['taskDefinitionArn']}"
    )

    # The RunTask response is the mutating call's own echo. Confirm the task is real by
    # reading it back through an independent operation — a target that fabricates a RunTask
    # response without persisting anything server-side would pass the assertions above but
    # fail this one.
    described = ecs.describe_tasks(
        cluster=cluster["clusterName"], tasks=[task["taskArn"]]
    ).get("tasks", [])
    assert described, (
        f"task {task['taskArn']} from RunTask is not visible via an independent "
        f"DescribeTasks read"
    )
    read_back = described[0]
    assert read_back["desiredStatus"] == "RUNNING", (
        f"{DATAPLANE_MARKER}: "
        f"independent DescribeTasks read expected desiredStatus RUNNING, got {read_back['desiredStatus']}"
    )
    assert read_back["lastStatus"] in (
        "PROVISIONING",
        "PENDING",
        "ACTIVATING",
        "RUNNING",
    ), f"independent DescribeTasks read got unexpected lastStatus {read_back['lastStatus']}"
    assert read_back["taskDefinitionArn"] == td["taskDefinitionArn"], (
        f"independent DescribeTasks read expected taskDefinitionArn {td['taskDefinitionArn']}, "
        f"got {read_back['taskDefinitionArn']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
