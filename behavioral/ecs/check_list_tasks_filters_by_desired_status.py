"""list-tasks-filters-by-desired-status."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-tasks-filters-by-desired-status"
GROUP = 'task-execution'
SERVICES = ['ecs']

FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/docker/library/busybox:1.36",
        "essential": True,
        "command": ["sh", "-c", "sleep 3600"],
    }
]

@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTasks with desiredStatus=STOPPED excludes tasks that are still
    desired RUNNING."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    _vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]
    ).get("Vpcs", [])
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
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    resp = ecs.run_task(
        cluster=cluster["clusterName"],
        taskDefinition=td["taskDefinitionArn"],
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
    )
    for _t in resp.get("tasks", []):
        ctx.on_cleanup(lambda cl=cluster["clusterName"], ta=_t["taskArn"]: ecs.stop_task(cluster=cl, task=ta))
    task_arn = resp["tasks"][0]["taskArn"]

    running_arns = ecs.list_tasks(
        cluster=cluster["clusterName"], desiredStatus="RUNNING"
    ).get("taskArns", [])
    assert task_arn in running_arns, "freshly run task missing from RUNNING filter"

    stopped_arns = ecs.list_tasks(
        cluster=cluster["clusterName"], desiredStatus="STOPPED"
    ).get("taskArns", [])
    assert task_arn not in stopped_arns, (
        "task with desiredStatus RUNNING should not appear in STOPPED filter"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
