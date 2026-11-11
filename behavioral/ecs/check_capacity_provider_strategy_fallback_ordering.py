"""capacity-provider-strategy-fallback-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-provider-strategy-fallback-ordering"
GROUP = "ordering"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A strategy with `base` on the primary provider and all the `weight` on the secondary
    places exactly the base count on the primary and every further task on the secondary,
    by base/weight resolution rather than an arbitrary split."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)
    cluster_arn, _cluster_name = _create_cluster(ctx)

    ecs.put_cluster_capacity_providers(
        cluster=cluster_arn,
        capacityProviders=["FARGATE", "FARGATE_SPOT"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1, "base": 0}],
    )

    task_def_arn = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-td-"), ["sleep", "120"])

    # base=1 on FARGATE guarantees exactly one task there; weight=0 means FARGATE
    # gets NO share of the remaining (non-base) tasks. weight=1 on FARGATE_SPOT
    # means every task beyond the base allocation must fall back to FARGATE_SPOT.
    resp = ecs.run_task(
        cluster=cluster_arn,
        taskDefinition=task_def_arn,
        count=2,
        capacityProviderStrategy=[
            {"capacityProvider": "FARGATE", "base": 1, "weight": 0},
            {"capacityProvider": "FARGATE_SPOT", "base": 0, "weight": 1},
        ],
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    assert not resp["failures"], f"unexpected RunTask failures: {resp['failures']}"
    tasks = resp["tasks"]
    task_arns = [t["taskArn"] for t in tasks]
    for arn in task_arns:
        ctx.on_cleanup(lambda a=arn: _try(lambda: ecs.stop_task(cluster=cluster_arn, task=a, reason="cleanup")))
    assert len(tasks) == 2, f"expected 2 tasks placed, got {len(tasks)}"

    providers = sorted(t["capacityProviderName"] for t in tasks)
    assert providers == ["FARGATE", "FARGATE_SPOT"], (
        f"expected exactly one task on FARGATE (the base allocation) and one falling "
        f"back to FARGATE_SPOT (the only provider with weight > 0), got {providers}"
    )

    # Independent read: RunTask's own response is the mutating call, so confirm the
    # placement it reported actually stuck by re-reading through DescribeTasks.
    described = ecs.describe_tasks(cluster=cluster_arn, tasks=task_arns)["tasks"]
    assert len(described) == 2, f"expected DescribeTasks to return 2 tasks, got {len(described)}"
    described_providers = sorted(t["capacityProviderName"] for t in described)
    assert described_providers == ["FARGATE", "FARGATE_SPOT"], (
        f"independent DescribeTasks read disagrees with the RunTask placement: expected one "
        f"task on FARGATE (base) and one on FARGATE_SPOT (fallback), got {described_providers}"
    )

    for arn in task_arns:
        _try(lambda a=arn: ecs.stop_task(cluster=cluster_arn, task=a, reason="sim2real cleanup"))
    _wait_for_tasks_stopped(ctx, cluster_arn, task_arns, timeout_s=180)
    _try(lambda: ecs.put_cluster_capacity_providers(
        cluster=cluster_arn, capacityProviders=[], defaultCapacityProviderStrategy=[]
    ), retry_codes=("ResourceInUseException", "UpdateInProgressException"))


def _default_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch Fargate tasks")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch Fargate tasks into")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx) -> tuple[str, str]:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-")
    arn = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]

    ctx.on_cleanup(lambda: _try(
        lambda: ecs.delete_cluster(cluster=arn),
        retry_codes=("ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException"),
    ))
    return arn, name


def _register_fargate_task_def(ctx, family: str, command: list[str]) -> str:
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _wait_for_tasks_stopped(ctx, cluster_arn: str, task_arns: list[str], timeout_s: float = 180.0) -> None:
    ecs = ctx.client("ecs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        running = ecs.list_tasks(cluster=cluster_arn, desiredStatus="RUNNING")["taskArns"]
        pending = ecs.list_tasks(cluster=cluster_arn, desiredStatus="PENDING")["taskArns"]
        if not (set(task_arns) & (set(running) | set(pending))):
            return
        time.sleep(2)


def _try(fn, retry_codes=(), timeout_s: float = 120.0) -> None:
    """Run a teardown call: an already-gone cluster or task is fine, a code in retry_codes
    (a dependency still being released) is retried every 2 s to the deadline, the rest raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ClusterNotFoundException" or (
                err["Code"] == "InvalidParameterException" and "not found" in err.get("Message", "")
            ):
                return
            if err["Code"] not in retry_codes or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
