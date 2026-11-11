"""update-service-primary-task-set-switches-primary."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-service-primary-task-set-switches-primary"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServicePrimaryTaskSet promotes the target task set to PRIMARY and demotes
    the formerly-primary task set to ACTIVE."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        # EXTERNAL-controller services don't use desiredCount for scaling (task sets
        # own the scale), but real ECS still requires the parameter to be present.
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    )

    network_configuration = {
        "awsvpcConfiguration": {
            "subnets": net["subnets"],
            "securityGroups": net["security_groups"],
            "assignPublicIp": "ENABLED",
        }
    }

    def _create_task_set():
        ts = ecs.create_task_set(
            cluster=cluster["clusterArn"],
            service=service_name,
            taskDefinition=task_def["taskDefinitionArn"],
            launchType="FARGATE",
            scale={"value": 50.0, "unit": "PERCENT"},
            networkConfiguration=network_configuration,
            tags=[{"key": "sim2real", "value": "true"}],
        )["taskSet"]
        ctx.on_cleanup(
            lambda ts_id=ts["id"]: ecs.delete_task_set(
                cluster=cluster["clusterArn"], service=service_name, taskSet=ts_id, force=True
            )
        )
        return ts

    task_set_a = _create_task_set()
    promoted_a = ecs.update_service_primary_task_set(
        cluster=cluster["clusterArn"], service=service_name, primaryTaskSet=task_set_a["taskSetArn"]
    )["taskSet"]
    assert promoted_a["status"] == "PRIMARY", f"expected PRIMARY, got {promoted_a['status']}"

    task_set_b = _create_task_set()

    def _statuses():
        sets = ecs.describe_task_sets(
            cluster=cluster["clusterArn"],
            service=service_name,
            taskSets=[task_set_a["taskSetArn"], task_set_b["taskSetArn"]],
        )["taskSets"]
        return {s["taskSetArn"]: s["status"] for s in sets}

    promoted_b = ecs.update_service_primary_task_set(
        cluster=cluster["clusterArn"], service=service_name, primaryTaskSet=task_set_b["taskSetArn"]
    )["taskSet"]
    assert promoted_b["status"] == "PRIMARY", f"expected PRIMARY, got {promoted_b['status']}"

    # Independent read (DescribeTaskSets, not the mutating call's own response) of BOTH task
    # sets at once: the flip must land as a single atomic transition, never a state where the
    # newly-promoted set is PRIMARY but the old one has not yet been demoted (or vice versa).
    final = _poll_until(
        _statuses,
        lambda s: s.get(task_set_a["taskSetArn"]) == "ACTIVE" and s.get(task_set_b["taskSetArn"]) == "PRIMARY",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final[task_set_a["taskSetArn"]] == "ACTIVE", (
        f"former primary should demote to ACTIVE, got {final[task_set_a['taskSetArn']]}"
    )
    assert final[task_set_b["taskSetArn"]] == "PRIMARY", (
        f"newly-promoted task set should read PRIMARY via an independent read, got {final[task_set_b['taskSetArn']]}"
    )


from botocore.exceptions import ClientError


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError("no subnets available in VPC to place Fargate tasks")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    return {
        "subnets": [s["SubnetId"] for s in subnets[:2]],
        "security_groups": [sgs[0]["GroupId"]] if sgs else [],
    }


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]

    def _cleanup(arn=cluster["clusterArn"]):
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return cluster


def _register_fargate_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command or ["sleep", "600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td = resp["taskDefinition"]

    def _cleanup(arn=td["taskDefinitionArn"]):
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)
    return td


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
