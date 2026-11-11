"""task-set-create-scale-and-stabilize."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "task-set-create-scale-and-stabilize"
GROUP = "state"
SERVICES = ["ecs"]


SERVICE_DESIRED_COUNT = 4
SCALE_PERCENT = 25.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateTaskSet against an EXTERNAL-controller service places tasks per the
    requested scale and its stabilityStatus progresses to STEADY_STATE."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        # EXTERNAL-controller services don't use desiredCount to drive scaling
        # directly (task sets own the scale), but on real ECS the task set's
        # computedDesiredCount is derived from the service's desiredCount times
        # the task set's scale percentage. A scale of exactly 100% would make
        # computedDesiredCount equal desiredCount regardless of whether the
        # multiplication is actually implemented, so pair a desiredCount > 1
        # with a non-100% scale to make the derivation itself the thing under
        # test.
        desiredCount=SERVICE_DESIRED_COUNT,
        deploymentController={"type": "EXTERNAL"},
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    )

    created = ecs.create_task_set(
        cluster=cluster["clusterArn"],
        service=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        launchType="FARGATE",
        scale={"value": SCALE_PERCENT, "unit": "PERCENT"},
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
    )["taskSet"]
    ts_id = created["id"]
    ctx.on_cleanup(
        lambda: ecs.delete_task_set(
            cluster=cluster["clusterArn"], service=service_name, taskSet=ts_id, force=True
        )
    )
    assert created["scale"]["value"] == SCALE_PERCENT, (
        f"expected created task set scale.value={SCALE_PERCENT}, got {created['scale']}"
    )

    def _describe():
        return ecs.describe_task_sets(
            cluster=cluster["clusterArn"], service=service_name, taskSets=[created["taskSetArn"]]
        )["taskSets"][0]

    stable = _poll_until(
        _describe, lambda ts: ts["stabilityStatus"] == "STEADY_STATE", timeout_s=300.0, interval_s=10.0
    )
    expected_computed = int(SERVICE_DESIRED_COUNT * SCALE_PERCENT / 100)
    assert stable["computedDesiredCount"] == expected_computed, (
        f"expected computedDesiredCount={expected_computed} "
        f"(desiredCount={SERVICE_DESIRED_COUNT} * scale={SCALE_PERCENT}%), "
        f"got {stable['computedDesiredCount']}"
    )
    assert stable["runningCount"] == stable["computedDesiredCount"], (
        f"expected runningCount == computedDesiredCount ({stable['computedDesiredCount']}), "
        f"got runningCount={stable['runningCount']}"
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
    cluster = ecs.create_cluster(clusterName=name)["cluster"]

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
