"""service-update-task-definition-triggers-new-deployment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-update-task-definition-triggers-new-deployment"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService with a new task definition revision creates a fresh PRIMARY
    deployment which stabilizes and supersedes the old one."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    family = ctx.unique_name("sim2real-ecs-fam-")
    rev1 = _register_fargate_task_def(ctx, family, cpu="256", memory="512")
    rev2 = _register_fargate_task_def(ctx, family, cpu="512", memory="1024")
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    network_configuration = {
        "awsvpcConfiguration": {
            "subnets": net["subnets"],
            "securityGroups": net["security_groups"],
            "assignPublicIp": "ENABLED",
        }
    }

    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        taskDefinition=rev1["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=network_configuration,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    )

    def _describe():
        return ecs.describe_services(cluster=cluster["clusterArn"], services=[service_name])["services"][0]

    stable = _poll_until(_describe, lambda svc: svc["runningCount"] == 1, timeout_s=300.0, interval_s=8.0)
    initial_deployment_ids = {d["id"] for d in stable["deployments"]}
    assert stable["taskDefinition"] == rev1["taskDefinitionArn"]

    ecs.update_service(cluster=cluster["clusterArn"], service=service_name, taskDefinition=rev2["taskDefinitionArn"])

    def _rolled_out(svc):
        if svc["taskDefinition"] != rev2["taskDefinitionArn"]:
            return False
        if svc["runningCount"] != svc["desiredCount"]:
            return False
        # Old deployment(s) must have drained out of the deployments list.
        current_ids = {d["id"] for d in svc["deployments"]}
        return not (current_ids & initial_deployment_ids) and len(svc["deployments"]) == 1

    rolled_out = _poll_until(_describe, _rolled_out, timeout_s=420.0, interval_s=10.0)
    assert rolled_out["taskDefinition"] == rev2["taskDefinitionArn"]
    assert rolled_out["deployments"][0]["taskDefinition"] == rev2["taskDefinitionArn"]
    assert rolled_out["deployments"][0]["status"] == "PRIMARY"


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


def _register_fargate_task_def(ctx, family, cpu="256", memory="512", command=None):
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu=cpu,
        memory=memory,
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
