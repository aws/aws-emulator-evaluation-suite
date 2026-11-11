"""service-scales-and-force-deletes-to-inactive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-scales-and-force-deletes-to-inactive"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateService brings runningCount up to desiredCount, UpdateService scales it
    further, and force-DeleteService drains the service ACTIVE->DRAINING->INACTIVE."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    network_configuration = {
        "awsvpcConfiguration": {
            "subnets": net["subnets"],
            "securityGroups": net["security_groups"],
            "assignPublicIp": "ENABLED",
        }
    }

    created = ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=network_configuration,
        tags=[{"key": "sim2real", "value": "true"}],
    )["service"]
    assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']!r}"
    assert created["desiredCount"] == 1, f"expected desiredCount=1 on create, got {created['desiredCount']!r}"

    def _describe():
        return ecs.describe_services(cluster=cluster["clusterArn"], services=[service_name])["services"][0]

    stable = _poll_until(_describe, lambda svc: svc["runningCount"] == 1, timeout_s=300.0, interval_s=8.0)
    assert stable["runningCount"] == 1, f"expected runningCount=1 after create, got {stable['runningCount']!r}"

    ecs.update_service(cluster=cluster["clusterArn"], service=service_name, desiredCount=2)
    scaled = _poll_until(_describe, lambda svc: svc["runningCount"] == 2, timeout_s=300.0, interval_s=8.0)
    assert scaled["desiredCount"] == 2 and scaled["runningCount"] == 2, (
        f"expected desiredCount=2 and runningCount=2 after scale-up, "
        f"got desiredCount={scaled['desiredCount']!r} runningCount={scaled['runningCount']!r}"
    )

    deleted = ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)["service"]
    assert deleted["status"] in ("DRAINING", "INACTIVE"), (
        f"expected DRAINING or INACTIVE on force-delete response, got {deleted['status']!r}"
    )

    final_status = _poll_until(
        lambda: _describe()["status"], lambda s: s == "INACTIVE", timeout_s=240.0, interval_s=8.0
    )
    assert final_status == "INACTIVE", f"expected terminal status INACTIVE, got {final_status!r}"


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
    cluster = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]

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
