"""service-delete-active-desired-count-without-force-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-delete-active-desired-count-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteService without force=True is rejected while desiredCount is still > 0, and the
    identical call (still no force) succeeds once desiredCount is restored to 0 — the positive
    control that separates "rejects this state" from "rejects every DeleteService"."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        taskDefinition=task_def["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": net["subnets"],
                "securityGroups": net["security_groups"],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    )

    code, message = _error(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "The service cannot be stopped while it is scaled above 0.", f"unexpected error message: {message!r}"

    still_active = ecs.describe_services(cluster=cluster["clusterArn"], services=[service_name])["services"][0]
    assert still_active["status"] == "ACTIVE", "service must remain ACTIVE after the rejected delete"
    assert still_active["desiredCount"] == 1, (
        f"desiredCount must be unaffected by the rejected delete, got {still_active['desiredCount']}"
    )

    # restore: once desiredCount (and the tasks it drives) reach 0, the identical DeleteService
    # call — still with no force — must succeed.
    ecs.update_service(cluster=cluster["clusterArn"], service=service_name, desiredCount=0)
    _poll_until(
        lambda: ecs.describe_services(cluster=cluster["clusterArn"], services=[service_name])["services"][0],
        lambda s: s["desiredCount"] == 0 and s["runningCount"] == 0,
        timeout_s=300.0,
        interval_s=8.0,
    )
    deleted = ecs.delete_service(cluster=cluster["clusterArn"], service=service_name)["service"]
    assert deleted["status"] in ("DRAINING", "INACTIVE"), (
        f"expected the identical DeleteService call to succeed once desiredCount reached 0, "
        f"got {deleted['status']}"
    )


from botocore.exceptions import ClientError


def _error(fn):
    """Return (code, message) of the ClientError *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
