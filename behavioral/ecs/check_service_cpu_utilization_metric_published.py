"""service-cpu-utilization-metric-published."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "service-cpu-utilization-metric-published"
GROUP = "telemetry"
SERVICES = ["ecs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-metrics.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A running ECS service emits AWS/ECS CPUUtilization datapoints to CloudWatch,
    dimensioned by ClusterName/ServiceName, as an observable side effect of RunTask
    placement -- not merely something the control plane claims happened."""
    ecs = ctx.client("ecs")
    cloudwatch = ctx.client("cloudwatch")
    cluster = _create_cluster(ctx)
    net = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")
    cluster_short_name = cluster["clusterName"]

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

    def _service():
        return ecs.describe_services(cluster=cluster["clusterArn"], services=[service_name])["services"][0]

    _poll_until(_service, lambda svc: svc["runningCount"] == 1, timeout_s=_budget_s(ctx, 300.0),
                interval_s=1.0, ctx=ctx)

    # Datapoints land on the publisher's per-minute period; poll every 2 s until one appears.
    deadline = time.monotonic() + _budget_s(ctx, 360.0)
    datapoints = []
    while time.monotonic() < deadline:
        now = datetime.now(timezone.utc)
        resp = cloudwatch.get_metric_statistics(
            Namespace="AWS/ECS",
            MetricName="CPUUtilization",
            Dimensions=[
                {"Name": "ClusterName", "Value": cluster_short_name},
                {"Name": "ServiceName", "Value": service_name},
            ],
            StartTime=now - timedelta(minutes=20),
            EndTime=now + timedelta(minutes=1),
            Period=60,
            Statistics=["Average"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            break
        time.sleep(2.0)

    if not datapoints:
        if _budget_spent(ctx):
            raise TimeoutError(
                "an AWS/ECS CPUUtilization datapoint: the run budget ended first; not graded")
        raise AssertionError(
            "AWS/ECS CPUUtilization metric did not land in CloudWatch within the poll budget "
            "(real ingestion latency can exceed this); not a hard failure"
        )

    averages = [dp["Average"] for dp in datapoints if dp.get("Average") is not None]
    assert averages, f"datapoints present but none carry an Average value: {datapoints!r}"
    assert all(0.0 <= v <= 100.0 for v in averages), (
        f"AWS/ECS CPUUtilization average must be a percentage in [0, 100], got {averages!r}"
    )
    units = {dp["Unit"] for dp in datapoints if dp.get("Unit")}
    assert units <= {"Percent"}, f"expected AWS/ECS CPUUtilization unit to be Percent, got {units!r}"


from botocore.exceptions import ClientError


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            "the service's runningCount reaching 1: the run budget ended first; not graded")
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

    def _cleanup(arn=cluster["clusterArn"], timeout_s=600.0):
        # The force-deleted service's tasks keep running until they stop, and the draining
        # service until its tasks are gone; DeleteCluster refuses while either remains.
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                ecs.delete_cluster(cluster=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if (code not in ("ClusterContainsTasksException", "ClusterContainsServicesException")
                        or time.monotonic() >= deadline):
                    raise
            time.sleep(2.0)

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
