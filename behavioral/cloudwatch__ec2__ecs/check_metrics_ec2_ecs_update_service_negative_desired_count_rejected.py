"""metrics-ec2-ecs-update-service-negative-desired-count-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metrics-ec2-ecs-update-service-negative-desired-count-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2", "ecs"]

_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_METRIC_BUDGET_S = 900.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html
@tags("axis:rejection", "cap:c3", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """UpdateService with desiredCount=-1 fails with the exact InvalidParameterException and leaves
    desiredCount and runningCount at 1, while desiredCount=2 on the same service takes effect and
    RunningTaskCount (Unit Count) reaches 2, never reading outside 0..2."""
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")

    subnet, sg = _public_network(ctx, ec2)
    cluster = ctx.unique_name("sim2real-xsvc-neg-")
    ecs.create_cluster(clusterName=cluster,
                       settings=[{"name": "containerInsights", "value": "enabled"}],
                       tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-xsvc-neg-td-"), networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
        containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True,
                               "command": ["sh", "-c", "sleep 3600"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td))

    services: list[str] = []
    ctx.on_cleanup(lambda: _teardown_services(ec2, ecs, cluster, services, subnet, raise_on_leak=True))
    svc = _create_service(ctx, ecs, cluster, td, subnet, sg, desired=1)
    services.append(svc)
    _poll_until(lambda: _svc(ecs, cluster, svc)["runningCount"], lambda n: n == 1,
                timeout_s=420.0, interval_s=10.0,
                description=f"service {svc} reaching runningCount=1")

    # ---- the refusal ------------------------------------------------------------------------- #
    got = _error(lambda: ecs.update_service(cluster=cluster, service=svc, desiredCount=-1))
    want = ("InvalidParameterException", "Task count can not be lesser than 0")
    assert got == want, (
        f"UpdateService desiredCount=-1 on {svc} returned error {got!r}; real AWS answers {want!r}"
    )
    after = _svc(ecs, cluster, svc)
    assert (after["desiredCount"], after["runningCount"]) == (1, 1), (
        f"the refused UpdateService left {svc} at desiredCount={after['desiredCount']!r} "
        f"runningCount={after['runningCount']!r}; a refusal must change nothing"
    )
    rejected_at = datetime.now(timezone.utc)

    # ---- positive control: the same call with a valid count takes effect ---------------------- #
    ecs.update_service(cluster=cluster, service=svc, desiredCount=2)
    _poll_until(lambda: _svc(ecs, cluster, svc)["runningCount"], lambda n: n == 2,
                timeout_s=420.0, interval_s=10.0,
                description=f"service {svc} reaching runningCount=2 after UpdateService(2)")
    dps = _poll_until(
        lambda: _series(cw, "RunningTaskCount", cluster, svc),
        lambda d: any(p["Maximum"] == 2.0 for p in d), timeout_s=_METRIC_BUDGET_S, interval_s=30.0,
        description=(f"ECS/ContainerInsights RunningTaskCount for {svc} reading 2 after the valid "
                     f"UpdateService"),
    )
    bad = [(p["Timestamp"].isoformat(), p["Maximum"]) for p in dps
           if p["Maximum"] not in (0.0, 1.0, 2.0)]
    assert not bad, (
        f"RunningTaskCount for {svc} read {bad!r}; the service only ever ran 0..2 tasks, so the "
        f"refused desiredCount=-1 (after {rejected_at.isoformat()}) leaked into the metric"
    )
    assert {p.get("Unit") for p in dps} == {"Count"}, f"RunningTaskCount units {dps!r}"

    _teardown_services(ec2, ecs, cluster, services, subnet)


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {resp!r}")


def _series(cw, metric: str, cluster: str, service: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    return cw.get_metric_statistics(
        Namespace="ECS/ContainerInsights", MetricName=metric,
        Dimensions=[{"Name": "ClusterName", "Value": cluster},
                    {"Name": "ServiceName", "Value": service}],
        StartTime=now - timedelta(minutes=30), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Maximum", "Minimum"],
    )["Datapoints"]


def _svc(ecs, cluster: str, service: str) -> dict:
    return ecs.describe_services(cluster=cluster, services=[service])["services"][0]


def _create_service(ctx, ecs, cluster, td, subnet, sg, *, desired: int) -> str:
    name = ctx.unique_name(f"sim2real-xsvc-ci-{desired}-")
    ecs.create_service(
        cluster=cluster, serviceName=name, taskDefinition=td, desiredCount=desired,
        launchType="FARGATE", tags=[{"key": "sim2real", "value": CHECK}],
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [subnet], "securityGroups": [sg], "assignPublicIp": "ENABLED"}},
    )
    return name


def _teardown_services(ec2, ecs, cluster: str, services: list[str], subnet: str, *,
                       raise_on_leak: bool = False) -> None:
    """Delete every service, wait for its tasks to stop and their ENIs to leave the subnet.

    The in-body call returns after the wait; the registered cleanup raises if anything remains.
    """
    for svc in list(services):
        try:
            ecs.delete_service(cluster=cluster, service=svc, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"ServiceNotFoundException",
                                                      "ServiceNotActiveException"}:
                raise
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        tasks = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING")["taskArns"]
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}])["NetworkInterfaces"]
        if not tasks and not enis:
            return
        time.sleep(5.0)
    if raise_on_leak:
        raise RuntimeError(f"tasks/ENIs still present in {cluster}/{subnet} after 300s")


#: Shared cleanup deadline of this suite (budget.cleanup_timeout).
_CLEANUP_S = 900.0
_CLUSTER_BUSY = {"ClusterContainsServicesException", "ClusterContainsTasksException",
                 "UpdateInProgressException"}


def _delete_cluster(ecs, cluster: str) -> None:
    """Delete the cluster, retrying every 2 s while its force-deleted services still drain."""
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code not in _CLUSTER_BUSY or time.monotonic() > deadline:
                raise
        time.sleep(2.0)


def _tags(value: str, name: str) -> list[dict]:
    return [{"Key": "sim2real", "Value": value}, {"Key": "Name", "Value": name}]


def _public_network(ctx, ec2) -> tuple[str, str]:
    """A VPC of our own with an IGW, so Fargate can pull the public image. No default VPC."""
    name = ctx.unique_name("sim2real-xsvc-neg-net-")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, f"no available availability zone in {ctx.region}"
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(CHECK, name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags(CHECK, name)}])[
        "InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_dependency(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    main_rt = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=zones[0],
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags(CHECK, name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    sg = ec2.create_security_group(GroupName=name, Description="sim2real container insights, no ingress",
                                   VpcId=vpc, TagSpecifications=[
                                       {"ResourceType": "security-group",
                                        "Tags": _tags(CHECK, name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg)))
    return subnet, sg


def _retry_dependency(fn, budget_s: float = 25.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


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
