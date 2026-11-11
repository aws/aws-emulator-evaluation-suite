"""metrics-ec2-ecs-container-insights-running-task-count-follows-each-service-desired-count."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metrics-ec2-ecs-container-insights-running-task-count-follows-each-service-desired-count"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2", "ecs"]

_VPC_CIDR = "10.95.0.0/16"
_SUBNET_CIDR = "10.95.1.0/24"
_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_METRIC_BUDGET_S = 900.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html
@tags("axis:happy-path", "cap:c3", "concern:metrics", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With Container Insights on, two Fargate services in one cluster scaled to two and one tasks
    report RunningTaskCount and DesiredTaskCount 2 and 1 for a common minute, per service:
    RunningTaskCount (Unit Count) never exceeds what each service ran."""
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")

    subnet, sg = _public_network(ctx, ec2)
    cluster = ctx.unique_name("sim2real-xsvc-ci-")
    ecs.create_cluster(clusterName=cluster,
                       settings=[{"name": "containerInsights", "value": "enabled"}],
                       tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    settings = {s["name"]: s["value"] for s in
                ecs.describe_clusters(clusters=[cluster], include=["SETTINGS"])["clusters"][0]["settings"]}
    assert settings.get("containerInsights") == "enabled", f"cluster settings are {settings!r}"

    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-xsvc-ci-td-"), networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
        containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True,
                               "command": ["sh", "-c", "sleep 3600"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td))

    services: list[str] = []
    ctx.on_cleanup(lambda: _teardown_services(ec2, ecs, cluster, services, subnet, raise_on_leak=True))
    two = _create_service(ctx, ecs, cluster, td, subnet, sg, desired=2)
    services.append(two)
    one = _create_service(ctx, ecs, cluster, td, subnet, sg, desired=1)
    services.append(one)

    for svc, want in ((two, 2), (one, 1)):
        _poll_until(lambda s=svc: _svc(ecs, cluster, s)["runningCount"], lambda n: n == want,
                    timeout_s=420.0, interval_s=10.0,
                    description=f"service {svc} reaching runningCount={want}")
    running_since = datetime.now(timezone.utc)

    def _values(metric: str) -> dict:
        """{timestamp: (two's Maximum, one's Maximum)} for minutes both services published."""
        a = {d["Timestamp"]: d for d in _series(cw, metric, cluster, two)}
        b = {d["Timestamp"]: d for d in _series(cw, metric, cluster, one)}
        return {t: (a[t]["Maximum"], b[t]["Maximum"]) for t in set(a) & set(b)}

    running = _poll_until(
        lambda: {t: v for t, v in _values("RunningTaskCount").items() if v == (2.0, 1.0)},
        lambda m: len(m) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=30.0,
        description=(f"a minute in which ECS/ContainerInsights RunningTaskCount reads 2 for "
                     f"{two} and 1 for {one} (both were running their desired count from "
                     f"{running_since.isoformat()})"),
    )
    desired = _poll_until(
        lambda: {t: v for t, v in _values("DesiredTaskCount").items() if v == (2.0, 1.0)},
        lambda m: len(m) >= 1, timeout_s=300.0, interval_s=30.0,
        description=f"a minute in which DesiredTaskCount reads 2 for {two} and 1 for {one}",
    )
    assert running and desired, "unreachable: both polls raise on timeout"

    # The counts are per service, never larger than what the service ever ran.
    for svc, cap in ((two, 2.0), (one, 1.0)):
        dps = _series(cw, "RunningTaskCount", cluster, svc)
        peak = max(d["Maximum"] for d in dps)
        assert peak <= cap, (
            f"RunningTaskCount for {svc} peaked at {peak!r} although the service never ran more "
            f"than {cap!r} tasks; the value is not per service"
        )
        units = {d.get("Unit") for d in dps}
        assert units == {"Count"}, f"RunningTaskCount for {svc} carries Unit(s) {units!r}"

    # In-body teardown so the bounded cleanup chain only has network deletes left to do.
    _teardown_services(ec2, ecs, cluster, services, subnet)


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
    name = ctx.unique_name("sim2real-xsvc-ci-net-")
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
