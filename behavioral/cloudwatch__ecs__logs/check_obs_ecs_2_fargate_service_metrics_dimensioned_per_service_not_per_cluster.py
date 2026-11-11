"""obs-ecs-2-fargate-service-metrics-dimensioned-per-service-not-per-cluster."""

from __future__ import annotations

import datetime
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-2-fargate-service-metrics-dimensioned-per-service-not-per-cluster"

GROUP = "service-metrics"

SERVICES = ["cloudwatch", "ecs", "logs"]

_NS = "AWS/ECS"

_SERVICE_METRICS = ("CPUUtilization", "MemoryUtilization")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-metrics.html
@tags(
    "axis:happy-path",
    "concern:metrics",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Fargate service's AWS/ECS CPU/memory metrics exist only as ClusterName+ServiceName series
    in Percent: an alarm on that pair fires while a ClusterName-only twin never receives data.
    """
    ecs = ctx.client("ecs")

    subnets, net = _own_network(ctx)
    # Container Insights pinned off so an account-default change cannot add a second namespace.
    cluster = _create_cluster(ctx, "svcm-", settings=[{"name": "containerInsights", "value": "disabled"}])
    td_arn = _register_task_def(ctx)
    service = _create_service(ctx, cluster, td_arn, subnets)
    started_at = datetime.datetime.now(datetime.timezone.utc)

    svc = _poll_until(
        lambda: ecs.describe_services(cluster=cluster, services=[service])["services"][0],
        lambda s: s.get("runningCount", 0) >= 1,
        timeout_s=600,
        interval_s=10,
        description=f"service {service} runningCount >= 1",
    )
    assert svc["runningCount"] == 1 and svc["desiredCount"] == 1, (
        f"service must run exactly its one desired task, got running={svc['runningCount']!r} "
        f"desired={svc['desiredCount']!r}"
    )

    pair = [{"Name": "ClusterName", "Value": cluster}, {"Name": "ServiceName", "Value": service}]
    cluster_only = [{"Name": "ClusterName", "Value": cluster}]

    svc_alarm = _create_alarm(ctx, "svc-", pair)
    cl_alarm = _create_alarm(ctx, "cl-", cluster_only)

    # ---- 3. the per-service series carry Percent datapoints
    for metric in _SERVICE_METRICS:
        dps = _poll_until(
            lambda m=metric: _datapoints(ctx, m, pair, started_at),
            lambda ds: bool(ds),
            timeout_s=600,
            interval_s=20,
            description=f"{_NS} {metric} datapoints for {pair}",
        )
        units = sorted({d.get("Unit") for d in dps})
        assert units == ["Percent"], f"{metric} for a service is published in Percent, got {units!r}"
        if metric == "MemoryUtilization":
            assert all(0.0 <= d["Maximum"] <= 100.0 for d in dps), (
                f"MemoryUtilization is a percentage of the task's hard memory limit, got {dps!r}"
            )
        assert all(d["Minimum"] >= 0.0 for d in dps), f"negative {metric}: {dps!r}"

    # ---- 4. the alarm on the pair fires; the ClusterName-only twin never gets data
    # Cluster-level utilization derives from EC2 container instances, of which Fargate has none.
    fired = _poll_until(
        lambda: _alarm(ctx, svc_alarm),
        lambda a: a.get("StateValue") == "ALARM",
        timeout_s=600,
        interval_s=15,
        description=f"alarm {svc_alarm} on the per-service CPUUtilization to reach ALARM",
    )
    assert fired["Dimensions"] and {d["Name"] for d in fired["Dimensions"]} == {"ClusterName", "ServiceName"}, fired
    barrier_end = time.monotonic() + 3 * 60
    polls = 0
    while True:
        cl_state = _alarm(ctx, cl_alarm)
        assert cl_state.get("StateValue") == "INSUFFICIENT_DATA", (
            f"the ClusterName-only alarm left INSUFFICIENT_DATA ({cl_state.get('StateValue')!r}, "
            f"reason {cl_state.get('StateReason')!r}) -- a cluster-level series exists for a "
            f"Fargate-only cluster"
        )
        for metric in _SERVICE_METRICS:
            leaked = _datapoints(ctx, metric, cluster_only, started_at)
            assert leaked == [], (
                f"{_NS} {metric} has ClusterName-only datapoints for a Fargate-only cluster: {leaked!r}"
            )
        polls += 1
        if time.monotonic() >= barrier_end:
            break
        time.sleep(30)
    assert polls >= 3, f"the post-ALARM barrier was observed only {polls} times"
    still = _alarm(ctx, svc_alarm)
    assert still.get("StateValue") == "ALARM", (
        f"the per-service alarm must stay in ALARM while the service runs, got {still.get('StateValue')!r}"
    )

    # ---- 5. the catalogue: exactly ClusterName+ServiceName, naming this service
    listed = _poll_until(
        lambda: _list_metrics(ctx, cluster_only),
        lambda ms: set(_SERVICE_METRICS) <= {m["MetricName"] for m in ms},
        timeout_s=900,
        interval_s=30,
        description=f"ListMetrics({_NS}, ClusterName={cluster}) to list {_SERVICE_METRICS}",
    )
    dimsets = {tuple(sorted(d["Name"] for d in m["Dimensions"])) for m in listed}
    assert dimsets == {("ClusterName", "ServiceName")}, (
        f"every {_NS} series for a Fargate service must be dimensioned exactly ClusterName+ServiceName; "
        f"got dimension sets {sorted(dimsets)!r} over {listed!r}"
    )
    services_seen = {
        d["Value"] for m in listed for d in m["Dimensions"] if d["Name"] == "ServiceName"
    }
    assert services_seen == {service}, (
        f"the ServiceName dimension must carry exactly this run's service {service!r}, got {sorted(services_seen)!r}"
    )
    clusters_seen = {
        d["Value"] for m in listed for d in m["Dimensions"] if d["Name"] == "ClusterName"
    }
    assert clusters_seen == {cluster}, clusters_seen
    print(f"[measure] AWS/ECS series for {cluster}: {sorted((m['MetricName'], tuple(sorted(d['Name'] for d in m['Dimensions']))) for m in listed)!r}")

    # ---- 6. teardown as a graded leg
    _teardown_leg(ctx, cluster=cluster, service=service, alarms=[svc_alarm, cl_alarm], td_arn=td_arn, net=net)


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

# ECR Public busybox: Fargate pulls it server-side and anonymously, so no execution role and no
# registry credentials are involved in a check about telemetry.
_PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn, *gone_codes):
    """Run a teardown step fn(); return on the resource's not-found codes, raise anything else."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in gone_codes:
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return it, raising on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _datapoints(ctx, metric_name, dimensions, since):
    return (
        ctx.client("cloudwatch")
        .get_metric_statistics(
            Namespace=_NS,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=since - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum", "Minimum", "SampleCount"],
        )
        .get("Datapoints", [])
    )


def _list_metrics(ctx, dimensions):
    out = []
    pages = ctx.client("cloudwatch").get_paginator("list_metrics").paginate(
        Namespace=_NS, Dimensions=dimensions
    )
    for page in pages:
        out.extend(page.get("Metrics", []))
    return out


def _create_alarm(ctx, kind, dimensions) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(_XSVC_PREFIX + "alarm-" + kind)
    cw.put_metric_alarm(
        AlarmName=name,
        AlarmDescription="sim2real-xsvc per-service vs per-cluster dimensioning probe",
        Namespace=_NS,
        MetricName="CPUUtilization",
        Dimensions=dimensions,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: cw.delete_alarms(AlarmNames=[name]), "ResourceNotFound"))
    return name


def _alarm(ctx, name) -> dict:
    found = ctx.client("cloudwatch").describe_alarms(AlarmNames=[name]).get("MetricAlarms", [])
    assert len(found) == 1, f"DescribeAlarms({name!r}) returned {found!r}"
    return found[0]


def _own_network(ctx) -> list[str]:
    """A throwaway VPC with an internet gateway and two public subnets in two usable AZs.

    No NAT gateway or EIP: the task gets a public IP. Teardown first waits for the Fargate ENIs to
    be released, since a subnet with an ENI cannot be deleted."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "net-")

    def spec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name}] + _tags_kv()}]

    state: dict = {"vpc": None, "igw": None, "rtb": None, "subnets": [], "deleted": False}
    vpc = ec2.create_vpc(CidrBlock="10.78.0.0/16", TagSpecifications=spec("vpc"))["Vpc"]["VpcId"]
    state["vpc"] = vpc
    ctx.on_cleanup(lambda: _teardown_network(ctx, state))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    state["igw"] = igw
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rtb = ec2.create_route_table(VpcId=vpc, TagSpecifications=spec("route-table"))["RouteTable"][
        "RouteTableId"
    ]
    state["rtb"] = rtb
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"need two available AZs in {ctx.region}, got {zones!r}"
    for i, az in enumerate(zones[:2]):
        sn = ec2.create_subnet(
            VpcId=vpc,
            CidrBlock=f"10.78.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=spec("subnet"),
        )["Subnet"]["SubnetId"]
        state["subnets"].append(sn)
        ec2.associate_route_table(RouteTableId=rtb, SubnetId=sn)
    return list(state["subnets"]), state


def _teardown_network(ctx, state) -> None:
    """Delete the network, setting ``state["deleted"]``; a leak raises once every delete has been
    attempted."""
    if state["deleted"]:
        return
    leaks: list[str] = []
    ec2 = ctx.client("ec2")
    vpc = state["vpc"]
    try:
        _poll_until(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc]}]
            ).get("NetworkInterfaces", []),
            lambda enis: not enis,
            timeout_s=420,
            interval_s=10,
            description=f"Fargate ENIs released from {vpc}",
        )
    except AssertionError as exc:
        leaks.append(f"{exc}")
    for sn in state["subnets"]:
        _unless_gone(lambda sn=sn: ec2.delete_subnet(SubnetId=sn), "InvalidSubnetID.NotFound")
    if state["rtb"]:
        _unless_gone(lambda: ec2.delete_route_table(RouteTableId=state["rtb"]), "InvalidRouteTableID.NotFound")
    if state["igw"]:
        _unless_gone(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=state["igw"], VpcId=vpc),
            "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
        )
        _unless_gone(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=state["igw"]), "InvalidInternetGatewayID.NotFound"
        )
    try:
        ec2.delete_vpc(VpcId=vpc)
        state["deleted"] = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            leaks.append(f"vpc {vpc} ({state}) not deleted: {exc}")
            raise RuntimeError("; ".join(leaks)) from exc
        state["deleted"] = True


def _create_cluster(ctx, kind, settings=None) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + kind)
    kwargs: dict = {"clusterName": name, "tags": _ecs_tags_kv()}
    if settings:
        kwargs["settings"] = settings
    ecs.create_cluster(**kwargs)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, name, raise_on_leak=True))
    return name


def _register_task_def(ctx) -> str:
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name(_XSVC_PREFIX + "td-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": _PUBLIC_IMAGE,
                "essential": True,
                "command": ["sh", "-c", "sleep 1700"],
            }
        ],
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ecs_tags_kv(),
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    return arn


def _create_service(ctx, cluster, td_arn, subnets) -> str:
    """A Fargate service with one task. Teardown scales to zero, force-deletes, and waits for the
    service's tasks to stop so the cluster and the subnets behind it can be deleted."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name(_XSVC_PREFIX + "svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=td_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {"subnets": subnets, "assignPublicIp": "ENABLED"}
        },
        tags=_ecs_tags_kv(),
    )

    ctx.on_cleanup(lambda: _drain_service(ctx, cluster, name, raise_on_leak=True))
    return name


def _drain_service(ctx, cluster, service, timeout_s=300, *, raise_on_leak: bool = False) -> bool:
    """Scale to zero, force-delete, and wait until every task of the cluster is STOPPED. Fast
    no-op when the service is already gone. True when nothing is left running."""
    ecs = ctx.client("ecs")
    found = ecs.describe_services(cluster=cluster, services=[service]).get("services", [])
    if found and found[0].get("status") != "INACTIVE":
        gone = ("ServiceNotFoundException", "ServiceNotActiveException", "ClusterNotFoundException")
        _unless_gone(lambda: ecs.update_service(cluster=cluster, service=service, desiredCount=0), *gone)
        _unless_gone(lambda: ecs.delete_service(cluster=cluster, service=service, force=True), *gone)

    def live():
        arns = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING").get("taskArns", [])
        arns += ecs.list_tasks(cluster=cluster, desiredStatus="STOPPED").get("taskArns", [])
        if not arns:
            return []
        return [
            t["taskArn"]
            for t in ecs.describe_tasks(cluster=cluster, tasks=arns[:100]).get("tasks", [])
            if t.get("lastStatus") != "STOPPED"
        ]

    try:
        _poll_until(live, lambda xs: not xs, timeout_s=timeout_s, interval_s=10,
                    description=f"tasks of service {service} STOPPED")
        return True
    except AssertionError as exc:  # the graded leg asserts the False; teardown raises
        if raise_on_leak:
            raise RuntimeError(f"{exc}") from exc
        return False


def _delete_cluster(ctx, name, attempts=18, *, raise_on_leak: bool = False) -> bool:
    """Delete a cluster, retrying while draining tasks still block it. True when it is gone."""
    ecs = ctx.client("ecs")
    for _ in range(attempts):
        found = ecs.describe_clusters(clusters=[name]).get("clusters", [])
        if not found or found[0].get("status") == "INACTIVE":
            return True
        try:
            ecs.delete_cluster(cluster=name)
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return True
            if code not in ("ClusterContainsTasksException", "ClusterContainsServicesException", "UpdateInProgressException"):
                raise
            time.sleep(10)
    if raise_on_leak:
        raise RuntimeError(f"ECS cluster {name} could not be deleted")
    return False


def _teardown_leg(ctx, *, cluster, service, alarms, td_arn, net) -> None:
    """Tear the estate down inside the check and assert it is gone: draining a Fargate service and
    releasing its ENIs takes minutes, longer than the cleanup chain's time bound."""
    assert _drain_service(ctx, cluster, service), f"service {service} did not drain"
    ctx.client("cloudwatch").delete_alarms(AlarmNames=alarms)
    assert _delete_cluster(ctx, cluster), f"cluster {cluster} could not be deleted"
    ctx.client("ecs").deregister_task_definition(taskDefinition=td_arn)
    _teardown_network(ctx, net)
    assert net["deleted"], f"the check's own VPC {net['vpc']} could not be deleted: {net!r}"


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
