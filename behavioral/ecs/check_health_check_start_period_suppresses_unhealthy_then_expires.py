"""health-check-start-period-suppresses-unhealthy-then-expires."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-start-period-suppresses-unhealthy-then-expires"
GROUP = "task-lifecycle"
SERVICES = ["ecs"]

_START_PERIOD_S = 120
_INTERVAL_S = 5
_RETRIES = 2
# Elapsed time is measured from the first poll that saw RUNNING; the API reports no per-container
# start time, so the window boundary gets this allowance.
_SLOP_S = 10
# The control has no grace period, so retries*interval plus scheduling slack is all it should need.
_CONTROL_DEADLINE_S = 90
_OBSERVE_DEADLINE_S = 420.0
_RUNNING_TIMEOUT_S = 600.0
_POLL_S = 5.0


# timing:real-time — cooldown: 120 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HealthCheck.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With an always-failing health check, a task with startPeriod is not UNHEALTHY inside the window
    but becomes UNHEALTHY after it, later than an identical task without startPeriod, which turns
    UNHEALTHY quickly and proves the probe runs.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_HealthCheck.html
    """
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)
    subnet_id, sg_id = _public_network(ctx)

    subject_td = _register(ctx, ecs, start_period=_START_PERIOD_S)
    control_td = _register(ctx, ecs, start_period=None)

    net = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    subject_arn = _run(ctx, ecs, cluster, subject_td, net)
    control_arn = _run(ctx, ecs, cluster, control_td, net)
    both = [subject_arn, control_arn]

    # The clock starts when BOTH tasks are RUNNING, so one slow launch cannot make the other look as
    # though it spent its grace window already.
    _poll_until(
        lambda: _statuses(ecs, cluster, both),
        lambda st: all(t["lastStatus"] == "RUNNING" for t in st.values()),
        timeout_s=_RUNNING_TIMEOUT_S,
        interval_s=10,
        description="both probe tasks reach RUNNING so the grace window can be timed from a "
        "common origin",
    )
    origin = time.monotonic()

    # Record (elapsed, healthStatus) for both tasks until each has been seen UNHEALTHY.
    trace: dict[str, list[tuple[float, str]]] = {subject_arn: [], control_arn: []}

    def _tick():
        state = _statuses(ecs, cluster, both)
        elapsed = time.monotonic() - origin
        for arn in both:
            trace[arn].append((elapsed, state[arn].get("healthStatus")))
        return state

    _poll_until(
        _tick,
        lambda st: all(t.get("healthStatus") == "UNHEALTHY" for t in st.values()),
        timeout_s=_OBSERVE_DEADLINE_S,
        interval_s=_POLL_S,
        description="both tasks eventually report healthStatus UNHEALTHY, proving the failing probe "
        "is executed and that the subject's grace window expires rather than suppressing forever",
    )

    control_at = _first_unhealthy(trace[control_arn])
    subject_at = _first_unhealthy(trace[subject_arn])

    # Barrier: the probe demonstrably works and lands quickly without a grace period.
    assert control_at < _CONTROL_DEADLINE_S, (
        f"the control task has NO startPeriod, so its always-failing probe must mark it UNHEALTHY "
        f"within {_CONTROL_DEADLINE_S}s; it took {control_at:.0f}s "
        f"(trace={_fmt(trace[control_arn])}). A control this slow means health evaluation is simply "
        f"lagging, so the subject's suppression below is not evidence of a grace window"
    )

    # Suppression: no UNHEALTHY inside the window. Asserted as != UNHEALTHY rather than == UNKNOWN:
    # the documented property is only that failed probes do not count toward `retries` yet.
    window = _START_PERIOD_S - _SLOP_S
    early = [(e, h) for e, h in trace[subject_arn] if e < window and h == "UNHEALTHY"]
    assert not early, (
        f"startPeriod={_START_PERIOD_S}s means failing probes must not count toward `retries` yet, so "
        f"the subject must not be UNHEALTHY before {window}s; it was at "
        f"{[f'{e:.0f}s' for e, _ in early]} (trace={_fmt(trace[subject_arn])})"
    )

    # Expiry: the window ends, and it ends later than the control's did.
    assert subject_at >= window, (
        f"the subject became UNHEALTHY at {subject_at:.0f}s, inside its own "
        f"{_START_PERIOD_S}s grace window (allowing {_SLOP_S}s of measurement slop), which is what a "
        f"target that accepts startPeriod and ignores it looks like "
        f"(trace={_fmt(trace[subject_arn])})"
    )
    assert subject_at > control_at, (
        f"the grace period must delay the UNHEALTHY verdict relative to an otherwise identical task "
        f"without one: subject {subject_at:.0f}s vs control {control_at:.0f}s"
    )

    # An independent read of the container record, not the task summary.
    final = ecs.describe_tasks(cluster=cluster, tasks=[subject_arn])["tasks"][0]
    container = next(c for c in final["containers"] if c["name"] == "app")
    assert container.get("healthStatus") == "UNHEALTHY", (
        f"the subject's container must itself report UNHEALTHY once the grace window has expired, got "
        f"{container.get('healthStatus')!r}"
    )
    assert final["lastStatus"] == "RUNNING", (
        f"a standalone task with an unhealthy container is reported, not killed, so the subject must "
        f"still be RUNNING; got {final['lastStatus']!r} "
        f"(stoppedReason={final.get('stoppedReason')!r})"
    )



_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _ecs_tags() -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in _MANAGED_TAGS.items()]


def _ec2_tags() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn) -> None:
    """Run fn(), swallowing any exception. Teardown ONLY — never on an assertion path."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded retry that RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed {last!r}"
    )


def _statuses(ecs, cluster, arns) -> dict:
    """One DescribeTasks call covering both tasks, keyed by taskArn."""
    resp = ecs.describe_tasks(cluster=cluster, tasks=list(arns))
    assert not resp.get("failures"), (
        f"DescribeTasks could not read {arns!r}: {resp.get('failures')!r}"
    )
    out = {t["taskArn"]: t for t in resp["tasks"]}
    assert set(out) == set(arns), f"expected {sorted(arns)!r} back, got {sorted(out)!r}"
    for arn, task in out.items():
        assert task["lastStatus"] != "STOPPED", (
            f"task {arn} stopped while its health status was under observation, so the timing "
            f"measurement is void: stopCode={task.get('stopCode')!r} "
            f"stoppedReason={task.get('stoppedReason')!r}"
        )
    return out


def _first_unhealthy(samples) -> float:
    for elapsed, health in samples:
        if health == "UNHEALTHY":
            return elapsed
    raise AssertionError(f"never observed UNHEALTHY in {_fmt(samples)}")


def _fmt(samples) -> str:
    return ", ".join(f"{e:.0f}s={h}" for e, h in samples)


def _register(ctx, ecs, start_period) -> str:
    """A Fargate task definition whose single container's health check can never pass."""
    probe = {
        "command": ["CMD-SHELL", "exit 1"],
        "interval": _INTERVAL_S,
        "timeout": 2,
        "retries": _RETRIES,
    }
    if start_period is not None:
        probe["startPeriod"] = start_period
    label = "grace" if start_period is not None else "nograce"
    arn = ecs.register_task_definition(
        family=ctx.unique_name(f"sim2real-behav-ecs-sp-{label}-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 900"],
                "healthCheck": probe,
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=_ecs_tags(),
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_task_definitions(taskDefinitions=[arn])))
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.deregister_task_definition(taskDefinition=arn)))

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    got = described["containerDefinitions"][0]["healthCheck"].get("startPeriod")
    assert got == start_period, (
        f"the {label} task definition must round-trip startPeriod={start_period!r}, got {got!r}"
    )
    return arn


def _create_cluster(ctx, ecs) -> str:
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ecs_tags())
    ctx.on_cleanup(lambda: _swallow(lambda: ecs.delete_cluster(cluster=name)))
    return name


def _run(ctx, ecs, cluster, td_arn, net) -> str:
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net,
        tags=_ecs_tags(),
    )
    assert not resp.get("failures"), f"RunTask reported failures: {resp.get('failures')!r}"
    arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: _swallow(
            lambda: ecs.stop_task(cluster=cluster, task=arn, reason="behavioral-cleanup")
        )
    )
    return arn


def _public_network(ctx):
    """A dedicated VPC with one public subnet, an IGW and a default route.

    An account may have no default VPC; the public route lets the container pull busybox from ECR.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.192.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags()}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags()}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _ec2_tags()}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "SecurityGroups"
        ]
        if sg["GroupName"] == "default"
    )

    def _teardown_network():
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if not ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
            ).get("NetworkInterfaces", []):
                break
            time.sleep(10)
        while time.monotonic() < deadline:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
                break
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnetID.NotFound":
                    break
                time.sleep(10)
        _swallow(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _swallow(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
        while time.monotonic() < deadline:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidVpcID.NotFound":
                    return
                time.sleep(10)
        raise RuntimeError(
            f"vpc {vpc_id} / subnet {subnet_id} not deleted within the teardown deadline"
        )

    ctx.on_cleanup(_teardown_network)
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
