"""weighted-capacity-group-metrics-diverge-from-instance-counts."""
from __future__ import annotations

import datetime as dt
import threading
import time

from behavioral_harness import tags

CHECK = "weighted-capacity-group-metrics-diverge-from-instance-counts"
GROUP = "metrics"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

NAMESPACE = "AWS/AutoScaling"
WEIGHT = 2
MIN_SIZE, MAX_SIZE, DESIRED_UNITS = 0, 4, 4
INSTANCES = DESIRED_UNITS // WEIGHT

#: Capacity metrics count WEIGHTED units, instance metrics count instances. With every instance
#: weighing 2, the two families must disagree by exactly that factor.
EXPECTED = {
    "GroupDesiredCapacity": float(DESIRED_UNITS),
    "GroupInServiceInstances": float(INSTANCES),
    "GroupInServiceCapacity": float(INSTANCES * WEIGHT),
    "GroupTotalInstances": float(INSTANCES),
    "GroupTotalCapacity": float(INSTANCES * WEIGHT),
    "GroupPendingCapacity": 0.0,
}

VALUE_BOUND_S = 600


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html
@tags(
    "axis:happy-path",
    "concern:metrics",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """With a weighted instance type, Auto Scaling's CAPACITY metrics report weighted units while
    its INSTANCE metrics report instances: at one CloudWatch timestamp, capacity = WEIGHT x instances,
    and ListMetrics indexes exactly the enabled subset.
    """
    asg = ctx.client("autoscaling")
    started = time.monotonic()

    ami = _al2023_ami(ctx)
    _vpc, subnets = _network(ctx, "t3.micro")
    lt_name = _launch_template(ctx, ami)
    group = _create_asg(ctx, lt_name, subnets)
    ctx.on_cleanup(lambda: _drop_group(ctx, group, wait_s=20))

    ids = _poll(
        lambda: _ids_in_state(ctx, group, "InService"),
        lambda ids: len(ids) == INSTANCES,
        timeout_s=900,
        description=f"setup: {group} reached {INSTANCES} InService instances",
    )
    print(f"[measured] {INSTANCES} InService after {time.monotonic() - started:.0f}s")
    described = _group(ctx, group)
    weights = sorted(i.get("WeightedCapacity") for i in described["Instances"])
    assert weights == [str(WEIGHT)] * INSTANCES, (
        f"every instance must carry WeightedCapacity {str(WEIGHT)!r}: got {weights!r}"
    )
    assert described["DesiredCapacity"] == DESIRED_UNITS, (
        f"DesiredCapacity is in weighted units and must stay {DESIRED_UNITS}: "
        f"got {described['DesiredCapacity']!r}"
    )

    asg.enable_metrics_collection(
        AutoScalingGroupName=group, Metrics=sorted(EXPECTED), Granularity="1Minute"
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.disable_metrics_collection(AutoScalingGroupName=group)))
    enabled = {m["Metric"] for m in _group(ctx, group)["EnabledMetrics"]}
    assert enabled == set(EXPECTED), (
        f"EnabledMetrics must be exactly the named subset {sorted(EXPECTED)!r}: got {sorted(enabled)!r}"
    )
    since = _now().replace(second=0, microsecond=0)

    t0 = time.monotonic()
    observed = _poll(
        lambda: _series_after(ctx, group, list(EXPECTED), since),
        lambda series: _common_correct_bucket(series) is not None,
        timeout_s=VALUE_BOUND_S,
        description=(
            f"CloudWatch serving {NAMESPACE} metrics for {group} with the weighted values "
            f"{EXPECTED!r} at one common timestamp (latest per metric shown)"
        ),
        render=_latest_per_metric,
    )
    bucket = _common_correct_bucket(observed)
    print(f"[measured] weighted metrics correct at bucket {bucket.isoformat()} "
          f"{time.monotonic() - t0:.0f}s after enable")
    in_service = observed["GroupInServiceInstances"][bucket]["Maximum"]
    capacity = observed["GroupInServiceCapacity"][bucket]["Maximum"]
    assert capacity == WEIGHT * in_service and capacity != in_service, (
        f"GroupInServiceCapacity must be {WEIGHT} x GroupInServiceInstances at the same "
        f"timestamp: capacity={capacity!r}, instances={in_service!r}"
    )
    for metric, points in observed.items():
        assert points[bucket]["Unit"] == "None", (
            f"{metric} is a dimensionless count; CloudWatch reports Unit {points[bucket]['Unit']!r}"
        )

    indexed = _poll(
        lambda: _indexed(ctx, group),
        lambda idx: set(EXPECTED) <= set(idx),
        timeout_s=300,
        description=f"ListMetrics indexing all of {sorted(EXPECTED)!r} for {group}",
        render=lambda idx: sorted(idx),
    )
    stray = sorted(set(indexed) - set(EXPECTED))
    assert not stray, (
        f"only {sorted(EXPECTED)!r} were enabled, yet ListMetrics indexes {stray!r} for {group}"
    )

    # Full teardown inline: the registered cleanup chain is capped at 60s, and
    # draining the instances before the subnet and VPC can go takes longer than that. The
    # registered cleanups remain the net for a failure path and are idempotent.
    _teardown(ctx, group, lt_name, subnets, _vpc)


class _Backoff:
    """Capped exponential backoff between polls (CloudWatch has no push for datapoints)."""

    def __init__(self, initial_s: float = 5.0, cap_s: float = 30.0, factor: float = 1.5):
        self._next = initial_s
        self._cap = cap_s
        self._factor = factor
        self._event = threading.Event()

    def wait(self, remaining_s: float | None = None) -> None:
        delay = self._next if remaining_s is None else max(0.0, min(self._next, remaining_s))
        self._event.wait(delay)
        self._next = min(self._cap, self._next * self._factor)


def _poll(fn, pred, *, timeout_s, description="condition", render=repr):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    waiter = _Backoff()
    last = fn()
    while not pred(last):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={render(last)!r}")
        waiter.wait(remaining)
        last = fn()
    return last


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _series_after(ctx, group: str, metrics: list[str], since: dt.datetime) -> dict:
    """{metric: {timestamp: datapoint}} from GetMetricStatistics, Maximum over 60s periods."""
    cw = ctx.client("cloudwatch")
    out = {}
    for metric in metrics:
        resp = cw.get_metric_statistics(
            Namespace=NAMESPACE,
            MetricName=metric,
            Dimensions=[{"Name": "AutoScalingGroupName", "Value": group}],
            StartTime=since,
            EndTime=_now() + dt.timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum"],
        )
        out[metric] = {
            p["Timestamp"]: {"Maximum": p["Maximum"], "Unit": p["Unit"], "Label": resp["Label"]}
            for p in resp["Datapoints"]
        }
    return out


def _common_correct_bucket(series: dict):
    """The latest timestamp at which EVERY expected metric has a datapoint with its value."""
    common = None
    for metric in EXPECTED:
        stamps = {ts for ts, p in series.get(metric, {}).items()
                  if p["Maximum"] == EXPECTED[metric]}
        common = stamps if common is None else common & stamps
    return max(common) if common else None


def _latest_per_metric(series: dict) -> dict:
    out = {}
    for metric, points in series.items():
        if points:
            ts = max(points)
            out[metric] = (ts.strftime("%H:%M"), points[ts]["Maximum"])
        else:
            out[metric] = None
    return out


def _fmt(points: dict) -> list:
    return [(ts.strftime("%H:%M"), p["Maximum"]) for ts, p in sorted(points.items())]


def _indexed(ctx, group: str) -> dict:
    """{metric name: [dimension sets]} that ListMetrics carries for this group."""
    names: dict = {}
    paginator = ctx.client("cloudwatch").get_paginator("list_metrics")
    for page in paginator.paginate(
        Namespace=NAMESPACE, Dimensions=[{"Name": "AutoScalingGroupName", "Value": group}]
    ):
        for metric in page["Metrics"]:
            names.setdefault(metric["MetricName"], []).append(metric["Dimensions"])
    return names


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _unless_gone(fn):
    """Run one teardown call: only a not-found answer means already gone; a busy group is
    retried every 2 s for 60 s; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code", "")
            if "NotFound" in code or code == "NoSuchEntity" or (
                code == "ValidationError" and "not found" in err.get("Message", "").lower()
            ):
                return None
            if code not in ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)


def _retry_delete(fn, what: str, *, timeout_s: float = 300.0) -> None:
    """Delete something that stays referenced while EC2 tears ENIs down; raises when the budget
    runs out."""
    deadline = time.monotonic() + timeout_s
    waiter = _Backoff(initial_s=5.0, cap_s=20.0)
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - still in use by a draining dependency
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"{what} could not be deleted: {exc}") from exc
            waiter.wait(remaining)


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, instance_type: str):
    """A DEDICATED VPC with one subnet, in an AZ that really offers instance_type."""
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers {instance_type!r} in {ctx.region}: {sorted(offered)!r}"

    vpc_id = ec2.create_vpc(
        CidrBlock="10.231.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_vpc_if_present(ec2, vpc_id), f"vpc {vpc_id}", timeout_s=10))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.231.0.0/24",
        AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_subnet_if_present(ec2, subnet_id), f"subnet {subnet_id}", timeout_s=10))
    return vpc_id, [subnet_id]


def _launch_template(ctx, ami: str, *, instance_type: str = "t3.micro") -> str:
    """Tag both the instance and its volume at launch, so ASG-created resources stay
    attributable if teardown loses one."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-as-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_lt_if_present(ec2, name), f"launch template {name}", timeout_s=10))
    return name


def _create_asg(ctx, lt_name: str, subnets) -> str:
    """A group whose ONLY instance type carries WeightedCapacity 2, on-demand only."""
    name = ctx.unique_name("sim2real-behav-as-grp-")
    ctx.client("autoscaling").create_auto_scaling_group(
        AutoScalingGroupName=name,
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {
                    "LaunchTemplateName": lt_name, "Version": "$Latest",
                },
                "Overrides": [{"InstanceType": "t3.micro", "WeightedCapacity": str(WEIGHT)}],
            },
            "InstancesDistribution": {
                "OnDemandBaseCapacity": 0,
                "OnDemandPercentageAboveBaseCapacity": 100,
            },
        },
        MinSize=MIN_SIZE,
        MaxSize=MAX_SIZE,
        DesiredCapacity=DESIRED_UNITS,
        VPCZoneIdentifier=",".join(subnets),
        HealthCheckGracePeriod=0,
        DefaultCooldown=0,
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()],
    )
    return name


def _teardown(ctx, group: str, lt_name: str, subnets: list[str], vpc_id: str) -> None:
    """The whole estate, in dependency order, each wait bounded."""
    ec2 = ctx.client("ec2")
    _drop_group(ctx, group, wait_s=900)
    _retry_delete(lambda: _delete_lt_if_present(ec2, lt_name), f"launch template {lt_name}",
                  timeout_s=60)
    for subnet_id in subnets:
        _retry_delete(lambda sn=subnet_id: _delete_subnet_if_present(ec2, sn),
                      f"subnet {subnet_id}", timeout_s=300)
    _retry_delete(lambda: _delete_vpc_if_present(ec2, vpc_id), f"vpc {vpc_id}", timeout_s=300)


def _absent(exc: Exception, *codes: str) -> bool:
    return getattr(exc, "response", {}).get("Error", {}).get("Code") in codes


def _delete_lt_if_present(ec2, name: str) -> None:
    try:
        ec2.delete_launch_template(LaunchTemplateName=name)
    except Exception as exc:  # noqa: BLE001
        if not _absent(exc, "InvalidLaunchTemplateName.NotFoundException"):
            raise


def _delete_subnet_if_present(ec2, subnet_id: str) -> None:
    try:
        ec2.delete_subnet(SubnetId=subnet_id)
    except Exception as exc:  # noqa: BLE001
        if not _absent(exc, "InvalidSubnetID.NotFound"):
            raise


def _delete_vpc_if_present(ec2, vpc_id: str) -> None:
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except Exception as exc:  # noqa: BLE001
        if not _absent(exc, "InvalidVpcID.NotFound"):
            raise


def _drop_group(ctx, name: str, *, wait_s: float) -> None:
    """Drain and ForceDelete the group (Standby instances included), then wait for it to go;
    raises if it is still present at ``wait_s``."""
    asg = ctx.client("autoscaling")
    _unless_gone(lambda: asg.update_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
    _unless_gone(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))
    deadline = time.monotonic() + wait_s
    waiter = _Backoff(initial_s=10.0, cap_s=20.0)
    while _describe_groups(ctx, name):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")
        waiter.wait(remaining)


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return multiple pages."""
    groups = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_groups"
    ).paginate(AutoScalingGroupNames=[name]):
        groups += page["AutoScalingGroups"]
    return groups


def _group(ctx, name: str) -> dict:
    groups = _describe_groups(ctx, name)
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]


def _ids_in_state(ctx, name: str, *states: str) -> list[str]:
    return sorted(
        i["InstanceId"] for i in _group(ctx, name)["Instances"] if i["LifecycleState"] in states
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
