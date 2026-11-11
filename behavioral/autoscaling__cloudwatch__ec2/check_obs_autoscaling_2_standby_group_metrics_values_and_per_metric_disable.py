"""obs-autoscaling-2-standby-group-metrics-values-and-per-metric-disable."""
from __future__ import annotations

import datetime as dt
import threading
import time

from behavioral_harness import tags

CHECK = "obs-autoscaling-2-standby-group-metrics-values-and-per-metric-disable"
GROUP = "metrics"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

NAMESPACE = "AWS/AutoScaling"
MIN_SIZE, MAX_SIZE, DESIRED = 1, 4, 3

#: What every group metric must read once one of three InService instances has entered Standby
#: with ShouldDecrementDesiredCapacity=True. All derived from the sizes this check set.
EXPECTED = {
    "GroupMinSize": float(MIN_SIZE),
    "GroupMaxSize": float(MAX_SIZE),
    "GroupDesiredCapacity": float(DESIRED - 1),
    "GroupInServiceInstances": float(DESIRED - 1),
    "GroupStandbyInstances": 1.0,
    "GroupTotalInstances": float(DESIRED),
    "GroupPendingInstances": 0.0,
    "GroupTerminatingInstances": 0.0,
    "GroupInServiceCapacity": float(DESIRED - 1),
}
DISABLED_METRIC = "GroupStandbyInstances"
TWIN_METRIC = "GroupDesiredCapacity"

VALUE_BOUND_S = 600
INDEX_BOUND_S = 300
HOLD_WINDOW_S = 180


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html
@tags(
    "axis:negative-delivery",
    "concern:metrics",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """Auto Scaling publishes every group metric with the value its state implies after EnterStandby
    with decrement, ListMetrics indexes exactly the enabled names, and disabling one metric stops
    only that series while its enabled twin keeps receiving datapoints.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html
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
        lambda ids: len(ids) == DESIRED,
        timeout_s=900,
        description=f"setup: {group} reached {DESIRED} InService instances",
    )
    print(f"[measured] {DESIRED} InService after {time.monotonic() - started:.0f}s")

    # Enable ALL group metrics: Granularity and no Metrics argument.
    asg.enable_metrics_collection(AutoScalingGroupName=group, Granularity="1Minute")
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.disable_metrics_collection(AutoScalingGroupName=group)))
    enabled = {m["Metric"]: m["Granularity"] for m in _group(ctx, group)["EnabledMetrics"]}
    print(f"[measured] EnabledMetrics after enable-all: {sorted(enabled)!r}")
    missing = sorted(set(EXPECTED) - set(enabled))
    assert not missing, (
        f"EnableMetricsCollection with no Metrics must enable every group metric; "
        f"EnabledMetrics lacks {missing!r} (got {sorted(enabled)!r})"
    )
    assert set(enabled.values()) == {"1Minute"}, (
        f"every enabled metric must carry Granularity '1Minute', got {enabled!r}"
    )

    # Exactly one instance into Standby, decrementing desired capacity.
    standby_id = ids[0]
    resp = asg.enter_standby(
        AutoScalingGroupName=group, InstanceIds=[standby_id], ShouldDecrementDesiredCapacity=True
    )
    activities = resp["Activities"]
    assert len(activities) == 1, f"EnterStandby for one instance returned {activities!r}"
    _poll(
        lambda: _state_of(ctx, group, standby_id),
        lambda state: state == "Standby",
        timeout_s=300,
        description=f"setup: {standby_id} reached Standby",
    )
    described = _group(ctx, group)
    assert described["DesiredCapacity"] == DESIRED - 1, (
        f"ShouldDecrementDesiredCapacity=True must take DesiredCapacity from {DESIRED} to "
        f"{DESIRED - 1}; DescribeAutoScalingGroups reports {described['DesiredCapacity']!r}"
    )
    standby_at = _now()
    since = standby_at.replace(second=0, microsecond=0)

    # Every metric correct at ONE common CloudWatch timestamp after the standby transition.
    t0 = time.monotonic()
    observed = _poll(
        lambda: _series_after(ctx, group, list(EXPECTED), since),
        lambda series: _common_correct_bucket(series) is not None,
        timeout_s=VALUE_BOUND_S,
        description=(
            f"CloudWatch serving every {NAMESPACE} group metric for {group} with the post-standby "
            f"values {EXPECTED!r} at one common timestamp (latest per metric shown)"
        ),
        render=_latest_per_metric,
    )
    bucket = _common_correct_bucket(observed)
    print(f"[measured] all nine metrics correct at bucket {bucket.isoformat()} "
          f"{time.monotonic() - t0:.0f}s after standby")
    for metric, points in observed.items():
        point = points[bucket]
        assert point["Label"] == metric, (
            f"GetMetricStatistics for {metric} labelled its series {point['Label']!r}: each "
            f"metric must be its own distinct series"
        )
        assert point["Unit"] == "None", (
            f"{metric} is a dimensionless count; CloudWatch reports Unit {point['Unit']!r}"
        )
    in_service = observed["GroupInServiceInstances"][bucket]["Maximum"]
    in_service_capacity = observed["GroupInServiceCapacity"][bucket]["Maximum"]
    assert in_service_capacity == in_service, (
        f"no weighted capacity is configured, so GroupInServiceCapacity must equal "
        f"GroupInServiceInstances at the same timestamp: {in_service_capacity!r} != {in_service!r}"
    )
    assert observed["GroupTotalInstances"][bucket]["Maximum"] == (
        in_service + observed["GroupStandbyInstances"][bucket]["Maximum"]
    ), f"GroupTotalInstances must count InService plus Standby: {_latest_per_metric(observed)!r}"

    # ListMetrics: all nine indexed under exactly the one dimension, and no WarmPool* name.
    indexed = _poll(
        lambda: _indexed(ctx, group),
        lambda idx: set(EXPECTED) <= set(idx),
        timeout_s=INDEX_BOUND_S,
        description=f"ListMetrics indexing all of {sorted(EXPECTED)!r} for {group}",
        render=lambda idx: sorted(idx),
    )
    print(f"[measured] ListMetrics names for the group: {sorted(indexed)!r}")
    for name, dims in indexed.items():
        assert dims == [[{"Name": "AutoScalingGroupName", "Value": group}]], (
            f"{NAMESPACE}/{name} must be published under exactly the dimension set "
            f"[AutoScalingGroupName={group}], ListMetrics shows {dims!r}"
        )
    # Negative control: nothing is published that EnabledMetrics did not name.
    stray_names = sorted(set(indexed) - set(enabled))
    assert not stray_names, (
        f"ListMetrics indexes {stray_names!r} for {group}, none of which EnabledMetrics "
        f"({sorted(enabled)!r}) names"
    )
    # Enable-all DOES publish the WarmPool* series for a group with no
    # warm pool -- so their absence is not the contract. Their VALUE is: there is no pool, so
    # every warm-pool capacity reads zero at the same instant the group metrics are correct.
    warm_names = sorted(n for n in enabled if n.startswith("WarmPool"))
    assert warm_names, f"enable-all must include the WarmPool* metrics: got {sorted(enabled)!r}"
    warm = _poll(
        lambda: _series_after(ctx, group, warm_names, since),
        lambda series: all(bucket in points for points in series.values()),
        timeout_s=INDEX_BOUND_S,
        description=f"every WarmPool* series for {group} carrying the bucket {bucket.isoformat()}",
        render=_latest_per_metric,
    )
    nonzero = {m: points[bucket]["Maximum"] for m, points in warm.items()
               if points[bucket]["Maximum"] != 0.0}
    assert not nonzero, (
        f"{group} has no warm pool, so every warm-pool capacity must read 0 at "
        f"{bucket.isoformat()}; got {nonzero!r}"
    )

    # Disable exactly one metric; its twin stays enabled.
    asg.disable_metrics_collection(AutoScalingGroupName=group, Metrics=[DISABLED_METRIC])
    disabled_at = _now()
    still = {m["Metric"] for m in _group(ctx, group)["EnabledMetrics"]}
    assert DISABLED_METRIC not in still and TWIN_METRIC in still, (
        f"after disabling only {DISABLED_METRIC}, EnabledMetrics must drop it and keep "
        f"{TWIN_METRIC}: got {sorted(still)!r}"
    )
    # The bucket containing the disable instant may legitimately still be published; every
    # LATER bucket was sampled after collection stopped and must never appear.
    cutoff = disabled_at.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)

    hold_until = time.monotonic() + HOLD_WINDOW_S
    twin_fresh: dict = {}
    waiter = _Backoff(initial_s=15.0, cap_s=15.0)
    while True:
        series = _series_after(ctx, group, [DISABLED_METRIC, TWIN_METRIC], since)
        stray = sorted(ts for ts in series[DISABLED_METRIC] if ts >= cutoff)
        assert not stray, (
            f"collection of {DISABLED_METRIC} was disabled at {disabled_at.isoformat()}, yet "
            f"CloudWatch received datapoints for buckets {[t.isoformat() for t in stray]!r} "
            f"(all: {_fmt(series[DISABLED_METRIC])!r})"
        )
        twin_fresh = {ts: p for ts, p in series[TWIN_METRIC].items() if ts >= cutoff}
        if time.monotonic() >= hold_until:
            break
        waiter.wait()
    print(f"[measured] disabled-series buckets {_fmt(series[DISABLED_METRIC])!r}; twin buckets "
          f"{_fmt(series[TWIN_METRIC])!r}; cutoff {cutoff.isoformat()}")
    assert len(twin_fresh) >= 2, (
        f"positive control: {TWIN_METRIC} stayed enabled, so it must keep receiving datapoints "
        f"over the {HOLD_WINDOW_S}s hold window; buckets at or after {cutoff.isoformat()}: "
        f"{_fmt(twin_fresh)!r} -- without this the silence of {DISABLED_METRIC} proves nothing"
    )
    wrong = {ts.isoformat(): p["Maximum"] for ts, p in twin_fresh.items()
             if p["Maximum"] != EXPECTED[TWIN_METRIC]}
    assert not wrong, f"{TWIN_METRIC}'s fresh datapoints must read {EXPECTED[TWIN_METRIC]}: {wrong!r}"

    # The catalogue is history: the disabled metric stays indexed beside its live twin.
    after = _indexed(ctx, group)
    for name in (DISABLED_METRIC, TWIN_METRIC):
        assert name in after, (
            f"ListMetrics must still index {name} for {group} after disabling "
            f"{DISABLED_METRIC}: got {sorted(after)!r}"
        )

    # Full teardown inline: the registered cleanup chain is capped at 60s, and draining three
    # instances before the subnet and VPC can go takes longer than that. The registered
    # cleanups remain the net for a failure path and are idempotent.
    _teardown(ctx, group, lt_name, subnets, _vpc)


class _Backoff:
    """Capped exponential backoff between polls. Blocks on a private Event, never time.sleep."""

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
    """Tag BOTH the instance and its volume AT LAUNCH, so the server-minted ids an ASG
    creates stay attributable to this check and reapable if teardown loses one."""
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
    name = ctx.unique_name("sim2real-behav-as-grp-")
    ctx.client("autoscaling").create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=MIN_SIZE,
        MaxSize=MAX_SIZE,
        DesiredCapacity=DESIRED,
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
    """Paginated: a filtered Describe can still return pages."""
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


def _state_of(ctx, name: str, instance_id: str) -> str | None:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["LifecycleState"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
