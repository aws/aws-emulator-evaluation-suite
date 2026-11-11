"""group-metrics-reach-cloudwatch-only-for-the-enabled-subset."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

# On AWS the first datapoint for the enabled metric lands within about 60 s of the capacity
# change (900 s is a ceiling, not the claim), and CloudWatch reports Unit "None" for both
# GroupDesiredCapacity and GroupTotalInstances.

CHECK = "group-metrics-reach-cloudwatch-only-for-the-enabled-subset"
GROUP = "alerting"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

NAMESPACE = "AWS/AutoScaling"
SUBJECT_METRIC = "GroupDesiredCapacity"
CONTROL_METRIC = "GroupTotalInstances"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html
@tags("axis:negative-delivery", "cap:c4", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Auto Scaling delivers group metrics to AWS/AutoScaling for the metrics that were
    enabled and for no others -- proven by two groups whose enabled subsets are swapped.
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    subject = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)
    control = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=1)
    ctx.on_cleanup(lambda: _drop_groups(ctx, [subject, control]))

    # Swapped subsets: exactly one metric each, and they differ.
    asg.enable_metrics_collection(
        AutoScalingGroupName=subject, Metrics=[SUBJECT_METRIC], Granularity="1Minute"
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.disable_metrics_collection(AutoScalingGroupName=subject)))
    asg.enable_metrics_collection(
        AutoScalingGroupName=control, Metrics=[CONTROL_METRIC], Granularity="1Minute"
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.disable_metrics_collection(AutoScalingGroupName=control)))
    for name, metric in ((subject, SUBJECT_METRIC), (control, CONTROL_METRIC)):
        enabled = {m["Metric"] for m in _group(ctx, name)["EnabledMetrics"]}
        assert enabled == {metric}, (
            f"setup: {name} must have exactly {{{metric!r}}} enabled, got {sorted(enabled)!r}"
        )

    for name in (subject, control):
        _poll(
            lambda name=name: _ids_in_state(ctx, name, "InService"),
            lambda ids: len(ids) == 1,
            timeout_s=900,
            interval_s=15,
            description=f"setup: {name} reached 1 InService instance",
        )

    # One fan-out, same instant: both groups have something to report about.
    started = _now()
    for name in (subject, control):
        asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2)
    for name in (subject, control):
        _poll(
            lambda name=name: _ids_in_state(ctx, name, "InService"),
            lambda ids: len(ids) == 2,
            timeout_s=900,
            interval_s=15,
            description=f"setup: {name} converged to 2 InService instances",
        )

    # Positive control legs, and the latency measurement that gives the absence legs meaning.
    # The poll's terminal set must not admit a STALE datapoint: CloudWatch can (and does)
    # still be serving the pre-scale desired=1 bucket seconds after the scale
    # to 2, so "len(values) >= 1" is satisfied by the wrong value and the check races ahead of
    # its own signal. Wait for the datapoint that actually reports the capacity this check set.
    for name, metric in ((subject, SUBJECT_METRIC), (control, CONTROL_METRIC)):
        values = _poll(
            lambda name=name, metric=metric: _datapoint_values(ctx, name, metric, started),
            lambda values: 2.0 in values,
            timeout_s=900,
            interval_s=30,
            description=(
                f"CloudWatch delivered a {NAMESPACE}/{metric} datapoint reporting the capacity "
                f"of 2 this check set for {name}, which enabled exactly that metric"
            ),
        )
        assert max(values) == 2.0, (
            f"{name} enabled {metric} and changed its capacity to 2, but CloudWatch's "
            f"{NAMESPACE}/{metric} datapoints for it are {sorted(values)!r}"
        )
    latency_s = (_now() - started).total_seconds()
    print(f"[measured] first enabled-metric datapoint reporting the new capacity visible after "
          f"{latency_s:.0f}s")

    # The value is derived from the capacity this check set.
    subject_values = _datapoint_values(ctx, subject, SUBJECT_METRIC, started)
    assert max(subject_values) == 2.0, (
        f"{SUBJECT_METRIC} must report the desired capacity this check actually set: expected a "
        f"maximum of 2.0, got {sorted(subject_values)!r}"
    )
    control_values = _datapoint_values(ctx, control, CONTROL_METRIC, started)
    assert max(control_values) == 2.0, (
        f"{CONTROL_METRIC} must report the instance count the group converged to: expected a "
        f"maximum of 2.0, got {sorted(control_values)!r}"
    )
    # Pinned, not just cross-checked for equality: AWS/AutoScaling's group metrics are dimensionless
    # counts with a fixed, server-defined Unit -- not an account-configurable value -- and AWS
    # reports Unit "None" for both GroupDesiredCapacity and GroupTotalInstances.
    subject_unit = _datapoint_unit(ctx, subject, SUBJECT_METRIC, started)
    control_unit = _datapoint_unit(ctx, control, CONTROL_METRIC, started)
    assert subject_unit == "None", (
        f"{SUBJECT_METRIC} is a dimensionless count and CloudWatch documents its Unit as 'None': "
        f"got {subject_unit!r}"
    )
    assert control_unit == "None", (
        f"{CONTROL_METRIC} is a dimensionless count and CloudWatch documents its Unit as 'None': "
        f"got {control_unit!r}"
    )

    # The absence legs, held for a window longer than the measured positive latency and
    # asserted on TWO independent observables apiece.
    hold_until = time.monotonic() + max(60.0, 3 * latency_s)
    while True:
        for name, absent in ((subject, CONTROL_METRIC), (control, SUBJECT_METRIC)):
            stray = _datapoint_values(ctx, name, absent, started)
            assert not stray, (
                f"{name} never enabled {absent}, but CloudWatch has {len(stray)} "
                f"{NAMESPACE}/{absent} datapoints for it: {sorted(stray)!r}. Its twin's "
                f"{absent} datapoints arrived {latency_s:.0f}s in, so this is a real "
                f"over-delivery and not a slow publish."
            )
            indexed = _indexed_metrics(ctx, name)
            assert absent not in indexed, (
                f"{name} never enabled {absent}, but ListMetrics indexes it under "
                f"{NAMESPACE} for that group: {sorted(indexed)!r}"
            )
        if time.monotonic() >= hold_until:
            break
        time.sleep(30)

    # The presence legs on the second observable, so the ListMetrics assertions above cannot
    # pass merely because ListMetrics returns nothing for anything.
    for name, metric in ((subject, SUBJECT_METRIC), (control, CONTROL_METRIC)):
        indexed = _indexed_metrics(ctx, name)
        assert metric in indexed, (
            f"{name} enabled {metric} and CloudWatch served datapoints for it, but ListMetrics "
            f"does not index it under {NAMESPACE} for that group: {sorted(indexed)!r}"
        )


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _dimensions(group: str) -> list[dict[str, str]]:
    return [{"Name": "AutoScalingGroupName", "Value": group}]


def _statistics(ctx, group: str, metric: str, since: dt.datetime) -> list[dict]:
    """GetMetricStatistics at CloudWatch -- the consumer, and a different service entirely
    from the Auto Scaling calls that produced the signal.

    A minute of slack on each side of the window: the aggregation boundary is the server's, not
    this check's, and a window that starts exactly at `since` can clip the first bucket.
    """
    return ctx.client("cloudwatch").get_metric_statistics(
        Namespace=NAMESPACE,
        MetricName=metric,
        Dimensions=_dimensions(group),
        StartTime=since - dt.timedelta(minutes=1),
        EndTime=_now() + dt.timedelta(minutes=1),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]


def _datapoint_values(ctx, group: str, metric: str, since: dt.datetime) -> list[float]:
    return [point["Maximum"] for point in _statistics(ctx, group, metric, since)]


def _datapoint_unit(ctx, group: str, metric: str, since: dt.datetime) -> str:
    points = _statistics(ctx, group, metric, since)
    assert points, f"no {metric} datapoints for {group}, so its unit cannot be read"
    return points[0]["Unit"]


def _indexed_metrics(ctx, group: str) -> set[str]:
    """Which AWS/AutoScaling metric names CloudWatch's own index carries for this group."""
    names: set[str] = set()
    paginator = ctx.client("cloudwatch").get_paginator("list_metrics")
    for page in paginator.paginate(Namespace=NAMESPACE, Dimensions=[
        {"Name": "AutoScalingGroupName", "Value": group}
    ]):
        for metric in page["Metrics"]:
            names.add(metric["MetricName"])
    return names


_MANAGED_TAGS = {"sim2real": CHECK, "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


_BUSY = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")


def _unless_gone(fn, wait_s: float = 60):
    """Run one teardown call: only a not-found answer means already gone; a busy group is
    retried every 2 s for wait_s seconds; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + wait_s
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
            if code not in _BUSY or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)


def _retry_delete(fn, what: str, *, attempts: int = 24, interval_s: float = 10.0) -> None:
    """Delete something that stays referenced while EC2 tears ENIs down."""
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception:  # noqa: BLE001 - still in use by a draining dependency
            time.sleep(interval_s)
    raise RuntimeError(f"{what} could not be deleted")


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition"):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, instance_type: str, want: int):
    """A DEDICATED VPC with `want` subnets, in AZs that really offer instance_type.

    A freshly provisioned account may have no default VPC at all, and borrowing an ambient
    one lets a concurrent run's IP exhaustion masquerade as a scaling failure.
    """
    ec2 = ctx.client("ec2")
    offered = sorted(
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    )
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    azs = [z for z in offered if z in available][:want]
    assert len(azs) == want, (
        f"need {want} available AZs offering {instance_type!r} in {ctx.region}, got {azs!r} "
        f"(offered={offered!r})"
    )

    vpc_id = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), f"vpc {vpc_id}")
    )

    subnet_ids = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.221.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sn=subnet_id: _retry_delete(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sn), f"subnet {sn}"
            )
        )
        subnet_ids.append(subnet_id)
    return vpc_id, azs, subnet_ids


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
    ctx.on_cleanup(
        lambda: _retry_delete(
            lambda: ec2.delete_launch_template(LaunchTemplateName=name),
            f"launch template {name}",
        )
    )
    return name


def _create_asg(ctx, lt_name: str, subnets, *, min_size: int, max_size: int, desired: int,
                lt_version: str = "$Latest", **kwargs) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-behav-as-grp-")
    params = {
        "AutoScalingGroupName": name,
        "LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": lt_version},
        "MinSize": min_size,
        "MaxSize": max_size,
        "DesiredCapacity": desired,
        "VPCZoneIdentifier": ",".join(subnets),
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [
            {"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()
        ],
    }
    params.update(kwargs)
    if params.get("MixedInstancesPolicy") is not None:
        # A group declares a top-level launch template OR a mixed instances policy, never both.
        params.pop("LaunchTemplate", None)
    asg.create_auto_scaling_group(**params)
    return name


def _drop_groups(ctx, names: list[str]) -> None:
    """ForceDelete every named group once before retrying any busy one, so one slow group cannot
    spend the cleanup budget before another is told to delete; a busy group then gets resume,
    drain-to-zero and ForceDelete with retries."""
    _leaks: list = []
    asg = ctx.client("autoscaling")
    from botocore.exceptions import ClientError

    busy = []
    for name in names:
        try:
            _unless_gone(lambda name=name: asg.resume_processes(AutoScalingGroupName=name), 0)
            _unless_gone(lambda name=name: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True), 0)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in _BUSY:
                busy.append(name)
            else:
                _leaks.append((f"auto scaling group {name} delete failed: {exc}", exc))
    for name in busy:
        try:
            _unless_gone(lambda name=name: asg.resume_processes(AutoScalingGroupName=name))
            _unless_gone(lambda name=name: asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
            _unless_gone(lambda name=name: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True))
        except ClientError as exc:
            _leaks.append((f"auto scaling group {name} delete failed: {exc}", exc))
    remaining = set(names)
    for _ in range(450):
        remaining = {n for n in remaining if _describe_groups(ctx, n)}
        if not remaining:
            if _leaks:
                raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
                    (e for _, e in _leaks if e is not None), None
                )
            return
        time.sleep(2)
    for name in sorted(remaining):
        _leaks.append((f"auto scaling group {name} still present after ForceDelete", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return several pages."""
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
        i["InstanceId"] for i in _group(ctx, name)["Instances"]
        if i["LifecycleState"] in states
    )


def _az_of(ctx, name: str, instance_id: str) -> str:
    for inst in _group(ctx, name)["Instances"]:
        if inst["InstanceId"] == instance_id:
            return inst["AvailabilityZone"]
    raise AssertionError(f"instance {instance_id!r} is not a member of group {name!r}")


def _count_by_az(ctx, name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for inst in _group(ctx, name)["Instances"]:
        if inst["LifecycleState"] == "InService":
            counts[inst["AvailabilityZone"]] = counts.get(inst["AvailabilityZone"], 0) + 1
    return counts


def _ec2_instance(ctx, instance_id: str) -> dict:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _ec2_state(ctx, instance_id: str) -> str:
    return _ec2_instance(ctx, instance_id)["State"]["Name"]


def _launch_time(ctx, instance_id: str):
    return _ec2_instance(ctx, instance_id)["LaunchTime"]


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: an asynchronous
# delete in this VPC leaves its ENIs behind briefly, so DeleteSubnet / DeleteVpc retries
# DependencyViolation within one shared window, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
