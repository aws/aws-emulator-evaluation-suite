"""target-tracking-disable-scale-in-omits-the-scale-in-alarm."""
from __future__ import annotations

import time

from behavioral_harness import tags

# AWS refuses two target-tracking policies for the same metric specification on one group
# (`ValidationError: Only one TargetTrackingScaling policy for a given metric specification is
# allowed.`), so the twin and the subject each get their own otherwise-identical group.

CHECK = "target-tracking-disable-scale-in-omits-the-scale-in-alarm"
GROUP = "alerting"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

TARGET_VALUE = 43.5
_SCALE_OUT_OPERATORS = ("GreaterThanThreshold", "GreaterThanOrEqualToThreshold")
_SCALE_IN_OPERATORS = ("LessThanThreshold", "LessThanOrEqualToThreshold")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:metrics",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A target-tracking policy with DisableScaleIn=True gets a scale-out alarm and NO
    scale-in alarm at CloudWatch; its identical twin without the flag gets both.
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # DesiredCapacity=0: a target-tracking policy and its alarms exist without any instance, so
    # this check costs nothing to run and still grades the whole alarm-minting path.
    both_group = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=4, desired=0)
    out_only_group = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=4, desired=0)

    configuration = {
        "PredefinedMetricSpecification": {
            "PredefinedMetricType": "ASGAverageCPUUtilization"
        },
        "TargetValue": TARGET_VALUE,
    }
    both_name = ctx.unique_name("sim2real-behav-tt-both-")
    out_only_name = ctx.unique_name("sim2real-behav-tt-out-")
    both_reported = asg.put_scaling_policy(
        AutoScalingGroupName=both_group,
        PolicyName=both_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={**configuration, "DisableScaleIn": False},
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.delete_policy(AutoScalingGroupName=both_group, PolicyName=both_name)))
    out_only_reported = asg.put_scaling_policy(
        AutoScalingGroupName=out_only_group,
        PolicyName=out_only_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={**configuration, "DisableScaleIn": True},
    )
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.delete_policy(AutoScalingGroupName=out_only_group, PolicyName=out_only_name)))

    # Independent read, through DescribePolicies rather than the PutScalingPolicy responses.
    both = _policy(ctx, both_group, both_name)
    out_only = _policy(ctx, out_only_group, out_only_name)
    assert both["TargetTrackingConfiguration"].get("DisableScaleIn") is False, (
        f"the twin policy must record DisableScaleIn=False, got "
        f"{both['TargetTrackingConfiguration'].get('DisableScaleIn')!r}"
    )
    assert out_only["TargetTrackingConfiguration"].get("DisableScaleIn") is True, (
        f"the subject policy must record DisableScaleIn=True, got "
        f"{out_only['TargetTrackingConfiguration'].get('DisableScaleIn')!r}"
    )
    for label, reported, described in (
        ("twin", both_reported, both),
        ("subject", out_only_reported, out_only),
    ):
        from_put = {a["AlarmName"] for a in reported.get("Alarms", [])}
        from_describe = {a["AlarmName"] for a in described.get("Alarms", [])}
        assert from_put == from_describe, (
            f"the {label} policy's alarm set must be the same whether read from the "
            f"PutScalingPolicy response or from DescribePolicies: {sorted(from_put)!r} vs "
            f"{sorted(from_describe)!r}"
        )

    # Terminal read at the CONSUMER: every reported alarm must really exist at CloudWatch, and
    # is classified by its own ComparisonOperator rather than by its generated name.
    both_alarms = _fetch_alarms(ctx, both_group, both, "twin", both_name)
    out_only_alarms = _fetch_alarms(ctx, out_only_group, out_only, "subject", out_only_name)

    both_out = [a for a in both_alarms if a["ComparisonOperator"] in _SCALE_OUT_OPERATORS]
    both_in = [a for a in both_alarms if a["ComparisonOperator"] in _SCALE_IN_OPERATORS]
    out_only_out = [
        a for a in out_only_alarms if a["ComparisonOperator"] in _SCALE_OUT_OPERATORS
    ]
    out_only_in = [a for a in out_only_alarms if a["ComparisonOperator"] in _SCALE_IN_OPERATORS]

    # Positive control: the unflagged twin proves this target mints BOTH directions, so the
    # subject's missing scale-in alarm is a consequence of the flag and not of a target that
    # never mints a scale-in alarm for anyone.
    assert len(both_out) >= 1 and len(both_in) >= 1, (
        f"the unflagged twin policy must own at least one scale-out AND one scale-in alarm, "
        f"got {[a['ComparisonOperator'] for a in both_alarms]!r} for "
        f"{sorted(a['AlarmName'] for a in both_alarms)!r}"
    )
    assert len(out_only_out) >= 1, (
        f"DisableScaleIn=True must still own a scale-out alarm, got "
        f"{[a['ComparisonOperator'] for a in out_only_alarms]!r}"
    )
    assert not out_only_in, (
        f"DisableScaleIn=True must own NO scale-in alarm, but CloudWatch reports "
        f"{[(a['AlarmName'], a['ComparisonOperator'], a['Threshold']) for a in out_only_in]!r}"
    )
    assert len(out_only_alarms) < len(both_alarms), (
        f"disabling scale-in must reduce the alarm count: the flagged policy owns "
        f"{len(out_only_alarms)} alarms ({sorted(a['AlarmName'] for a in out_only_alarms)!r}) "
        f"and its unflagged twin owns {len(both_alarms)} "
        f"({sorted(a['AlarmName'] for a in both_alarms)!r})"
    )

    # The threshold is DERIVED from the target value this check chose, not recorded.
    for label, alarms in (("twin", both_out), ("subject", out_only_out)):
        thresholds = sorted({a["Threshold"] for a in alarms})
        assert thresholds == [TARGET_VALUE], (
            f"the {label} policy's scale-out alarm must fire at the TargetValue this check set: "
            f"expected [{TARGET_VALUE}], got {thresholds!r}"
        )

    # Scoped cleanup: deleting the flagged policy removes ITS alarms from CloudWatch and leaves
    # the twin's alone -- the delete is asserted rather than assumed.
    doomed = sorted(a["AlarmName"] for a in out_only_alarms)
    survivors = sorted(a["AlarmName"] for a in both_alarms)
    asg.delete_policy(AutoScalingGroupName=out_only_group, PolicyName=out_only_name)
    gone = _poll(
        lambda: _existing_alarm_names(ctx, doomed),
        lambda present: not present,
        timeout_s=600,
        interval_s=20,
        description=(
            f"DeletePolicy removed the managed alarms {doomed!r} from CloudWatch as well as "
            f"the policy"
        ),
    )
    assert not gone, (
        f"deleting the target-tracking policy left its managed alarms behind at CloudWatch: "
        f"{sorted(gone)!r}"
    )
    still_there = _existing_alarm_names(ctx, survivors)
    assert sorted(still_there) == survivors, (
        f"deleting one policy must not touch the other's alarms: expected {survivors!r} to "
        f"survive, CloudWatch still has {sorted(still_there)!r}"
    )
    remaining_out_only = {p["PolicyName"] for p in _policies(ctx, out_only_group)}
    remaining_both = {p["PolicyName"] for p in _policies(ctx, both_group)}
    assert out_only_name not in remaining_out_only, (
        f"after DeletePolicy the subject group must not list {out_only_name!r}, got "
        f"{sorted(remaining_out_only)!r}"
    )
    assert both_name in remaining_both, (
        f"deleting the subject policy must not touch the twin group's own policy list: "
        f"expected {both_name!r} in {sorted(remaining_both)!r}"
    )


def _policies(ctx, group: str) -> list[dict]:
    records = []
    paginator = ctx.client("autoscaling").get_paginator("describe_policies")
    for page in paginator.paginate(AutoScalingGroupName=group):
        records += page["ScalingPolicies"]
    return records


def _policy(ctx, group: str, policy: str) -> dict:
    for record in _policies(ctx, group):
        if record["PolicyName"] == policy:
            return record
    raise AssertionError(f"scaling policy {policy!r} not found on group {group!r}")


def _existing_alarm_names(ctx, names: list[str]) -> set[str]:
    """Which of `names` CloudWatch actually has. DescribeAlarms ignores unknown names, so the
    caller learns presence and absence from the same read."""
    if not names:
        return set()
    found: set[str] = set()
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNames=names):
        for alarm in page.get("MetricAlarms", []):
            found.add(alarm["AlarmName"])
    return found


def _fetch_alarms(ctx, group: str, policy: dict, label: str, policy_name: str) -> list[dict]:
    """Fetch every alarm the policy claims, AT CLOUDWATCH, and assert each one is really the
    policy's: right metric, right dimension, and an action pointing back at this policy.

    A target that returns invented alarm names in the PutScalingPolicy response passes any
    assertion made against that response alone; it cannot pass this one.
    """
    claimed = sorted(a["AlarmName"] for a in policy.get("Alarms", []))
    assert claimed, (
        f"the {label} policy {policy_name!r} reported no alarms at all: {policy!r}"
    )
    fetched: list[dict] = []
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNames=claimed):
        fetched += page.get("MetricAlarms", [])
    found = sorted(a["AlarmName"] for a in fetched)
    assert found == claimed, (
        f"the {label} policy claims alarms that do not exist at CloudWatch: claimed "
        f"{claimed!r}, CloudWatch has {found!r}"
    )
    policy_arn = policy["PolicyARN"]
    for alarm in fetched:
        assert alarm["Namespace"] == "AWS/EC2", (
            f"{alarm['AlarmName']} must watch AWS/EC2 for ASGAverageCPUUtilization, got "
            f"{alarm['Namespace']!r}"
        )
        assert alarm["MetricName"] == "CPUUtilization", (
            f"{alarm['AlarmName']} must watch CPUUtilization, got {alarm['MetricName']!r}"
        )
        dimensions = {d["Name"]: d["Value"] for d in alarm["Dimensions"]}
        assert dimensions == {"AutoScalingGroupName": group}, (
            f"{alarm['AlarmName']} must be dimensioned on this group only, got {dimensions!r}, "
            f"expected {{'AutoScalingGroupName': {group!r}}}"
        )
        assert policy_arn in alarm["AlarmActions"], (
            f"{alarm['AlarmName']} must act on the policy that owns it: AlarmActions "
            f"{alarm['AlarmActions']!r} does not contain {policy_arn!r}"
        )
    return fetched


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

    def _drop():
        # A group left with capacity RELAUNCHES what you just deleted, and a group with
        # Terminate suspended cannot be drained at all -- so resume everything, drain to
        # zero, ForceDelete, then WAIT for the group to disappear before the subnets go.
        _unless_gone(lambda: asg.resume_processes(AutoScalingGroupName=name))
        _unless_gone(lambda: asg.update_auto_scaling_group(
            AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0))
        _unless_gone(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))
        for _ in range(450):
            if not _describe_groups(ctx, name):
                return
            time.sleep(2)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


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
