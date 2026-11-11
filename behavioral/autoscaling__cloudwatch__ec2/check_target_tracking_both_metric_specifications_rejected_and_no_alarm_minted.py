"""target-tracking-both-metric-specifications-rejected-and-no-alarm-minted."""
from __future__ import annotations

import time

from behavioral_harness import tags

# On AWS, PutScalingPolicy(TargetTrackingScaling) carrying BOTH a
# PredefinedMetricSpecification and a CustomizedMetricSpecification returned HTTP 400
# ValidationError 'You should provide either a CustomizedMetricSpecification or a
# PredefinedMetricSpecification'.
# The Smithy model declares no such rule (TargetTrackingConfiguration declares both members optional and
# independent), so a model-driven
# target accepts this input for free -- the gap between model and service is the signal.

CHECK = "target-tracking-both-metric-specifications-rejected-and-no-alarm-minted"
GROUP = "alerting"
SERVICES = ["autoscaling", "cloudwatch", "ec2"]

NAMESPACE = "sim2real/autoscaling"
METRIC = "ScaleSignal"
TARGET_VALUE = 50.0


def _valid_configuration(group: str) -> dict:
    return {
        "CustomizedMetricSpecification": {
            "Namespace": NAMESPACE,
            "MetricName": METRIC,
            "Dimensions": [{"Name": "AutoScalingGroupName", "Value": group}],
            "Statistic": "Average",
        },
        "TargetValue": TARGET_VALUE,
    }


def _broken_configuration(group: str) -> dict:
    """The valid configuration with exactly ONE thing broken."""
    config = _valid_configuration(group)
    config["PredefinedMetricSpecification"] = {"PredefinedMetricType": "ASGAverageCPUUtilization"}
    return config


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A target-tracking policy naming BOTH a predefined and a customized metric is refused
    with ValidationError, and the refusal mints no CloudWatch alarm.
    """
    asg = ctx.client("autoscaling")
    ami = _al2023_ami(ctx)
    _vpc, _azs, subnets = _network(ctx, "t3.micro", want=1)
    lt_name = _launch_template(ctx, ami)
    # DesiredCapacity=0: the policy and its alarms exist without any instance.
    group = _create_asg(ctx, lt_name, subnets, min_size=0, max_size=2, desired=0)
    policy_name = ctx.unique_name("sim2real-xsvc-tt-neg-")
    ctx.on_cleanup(lambda: _unless_gone(
        lambda: asg.delete_policy(AutoScalingGroupName=group, PolicyName=policy_name)))

    response = _call(lambda: asg.put_scaling_policy(
        AutoScalingGroupName=group,
        PolicyName=policy_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration=_broken_configuration(group),
    ))
    assert response["accepted"] is False, (
        f"PutScalingPolicy must reject the broken configuration, but it was accepted: "
        f"{response['result']!r}"
    )
    assert response["code"] == "ValidationError", (
        f"expected ValidationError, got {response['code']!r} ({response['message']!r})"
    )
    expected = ("You should provide either a CustomizedMetricSpecification or a "
                "PredefinedMetricSpecification")
    assert response["message"] == expected, (
        f"expected message {expected!r}, got {response['message']!r}"
    )
    assert response["status"] == 400, (
        f"the rejection must be a 400 sender fault, got HTTP {response['status']!r}"
    )

    # Effect absent at Auto Scaling.
    names = [p["PolicyName"] for p in _policies(ctx, group)]
    assert names == [], f"a rejected PutScalingPolicy must leave no policy, got {names!r}"

    # Positive control: repair the ONE broken thing, same group, same policy name.
    good = asg.put_scaling_policy(
        AutoScalingGroupName=group,
        PolicyName=policy_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration=_valid_configuration(group),
    )
    minted = sorted(a["AlarmName"] for a in good.get("Alarms", []))
    assert len(minted) == 2, (
        f"the repaired policy must mint two alarms (AlarmHigh, AlarmLow), got {minted!r}"
    )
    described = _policies(ctx, group)
    assert [p["PolicyName"] for p in described] == [policy_name], (
        f"exactly the repaired policy must be listed, got {[p['PolicyName'] for p in described]!r}"
    )
    stored = described[0]["TargetTrackingConfiguration"]
    assert stored.get("TargetValue") == TARGET_VALUE, (
        f"the stored TargetValue must be the repaired {TARGET_VALUE}, got {stored!r}"
    )
    assert "PredefinedMetricSpecification" not in stored, (
        f"the stored configuration must carry no predefined metric, got {stored!r}"
    )
    assert stored.get("CustomizedMetricSpecification", {}).get("Statistic") == "Average", (
        f"the stored customized metric must carry Statistic=Average, got {stored!r}"
    )

    # Effect absent at CloudWatch: with the repaired policy's alarms present (the barrier), the
    # group's TargetTracking prefix holds exactly those -- the rejected attempt minted nothing.
    present = _poll(
        lambda: _alarm_names_with_prefix(ctx, f"TargetTracking-{group}-"),
        lambda found: set(minted) <= set(found),
        timeout_s=120,
        interval_s=5,
        description=f"CloudWatch lists the repaired policy's alarms {minted!r}",
    )
    assert present == minted, (
        f"CloudWatch must hold exactly the repaired policy's alarms for this group, got "
        f"{present!r}, expected {minted!r}"
    )
    for alarm in _alarms_named(ctx, minted):
        assert alarm.get("AlarmActions") == [good["PolicyARN"]], (
            f"{alarm['AlarmName']} must act only on the repaired policy, got "
            f"{alarm.get('AlarmActions')!r}"
        )
        assert (alarm.get("Namespace"), alarm.get("MetricName")) == (NAMESPACE, METRIC), (
            f"{alarm['AlarmName']} must watch {NAMESPACE}/{METRIC}, got "
            f"{(alarm.get('Namespace'), alarm.get('MetricName'))!r}"
        )


def _call(fn) -> dict:
    """Run fn and classify the outcome. An unexpected SUCCESS is reported as accepted=True
    with the result attached, never as a falsy code that would read as a naming mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classified below
        resp = getattr(exc, "response", None)
        if not resp:
            raise
        return {
            "accepted": False,
            "code": resp.get("Error", {}).get("Code"),
            "message": resp.get("Error", {}).get("Message"),
            "status": resp.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            "result": None,
        }
    return {"accepted": True, "code": None, "message": None, "status": None, "result": result}


def _policies(ctx, group: str) -> list[dict]:
    records = []
    paginator = ctx.client("autoscaling").get_paginator("describe_policies")
    for page in paginator.paginate(AutoScalingGroupName=group):
        records += page["ScalingPolicies"]
    return records


def _alarm_names_with_prefix(ctx, prefix: str) -> list[str]:
    names: list[str] = []
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNamePrefix=prefix):
        names += [a["AlarmName"] for a in page.get("MetricAlarms", [])]
    return sorted(names)


def _alarms_named(ctx, names: list[str]) -> list[dict]:
    fetched: list[dict] = []
    paginator = ctx.client("cloudwatch").get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNames=names):
        fetched += page.get("MetricAlarms", [])
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
    """Latest Amazon-owned AL2023 x86_64 image, resolved through EC2 itself (no SSM)."""
    images = ctx.client("ec2").describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, f"no available Amazon-owned AL2023 x86_64 image in {ctx.region}"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _network(ctx, instance_type: str, want: int):
    """A DEDICATED VPC with `want` subnets, in AZs that really offer instance_type."""
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
        CidrBlock="10.224.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), f"vpc {vpc_id}")
    )
    subnet_ids = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.224.{index}.0/24",
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
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-xsvc-as-lt-")
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


def _create_asg(ctx, lt_name: str, subnets, *, min_size: int, max_size: int,
                desired: int) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-xsvc-as-grp-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=",".join(subnets),
        Tags=[
            {"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()
        ],
    )

    def _drop():
        _unless_gone(lambda: asg.delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True))
        for _ in range(60):
            if not _describe_groups(ctx, name):
                return
            time.sleep(5)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    groups = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_groups"
    ).paginate(AutoScalingGroupNames=[name]):
        groups += page["AutoScalingGroups"]
    return groups


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
