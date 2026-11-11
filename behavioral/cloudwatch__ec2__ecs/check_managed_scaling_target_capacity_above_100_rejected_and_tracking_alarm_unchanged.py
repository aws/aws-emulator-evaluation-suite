"""managed-scaling-target-capacity-above-100-rejected-and-tracking-alarm-unchanged."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-scaling-target-capacity-above-100-rejected-and-tracking-alarm-unchanged"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2", "ecs"]

_VPC_CIDR = "10.97.0.0/16"
_SUBNET_CIDR = "10.97.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AMI_PARAM = "/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
_TARGET_RANGE_MSG = ("The managed scaling target capacity value is invalid. Specify an integer "
                     "greater than 0 and less than or equal to 100 and try again.")


@tags("axis:rejection", "cap:c1", "concern:metrics", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider with targetCapacity=101 is refused and leaves the ECS-owned tracking
    policy and its CapacityProviderReservation AlarmHigh at the old target, while valid updates
    before (100 -> 80) and after (90) the refusal propagate to both.
    """
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    asg = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")

    _ensure_ecs_slr(ctx)
    subnet = _private_subnet(ctx, ec2)
    cluster = ctx.unique_name("sim2real-xsvc-tcap-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))

    ami = ctx.client("ssm").get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AMI_PARAM} resolved to {ami!r}"
    lt_name = _launch_template(ctx, ec2, ami)
    asg_name, asg_arn = _create_asg(ctx, asg, lt_name, subnet)

    cp_name = ctx.unique_name("sim2real-xsvc-tcap-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "ENABLED", "targetCapacity": 100},
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_capacity_provider(ecs, cp_name))
    _associate(ecs, cluster, cp_name)
    ctx.on_cleanup(lambda: _disassociate(ecs, cluster))

    def _wiring():
        """(policy TargetValue, AlarmHigh threshold, AlarmHigh metric, AlarmHigh dims) or None."""
        pols = [p for p in asg.describe_policies(AutoScalingGroupName=asg_name)["ScalingPolicies"]
                if p.get("PolicyType") == "TargetTrackingScaling"]
        if len(pols) != 1:
            return None
        names = [a["AlarmName"] for a in pols[0].get("Alarms", [])]
        if not names:
            return None
        high = [a for a in cw.describe_alarms(AlarmNames=names)["MetricAlarms"]
                if a["ComparisonOperator"] == "GreaterThanThreshold"]
        if len(high) != 1:
            return None
        h = high[0]
        return (pols[0]["TargetTrackingConfiguration"]["TargetValue"], h["Threshold"],
                (h.get("Namespace"), h.get("MetricName")),
                {d["Name"]: d["Value"] for d in h.get("Dimensions", [])})

    before = _poll_until(_wiring, lambda w: w is not None and w[0] == 100.0 and w[1] == 100.0,
                         timeout_s=300.0, interval_s=10.0,
                         description=f"ECS wiring {cp_name} into a target-tracking policy at 100")
    assert before[2] == ("AWS/ECS/ManagedScaling", "CapacityProviderReservation"), (
        f"AlarmHigh watches {before[2]!r}"
    )
    assert before[3] == {"CapacityProviderName": cp_name, "ClusterName": cluster}, (
        f"AlarmHigh dimensions {before[3]!r}"
    )

    # --- Positive control first: a valid target propagates to the policy and the CloudWatch
    # alarm, and how long that took bounds how long a wrongly-accepted value would take.
    t0 = time.monotonic()
    _update_target(ecs, cluster, cp_name, 80)
    at80 = _poll_until(_wiring, lambda w: w is not None and w[0] == 80.0 and w[1] == 80.0,
                       timeout_s=300.0, interval_s=5.0,
                       description=f"targetCapacity=80 reaching the policy and AlarmHigh of {asg_name}")
    latency = time.monotonic() - t0
    assert at80[3] == before[3], f"AlarmHigh dimensions changed {before[3]!r} -> {at80[3]!r}"
    _settled_cp(ecs, cluster, cp_name, 80)

    # --- Break exactly one thing: a target above the 1-100 range.
    code, message = _error(lambda: _update_target(ecs, cluster, cp_name, 101))
    assert code == "ClientException", f"targetCapacity=101 was refused with {code!r}"
    assert message == _TARGET_RANGE_MSG, (
        f"targetCapacity=101 was refused with message {message!r}, expected {_TARGET_RANGE_MSG!r}"
    )
    held = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    held_target = held["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"]
    assert held_target == 80, (
        f"after the refused update the capacity provider reports targetCapacity {held_target!r}"
    )
    assert held.get("updateStatus") == "UPDATE_COMPLETE", (
        f"the refused update left updateStatus {held.get('updateStatus')!r} "
        f"({held.get('updateStatusReason')!r})"
    )
    # Watch the downstream wiring for twice the measured propagation time of the control (at
    # least a minute): every read must still be the pre-refusal target.
    window = max(60.0, 2.0 * latency)
    # The last read is taken at or after the deadline, so the watch always covers the window.
    deadline = time.monotonic() + window
    reads = 0
    while True:
        w = _wiring()
        assert w is not None and w[0] == 80.0 and w[1] == 80.0, (
            f"read #{reads} of the watch after the refused targetCapacity=101, the policy/AlarmHigh read "
            f"{w!r}; expected (80.0, 80.0, ...)"
        )
        reads += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert reads >= 2, f"only {reads} reads in a {window:.0f}s watch window"

    group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    assert group["Instances"] == [], f"an instance launched despite suspended Launch: {group['Instances']!r}"

    # --- Repair: a valid target after the refusal still propagates, so the pipeline we watched
    # was live the whole time and only the out-of-range value was withheld.
    _update_target(ecs, cluster, cp_name, 90)
    _poll_until(_wiring, lambda w: w is not None and w[0] == 90.0 and w[1] == 90.0,
                timeout_s=300.0, interval_s=5.0,
                description=f"targetCapacity=90 reaching the policy and AlarmHigh of {asg_name}")
    _settled_cp(ecs, cluster, cp_name, 90)


def _attachments_settled(ecs, cluster) -> None:
    """An update issued while the cluster's capacity-provider attachment is still
    UPDATE_IN_PROGRESS comes back synchronously as UPDATE_FAILED ('Cluster ... is processing a
    previous update', measured on real AWS), so every update waits for UPDATE_COMPLETE first."""
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster], include=["ATTACHMENTS"])["clusters"][0].get(
            "attachmentsStatus"),
        lambda st: st == "UPDATE_COMPLETE", timeout_s=300.0, interval_s=5.0,
        description=f"cluster {cluster} attachments reaching UPDATE_COMPLETE",
    )


def _settled_cp(ecs, cluster, cp_name, target) -> None:
    cp = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda c: c.get("updateStatus") in ("UPDATE_COMPLETE", "UPDATE_FAILED"),
        timeout_s=300.0, interval_s=5.0, description=f"capacity provider {cp_name} update settling",
    )
    assert cp["updateStatus"] == "UPDATE_COMPLETE", (
        f"update to {target} ended {cp['updateStatus']!r}: {cp.get('updateStatusReason')!r}"
    )
    got = cp["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"]
    assert got == target, f"capacity provider reports targetCapacity {got!r}, expected {target!r}"
    _attachments_settled(ecs, cluster)


def _update_target(ecs, cluster, cp_name, target):
    _attachments_settled(ecs, cluster)
    return ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"managedScaling": {"status": "ENABLED", "targetCapacity": target}})


def _error(fn) -> tuple[str, str]:
    """The botocore (code, message) of fn(). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _tags(name: str) -> list[dict]:
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "Name", "Value": name}]


def _retry_dependency(fn, budget_s: float = 120.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _private_subnet(ctx, ec2) -> str:
    """A VPC and subnet of our own for the ASG. Nothing ever launches into it (the ASG stays at
    0), so no gateway is needed."""
    name = ctx.unique_name("sim2real-xsvc-tcap-net-")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE}; offered {sorted(offered)!r}"
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=zones[0],
                               TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}]
                               )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _launch_template(ctx, ec2, ami) -> str:
    name = ctx.unique_name("sim2real-xsvc-tcap-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "TagSpecifications": [{"ResourceType": "instance", "Tags": _tags(name)},
                                  {"ResourceType": "volume", "Tags": _tags(name)}],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags(name)}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_asg(ctx, asg, lt_name, subnet) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-xsvc-tcap-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg(asg, name))
    # Lowering the target below 100 makes ECS scale out from zero (CapacityProviderReservation
    # reads 100 with no instances, so a move to 80 launches one). Nothing in
    # this check needs an instance, so launching is suspended before ECS ever sees the group.
    asg.suspend_processes(AutoScalingGroupName=name, ScalingProcesses=["Launch"])
    arn = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"]
    return name, arn


def _delete_asg(asg, name) -> None:
    """Force-delete and WAIT until the group is gone. The delete itself is refused while a
    scaling activity is mid-flight (an ECS-driven launch, measured as the cause of a leaked
    instance), so a refusal is retried on a deadline rather than swallowed once."""
    deadline = time.monotonic() + 600.0
    issued = False
    while time.monotonic() < deadline:
        if not asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
            return
        if not issued:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                issued = True
            except ClientError as exc:
                print(f"[retry] delete auto scaling group {name}: {exc.response['Error']['Code']}")
        time.sleep(10.0)
    raise RuntimeError(f"auto scaling group {name} still present after 600s")


def _ensure_ecs_slr(ctx) -> None:
    """Capacity providers need AWSServiceRoleForECS; create it if absent (never deleted --
    it is account-wide and other runs rely on it)."""
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _associate(ecs, cluster, cp_name) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.put_cluster_capacity_providers(
                cluster=cluster, capacityProviders=[cp_name],
                defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}])
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _disassociate(ecs, cluster) -> None:
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.put_cluster_capacity_providers(cluster=cluster, capacityProviders=[],
                                               defaultCapacityProviderStrategy=[])
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code != "UpdateInProgressException" or time.monotonic() > deadline:
                raise
            time.sleep(10.0)


def _delete_capacity_provider(ecs, cp_name) -> None:
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
            return
        except ClientError as exc:
            if time.monotonic() > deadline:
                raise RuntimeError(f"capacity provider {cp_name}: {exc}") from exc
            time.sleep(10.0)


def _delete_cluster(ecs, cluster) -> None:
    deadline = time.monotonic() + 180.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ClusterNotFoundException":
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"cluster {cluster}: {exc}") from exc
            time.sleep(10.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
