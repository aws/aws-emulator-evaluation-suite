"""attach-operations-accepted-during-instance-refresh."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-operations-accepted-during-instance-refresh"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancers, AttachTrafficSources and AttachLoadBalancerTargetGroups succeed while an
    instance refresh is replacing instances (only AttachInstances/DetachInstances are blocked),
    the resources end up attached, and the refresh keeps progressing."""
    asg = ctx.client("autoscaling")
    vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ctx.client("ec2"))
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=2,
        MaxSize=3,
        DesiredCapacity=2,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    def _instances_probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ][0]["Instances"]

    _poll_until(
        _instances_probe,
        lambda ins: len(ins) >= 2 and all(i["LifecycleState"] == "InService" for i in ins),
        timeout_s=420,
        interval_s=10,
    )

    # Real resources: AWS validates existence before the refresh-in-progress gate.
    clb_name = _create_classic_load_balancer(ctx, subnet_id)
    # Distinct target groups so the two attach APIs cannot hit an "already attached" conflict.
    ts_tg_arn = _create_target_group(ctx, vpc_id)
    tg_arn = _create_target_group(ctx, vpc_id)

    # The checkpoint keeps the refresh InProgress long enough; a small group can finish first.
    refresh_id = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Preferences={
            "MinHealthyPercentage": 90,
            "InstanceWarmup": 0,
            "CheckpointPercentages": [50],
            "CheckpointDelay": 600,
        },
    )["InstanceRefreshId"]
    ctx.on_cleanup(lambda: _cancel_refresh_best_effort(ctx, group_name))

    def _refresh_status_probe():
        refreshes = asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, InstanceRefreshIds=[refresh_id]
        )["InstanceRefreshes"]
        return refreshes[0]["Status"] if refreshes else None

    _poll_until(
        _refresh_status_probe,
        lambda s: s in ("Pending", "InProgress"),
        timeout_s=60,
        interval_s=2,
    )

    # A Pending/InProgress status can precede real replacement work; wait until instances change
    # (non-InService state or a surge count) so the refresh is unambiguously active.
    def _refresh_and_instances_probe():
        return _refresh_status_probe(), _instances_probe()

    def _replacement_underway(pair):
        status, instances = pair
        if status not in ("Pending", "InProgress"):
            return False
        non_steady = [i for i in instances if i["LifecycleState"] != "InService"]
        return len(instances) != 2 or bool(non_steady)

    _poll_until(
        _refresh_and_instances_probe,
        _replacement_underway,
        timeout_s=300,
        interval_s=5,
    )

    def _refresh_still_active():
        status = _refresh_status_probe()
        return status in ("Pending", "InProgress")

    assert _refresh_still_active(), (
        "instance refresh unexpectedly stopped progressing before the attach calls were issued"
    )

    # Real AWS accepts this call while a refresh is in progress; a refusal raises here.
    asg.attach_load_balancers(AutoScalingGroupName=group_name, LoadBalancerNames=[clb_name])

    # Real AWS accepts this call while a refresh is in progress; a refusal raises here.
    asg.attach_traffic_sources(AutoScalingGroupName=group_name, TrafficSources=[{"Identifier": ts_tg_arn}])

    # Real AWS accepts this call while a refresh is in progress; a refusal raises here.
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=group_name, TargetGroupARNs=[tg_arn])

    # A 200 alone could be a silent no-op: confirm the attachments and the refresh state.
    group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
        "AutoScalingGroups"
    ][0]
    assert clb_name in group.get("LoadBalancerNames", []), (
        f"AttachLoadBalancers during active refresh did not result in {clb_name} being "
        f"attached; LoadBalancerNames={group.get('LoadBalancerNames')}"
    )
    target_group_arns = set(group.get("TargetGroupARNs", []))
    assert ts_tg_arn in target_group_arns, (
        f"AttachTrafficSources during active refresh did not result in {ts_tg_arn} being "
        f"attached; TargetGroupARNs={group.get('TargetGroupARNs')}"
    )
    assert tg_arn in target_group_arns, (
        f"AttachLoadBalancerTargetGroups during active refresh did not result in {tg_arn} "
        f"being attached; TargetGroupARNs={group.get('TargetGroupARNs')}"
    )

    final_status = _refresh_status_probe()
    assert final_status in ("Pending", "InProgress", "Successful"), (
        f"instance refresh ended up in status {final_status!r} after the attach calls, "
        "expected it to still be progressing (or to have completed normally), not "
        "cancelled/failed as a side effect of the attach calls"
    )




def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _own_vpc_and_subnet(ctx, ec2, instance_type="t3.micro", cidr="10.81.0.0/16",
                        subnet_cidr="10.81.1.0/24"):
    """A VPC and one subnet this check creates, in an available AZ that offers
    ``instance_type``. Each create registers its cleanup immediately."""
    tag = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ offers {instance_type!r}"
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=zones[0],
                                  TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}]
                                  )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _create_classic_load_balancer(ctx, subnet_id: str) -> str:
    elb = ctx.client("elb")
    name = ctx.unique_name("sim2real-clb-")[:32].rstrip("-")
    elb.create_load_balancer(
        LoadBalancerName=name,
        Listeners=[
            {"Protocol": "TCP", "LoadBalancerPort": 80, "InstanceProtocol": "TCP", "InstancePort": 80}
        ],
        Subnets=[subnet_id],
        Scheme="internal",
    )
    ctx.on_cleanup(lambda: _teardown(lambda: elb.delete_load_balancer(LoadBalancerName=name), "LoadBalancerNotFound"))
    return name


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-")[:32].rstrip("-")
    resp = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
    )
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn), "TargetGroupNotFound"))
    return tg_arn


def _teardown(fn, *not_found: str) -> None:
    """Run a delete; only ``not_found`` means gone, ResourceInUse is retried for 60 s, the rest raises."""
    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in not_found:
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _cancel_refresh_best_effort(ctx, group_name: str) -> None:
    asg = ctx.client("autoscaling")
    try:
        asg.cancel_instance_refresh(AutoScalingGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ActiveInstanceRefreshNotFound":
            raise


def _delete_asg_force(ctx, name: str) -> None:
    """Force-delete the group, retrying in-progress refusals for 60 s; only "not found" means gone."""
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + 60
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ValidationError" and "not found" in err.response["Error"].get("Message", ""):
                return
            if code not in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)



# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits a 900s cleanup budget.
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
        _time.sleep(10)
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
        _time.sleep(10)


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
