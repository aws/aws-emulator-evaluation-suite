"""op-contract-cancelInstanceRefresh."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-cancelInstanceRefresh"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelInstanceRefresh transitions an in-progress refresh to Cancelled;
    cancelling again once no refresh is active is rejected with
    ActiveInstanceRefreshNotFound."""
    asg = ctx.client("autoscaling")
    group_name, _instance_id = _create_asg_with_instance(ctx, desired=1)

    start = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Preferences={"MinHealthyPercentage": 90, "InstanceWarmup": 120},
    )
    refresh_id = start["InstanceRefreshId"]

    def _probe_for(rid):
        def _inner():
            refreshes = asg.describe_instance_refreshes(
                AutoScalingGroupName=group_name, InstanceRefreshIds=[rid]
            )["InstanceRefreshes"]
            return refreshes[0]["Status"]

        return _inner

    _probe = _probe_for(refresh_id)
    _poll_until(_probe, lambda s: s in ("InProgress",), timeout_s=60.0, interval_s=3.0)

    cancel_resp = asg.cancel_instance_refresh(AutoScalingGroupName=group_name)
    assert cancel_resp["InstanceRefreshId"] == refresh_id, (
        f"expected cancel to return the active refresh id {refresh_id!r}, "
        f"got {cancel_resp['InstanceRefreshId']!r}"
    )

    final_status = _poll_until(
        _probe, lambda s: s == "Cancelled", timeout_s=180.0, interval_s=5.0
    )
    assert final_status == "Cancelled", f"expected Cancelled, got {final_status!r}"

    code, message = _error(lambda: asg.cancel_instance_refresh(AutoScalingGroupName=group_name))
    assert code == "ActiveInstanceRefreshNotFound", (
        f"expected ActiveInstanceRefreshNotFound, got {code}"
    )
    expected = (
        "No in progress, baking, pending, or cancelling Instance Refresh found for Auto Scaling "
        f"group {group_name}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Restore: with no active refresh, CancelInstanceRefresh's rejection above is a
    # property of the state, not of the group or the call shape. Start a new refresh
    # on the same group and prove the identical cancel call succeeds again.
    restore = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Preferences={"MinHealthyPercentage": 90, "InstanceWarmup": 120},
    )
    restore_id = restore["InstanceRefreshId"]
    _restore_probe = _probe_for(restore_id)
    _poll_until(_restore_probe, lambda s: s in ("InProgress",), timeout_s=60.0, interval_s=3.0)

    restore_cancel_resp = asg.cancel_instance_refresh(AutoScalingGroupName=group_name)
    assert restore_cancel_resp["InstanceRefreshId"] == restore_id, (
        f"expected restore cancel to return the new refresh id {restore_id!r}, "
        f"got {restore_cancel_resp['InstanceRefreshId']!r}"
    )
    restore_final_status = _poll_until(
        _restore_probe, lambda s: s == "Cancelled", timeout_s=180.0, interval_s=5.0
    )
    assert restore_final_status == "Cancelled", f"expected Cancelled, got {restore_final_status!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore ``(code, message)``. An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
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


# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the check's cleanup budget.
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


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-behav", "Value": "true"}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg_with_instance(ctx, desired=1, min_size=0, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    _vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ctx.client("ec2"))
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckType="EC2",
        HealthCheckGracePeriod=30,
        Tags=[{"Key": "sim2real-behav", "Value": "true", "PropagateAtLaunch": False}],
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_delete_group)

    def _probe():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ]
        return groups[0]["Instances"] if groups else []

    instances = _poll_until(
        _probe,
        lambda insts: len([i for i in insts if i["LifecycleState"] == "InService"]) >= desired,
        timeout_s=420.0,
        interval_s=10.0,
    )
    in_service = [i for i in instances if i["LifecycleState"] == "InService"]
    return group_name, (in_service[0]["InstanceId"] if in_service else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
