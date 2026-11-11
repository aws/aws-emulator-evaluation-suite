"""instance-refresh-in-progress-conflict-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "instance-refresh-in-progress-conflict-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartInstanceRefresh while one is already active must be rejected, not queued/duplicated."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
        import time
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if pred(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _group_instances(name):
        g = _describe_group(name)
        return g.get("Instances", []) if g else []

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    _vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ec2)

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": subnet_id,
            "HealthCheckGracePeriod": 0,
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=2, desired_capacity=1)
    in_service = _wait_for_in_service(name, 1, timeout_s=420, interval_s=5)

    # Hold the refresh open: the only instance is scale-in protected and the refresh is told to
    # Wait for protected instances, so it stays active until this check cancels it.
    as_.set_instance_protection(
        AutoScalingGroupName=name,
        InstanceIds=[in_service[0]["InstanceId"]],
        ProtectedFromScaleIn=True,
    )
    first = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={
            "MinHealthyPercentage": 0,
            "InstanceWarmup": 0,
            "ScaleInProtectedInstances": "Wait",
        },
    )

    try:
        as_.start_instance_refresh(AutoScalingGroupName=name)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InstanceRefreshInProgress", f"expected InstanceRefreshInProgress, got {code}"
    expected = (
        "An Instance Refresh is already in progress and blocks the execution of this Instance "
        "Refresh."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Exactly one refresh must exist for the group.
    resp = as_.describe_instance_refreshes(AutoScalingGroupName=name)
    ids = {r["InstanceRefreshId"] for r in resp["InstanceRefreshes"]}
    assert ids == {first["InstanceRefreshId"]}, f"rejected refresh must not be recorded, saw {ids}"

    # Restore: cancel the active refresh and drive it to a terminal state.
    cancel_resp = as_.cancel_instance_refresh(AutoScalingGroupName=name)
    assert cancel_resp["InstanceRefreshId"] == first["InstanceRefreshId"], (
        f"cancel must target the active refresh {first['InstanceRefreshId']!r}, "
        f"got {cancel_resp['InstanceRefreshId']!r}"
    )

    def _refresh_status():
        r = as_.describe_instance_refreshes(
            AutoScalingGroupName=name, InstanceRefreshIds=[first["InstanceRefreshId"]]
        ).get("InstanceRefreshes", [])
        return r[0]["Status"] if r else None

    status = _poll_until(
        _refresh_status,
        lambda s: s == "Cancelled",
        timeout_s=180,
        interval_s=5,
        description="cancelled refresh reaching Cancelled",
    )
    assert status == "Cancelled", f"expected the cancelled refresh to settle at Cancelled, got {status}"

    # The identical call must now succeed once nothing is in progress.
    second = as_.start_instance_refresh(AutoScalingGroupName=name)
    second_id = second["InstanceRefreshId"]
    assert second_id != first["InstanceRefreshId"], "restored call must start a distinct refresh"

    resp = as_.describe_instance_refreshes(AutoScalingGroupName=name)
    ids_after_restore = {r["InstanceRefreshId"] for r in resp["InstanceRefreshes"]}
    assert second_id in ids_after_restore, f"restored refresh must be recorded, saw {ids_after_restore}"

    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=name)
    except Exception:
        pass


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
# shared by all of one check's network deletes and fits a 900 s cleanup budget.
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
