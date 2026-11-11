"""op-contract-createOrUpdateTags."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createOrUpdateTags"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOrUpdateTags creates/updates the exact tag round-tripped by
    DescribeTags; exceeding the per-resource tag limit (50) is rejected with
    LimitExceeded and leaves the existing tag set unmodified."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx)

    asg.create_or_update_tags(
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real-env",
                "Value": "test",
                "PropagateAtLaunch": True,
            }
        ]
    )
    tags = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(tags) == 1
    assert tags[0]["Key"] == "sim2real-env" and tags[0]["Value"] == "test"
    assert tags[0]["PropagateAtLaunch"] is True

    # --- error boundary: exceed the 50-tags-per-resource limit in one call ---
    excess_tags = [
        {
            "ResourceId": group_name,
            "ResourceType": "auto-scaling-group",
            "Key": f"sim2real-excess-{i}",
            "Value": "x",
            "PropagateAtLaunch": False,
        }
        for i in range(55)
    ]
    code, message = _error(lambda: asg.create_or_update_tags(Tags=excess_tags))
    assert code == "LimitExceeded", f"expected LimitExceeded, got {code}"
    assert message == "You tried to create more tags than allowed", (
        f"expected message 'You tried to create more tags than allowed', got {message!r}"
    )

    tags_after = asg.describe_tags(
        Filters=[{"Name": "auto-scaling-group", "Values": [group_name]}]
    )["Tags"]
    assert len(tags_after) == 1, "no excess tags should have been persisted"
    assert tags_after[0]["Key"] == "sim2real-env"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore ``(code, message)``. An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    _vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ctx.client("ec2"))
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=2,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )

    def _delete_group():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=group_name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_delete_group)
    return group_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
