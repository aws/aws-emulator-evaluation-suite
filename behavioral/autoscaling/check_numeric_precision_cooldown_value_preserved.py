"""numeric-precision-cooldown-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "numeric-precision-cooldown-value-preserved"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large integer Cooldown set on a scaling policy is returned by
    DescribePolicies as the exact same integer -- no float coercion, no truncation."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    subnet_id, sg_id = _own_vpc_subnet(ctx, ec2)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    large_cooldown = 999999
    policy_name = ctx.unique_name("sim2real-policy-")
    autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name, PolicyName=policy_name,
        PolicyType="SimpleScaling", AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1, Cooldown=large_cooldown,
    )
    ctx.on_cleanup(lambda: autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name))

    policy = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name, PolicyNames=[policy_name]
    )["ScalingPolicies"][0]
    assert policy["Cooldown"] == large_cooldown, (
        f"expected Cooldown == {large_cooldown}, got {policy['Cooldown']!r}"
    )
    assert isinstance(policy["Cooldown"], int), (
        f"expected Cooldown to be an int (no float coercion), got "
        f"{type(policy['Cooldown']).__name__}: {policy['Cooldown']!r}"
    )


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _own_vpc_subnet(ctx, ec2):
    """Own VPC + subnet rather than an ambient default VPC, which a freshly
    provisioned account may not have."""
    tag = ctx.unique_name("sim2real-cooldown-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.231.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.231.0.0/25", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_id, sg_id


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that would leak the
# VPC while the check passes. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
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
