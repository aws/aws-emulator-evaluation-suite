"""launch-configuration-delete-removes-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "launch-configuration-delete-removes-config"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration is rejected with UnsupportedOperation naming launch templates, and
    an independent read shows nothing was created, while a launch-template-backed Auto Scaling
    group in the same account succeeds (positive control)."""
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    lc_name = ctx.unique_name("sim2real-lc-")
    ami_id = _latest_al2023_ami(ctx)

    from botocore.exceptions import ClientError

    # Positive control: a launch-template-backed ASG, in a VPC/subnet this check
    # provisions itself, can be created and is visible — the account and the
    # autoscaling/ec2 write path are healthy.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.123.0.0/24",
        TagSpecifications=[_ec2_tag_spec("vpc")],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    zone = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}],
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.123.0.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[_ec2_tag_spec("subnet")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[_ec2_tag_spec("launch-template")],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=_asg_tags(asg_name),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    control = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    assert len(control) == 1, (
        f"positive control failed: launch-template-backed ASG {asg_name} not "
        f"visible, got {control}"
    )

    # The withdrawal itself: CreateLaunchConfiguration is rejected with the specific,
    # deterministic code AWS uses for this retirement, not a generic denial.
    try:
        autoscaling.create_launch_configuration(
            LaunchConfigurationName=lc_name,
            ImageId=ami_id,
            InstanceType="t3.micro",
        )
        raise AssertionError(
            "expected CreateLaunchConfiguration to be rejected with "
            "UnsupportedOperation in this account, but it succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        assert code == "UnsupportedOperation", (
            f"expected UnsupportedOperation, got {code!r} (message={message!r})"
        )
        expected = (
            "The Launch Configuration creation operation is not available in your account. "
            "Use launch templates to create configuration templates for your Auto Scaling groups."
        )
        assert message == expected, (
            f"expected the rejection message {expected!r}, got {message!r}"
        )

    # Effect-absent: the rejected launch configuration was never created.
    described = autoscaling.describe_launch_configurations(
        LaunchConfigurationNames=[lc_name]
    )["LaunchConfigurations"]
    assert described == [], (
        f"expected no launch configuration named {lc_name} after the rejected "
        f"create, got {described}"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:check": CHECK}


def _ec2_tag_spec(resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    }


def _asg_tags(asg_name: str) -> list[dict]:
    return [
        {
            "ResourceId": asg_name,
            "ResourceType": "auto-scaling-group",
            "Key": k,
            "Value": v,
            "PropagateAtLaunch": False,
        }
        for k, v in _MANAGED_TAGS.items()
    ]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


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
