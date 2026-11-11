"""notification-configuration-empty-vs-absent-topic-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "notification-configuration-empty-vs-absent-topic-preserved"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A group that never had PutNotificationConfiguration called returns an empty
    DescribeNotificationConfigurations list (absent), which is distinct from -- and
    not confused with -- a sibling group that was explicitly configured."""
    autoscaling = ctx.client("autoscaling")
    sns = ctx.client("sns")

    ec2 = ctx.client("ec2")
    _vpc_id, subnet_ids, sg_id = _own_vpc_subnet(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    unconfigured_name = ctx.unique_name("sim2real-asg-plain-")
    configured_name = ctx.unique_name("sim2real-asg-notif-")
    for name in (unconfigured_name, configured_name):
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0, MaxSize=0, DesiredCapacity=0,
            VPCZoneIdentifier=subnet_ids[0],
            Tags=[{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": False}],
        )
        ctx.on_cleanup(lambda n=name: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True))

    # never configured -> absent
    before = autoscaling.describe_notification_configurations(
        AutoScalingGroupNames=[unconfigured_name]
    )["NotificationConfigurations"]
    assert before == [], f"expected no notification configuration before any Put, saw {before!r}"

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    autoscaling.put_notification_configuration(
        AutoScalingGroupName=configured_name, TopicARN=topic_arn,
        NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
    )

    after_unconfigured = autoscaling.describe_notification_configurations(
        AutoScalingGroupNames=[unconfigured_name]
    )["NotificationConfigurations"]
    assert after_unconfigured == [], "configuring a sibling group must not leak a config onto this one"

    after_configured = autoscaling.describe_notification_configurations(
        AutoScalingGroupNames=[configured_name]
    )["NotificationConfigurations"]
    assert len(after_configured) == 1, (
        f"expected exactly 1 notification configuration for {configured_name}, saw {after_configured!r}"
    )
    assert after_configured[0]["TopicARN"] == topic_arn, (
        f"expected TopicARN {topic_arn!r}, got {after_configured[0]['TopicARN']!r}"
    )
    assert after_configured[0]["NotificationType"] == "autoscaling:TEST_NOTIFICATION", (
        f"expected NotificationType autoscaling:TEST_NOTIFICATION, got {after_configured[0]['NotificationType']!r}"
    )


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _own_vpc_subnet(ctx):
    """Adopt an existing VPC subnet, else create a minimal one (an account may have no default VPC).
    The groups never launch instances, so the subnet needs no route."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if not subnets:
            continue
        sg = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"][0]["GroupId"]
        return vpc_id, [s["SubnetId"] for s in subnets], sg

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.201.0.0/28",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [subnet_id], sg


# Resources in this VPC delete asynchronously and leave ENIs behind, so a network delete
# waits (bounded) for them and retries DependencyViolation instead of leaking the VPC.
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
