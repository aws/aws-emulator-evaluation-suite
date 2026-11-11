"""op-contract-describeInstanceRefreshes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceRefreshes"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceRefreshes reports the refresh through its status lifecycle to
    a terminal state; an invalid pagination token is rejected with InvalidNextToken."""
    asg = ctx.client("autoscaling")
    group_name, _instance_id = _create_asg_with_instance(ctx, desired=1)

    start = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Preferences={"MinHealthyPercentage": 100, "InstanceWarmup": 0},
    )
    refresh_id = start["InstanceRefreshId"]

    def _probe():
        refreshes = asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, InstanceRefreshIds=[refresh_id]
        )["InstanceRefreshes"]
        return refreshes[0]

    first = _probe()
    assert first["AutoScalingGroupName"] == group_name, (
        f"expected group {group_name!r}, got {first['AutoScalingGroupName']!r}"
    )
    assert first["InstanceRefreshId"] == refresh_id, (
        f"expected refresh id {refresh_id!r}, got {first['InstanceRefreshId']!r}"
    )
    assert first["Status"] in ("Pending", "InProgress", "Successful"), (
        f"unexpected initial status: {first['Status']!r}"
    )

    final = _poll_until(
        _probe,
        lambda r: r["Status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert final["Status"] == "Successful", f"unexpected terminal status: {final}"
    assert final["PercentageComplete"] == 100, (
        f"expected a Successful refresh to report 100% complete, got {final['PercentageComplete']!r}"
    )

    code, message = _error(
        lambda: asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, NextToken="sim2real-not-a-real-token"
        )
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = "The token 'sim2real-not-a-real-token' is invalid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return subnets[0]["SubnetId"], vpc_id

    # No ambient shared network (a freshly provisioned account may not have one) — create the
    # minimal network the ASG needs rather than depending on one existing.
    vpc_id = ec2.create_vpc(CidrBlock="10.211.0.0/24")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.211.0.0/24", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id, vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg_with_instance(ctx, desired=1, min_size=0, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: an asynchronous delete
# in this VPC leaves its ENIs behind briefly, so DeleteSubnet / DeleteVpc retries DependencyViolation
# within one shared window, then raises naming the ENIs still attached.
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
