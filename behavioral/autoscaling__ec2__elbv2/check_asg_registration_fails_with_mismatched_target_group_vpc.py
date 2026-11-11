"""asg-registration-fails-with-mismatched-target-group-vpc."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "asg-registration-fails-with-mismatched-target-group-vpc"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachLoadBalancerTargetGroups accepts a target group from another VPC, but the ASG never
    registers its instance there; a target group in the same VPC registers it."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _default_security_group(ctx, vpc_id)
    ami_id = _latest_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id, sg_id)
    tg_baseline_arn = _create_target_group(ctx, vpc_id, "base")

    asg_name = _create_asg(
        ctx, lt_name, subnet_ids, min_size=1, max_size=1, desired=1,
        target_group_arns=[tg_baseline_arn], health_check_type="EC2",
    )
    instance_id = _wait_for_inservice_instances(ctx, asg_name, count=1)[0]

    # --- Negative: attach a target group from a DIFFERENT VPC ---
    other_vpc_id, other_subnet_id = _create_isolated_vpc(ctx)
    tg_other_vpc_arn = _create_target_group(ctx, other_vpc_id, "othv")

    asg = ctx.client("autoscaling")
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_other_vpc_arn])

    elbv2 = ctx.client("elbv2")

    def _failed_vpc_activities() -> list[dict[str, Any]]:
        activities = asg.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]
        return [
            a for a in activities
            if a.get("StatusCode") == "Failed" and "vpc" in (a.get("StatusMessage") or a.get("Description") or "").lower()
        ]

    # Bounded retry, not a fixed sleep: wait for the ASG's own scaling-activity
    # log to record the VPC-mismatch failure it logs when it tries (and fails)
    # to register the instance into the newly-attached target group.
    failed_vpc_activity = _poll_until(
        _failed_vpc_activities, lambda failed: bool(failed), timeout_s=180.0, interval_s=15.0,
    )
    assert failed_vpc_activity, "expected a Failed scaling activity referencing VPC mismatch"

    other_vpc_targets = elbv2.describe_target_health(TargetGroupArn=tg_other_vpc_arn)["TargetHealthDescriptions"]
    assert instance_id not in [t["Target"]["Id"] for t in other_vpc_targets], (
        "instance was registered into a target group from a different VPC - should be impossible"
    )

    # --- Positive control: attach a target group from the SAME VPC ---
    tg_same_vpc_arn = _create_target_group(ctx, vpc_id, "same")
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_same_vpc_arn])
    same_vpc_ids = _poll_until(
        lambda: [t["Target"]["Id"] for t in elbv2.describe_target_health(TargetGroupArn=tg_same_vpc_arn)["TargetHealthDescriptions"]],
        lambda ids: instance_id in ids,
        timeout_s=180.0, interval_s=10.0,
    )
    assert instance_id in same_vpc_ids


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]


def _default_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch ASG instances into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    if not subnet_ids:
        raise AssertionError("shared network has no subnets to launch ASG instances into")
    return vpc_id, subnet_ids


def _default_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )
    return resp["SecurityGroups"][0]["GroupId"]


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, sg_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": _tag_spec("instance", name),
        },
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _tg_name(ctx, suffix: str = "") -> str:
    name = ctx.unique_name(f"sim2real-tg{suffix}-")
    return name[:32].rstrip("-")


def _create_target_group(
    ctx, vpc_id: str, suffix: str = "", port: int = 22, protocol: str = "TCP",
    health_check_port: int | None = None, interval: int = 10, healthy: int = 2, unhealthy: int = 2,
) -> str:
    elbv2 = ctx.client("elbv2")
    tg = elbv2.create_target_group(
        Name=_tg_name(ctx, suffix),
        Protocol=protocol,
        Port=port,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol=protocol,
        HealthCheckPort=str(health_check_port or port),
        HealthCheckIntervalSeconds=interval,
        HealthyThresholdCount=healthy,
        UnhealthyThresholdCount=unhealthy,
    )["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_ignore_missing(ctx, arn))
    return arn


def _delete_target_group_ignore_missing(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError
    elbv2 = ctx.client("elbv2")
    try:
        _delete_target_group_when_free(elbv2, arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _create_isolated_vpc(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=_tag_spec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.77.1.0/24", AvailabilityZone=az, TagSpecifications=_tag_spec("subnet", name),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _create_asg(
    ctx, lt_name: str, subnet_ids: list[str], min_size: int, max_size: int, desired: int,
    target_group_arns: list[str] | None = None, health_check_type: str = "EC2", grace_period: int = 60,
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asg-")
    params: dict[str, Any] = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=",".join(subnet_ids[:2]),
        HealthCheckType=health_check_type,
        HealthCheckGracePeriod=grace_period,
    )
    if target_group_arns:
        params["TargetGroupARNs"] = target_group_arns
    asg.create_auto_scaling_group(**params)
    ctx.on_cleanup(lambda: _delete_asg(ctx, name))
    return name


def _delete_asg(ctx, name: str) -> None:
    # One call and no wait: ForceDelete starts the asynchronous termination, and the cleanups
    # queued after this one share the same teardown deadline.
    asg = ctx.client("autoscaling")
    asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)


def _wait_for_inservice_instances(ctx, asg_name: str, count: int, timeout_s: float = 400.0, interval_s: float = 15.0) -> list[str]:
    asg = ctx.client("autoscaling")

    def probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]

    def pred(instances):
        return len([i for i in instances if i["LifecycleState"] == "InService"]) >= count

    instances = _poll_until(probe, pred, timeout_s, interval_s)
    return [i["InstanceId"] for i in instances if i["LifecycleState"] == "InService"]


# Network teardown: AWS-managed ENIs of resources deleted asynchronously block DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc with DependencyViolation, so it waits for them, retries inside one
# window shared by all of the check's network deletes, and raises naming the ENIs still attached.
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



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
