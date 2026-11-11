"""asg-scale-up-blocked-after-target-group-deleted."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "asg-scale-up-blocked-after-target-group-deleted"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A scale-out works while the attached target group exists; after it is deleted out-of-band the
    next scale-out fails ("target group not found") and launches nothing; swapping in a fresh target
    group lifts the block and the new instance registers there."""
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)
    sg_id = _default_security_group(ctx, vpc_id)
    ami_id = _latest_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id, sg_id)
    tg_arn = _create_target_group(ctx, vpc_id, "dead")

    asg_name = _create_asg(
        ctx, lt_name, subnet_ids, min_size=1, max_size=3, desired=1,
        target_group_arns=[tg_arn], health_check_type="EC2",
    )
    _wait_for_inservice_instances(ctx, asg_name, count=1)

    asg = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    scale_out_start = time.monotonic()
    asg.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=2, HonorCooldown=False)
    inservice_ids = _wait_for_inservice_instances(ctx, asg_name, count=2)
    positive_scale_out_s = time.monotonic() - scale_out_start
    assert len(inservice_ids) == 2, f"expected 2 in-service instances after the control scale-out, got {len(inservice_ids)}"
    tg_ids = _poll_until(
        lambda: [t["Target"]["Id"] for t in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]],
        lambda ids: all(i in ids for i in inservice_ids),
        timeout_s=180.0, interval_s=10.0,
    )
    assert all(i in tg_ids for i in inservice_ids), f"expected {inservice_ids} registered in target group {tg_arn}, got {tg_ids}"

    elbv2.delete_target_group(TargetGroupArn=tg_arn)

    asg.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=3, HonorCooldown=False)

    failed_activity = _poll_until(
        lambda: [
            a for a in asg.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]
            if a.get("StatusCode") == "Failed"
            and "target group" in (a.get("StatusMessage") or a.get("Description") or "").lower()
        ],
        lambda acts: len(acts) > 0,
        timeout_s=240.0, interval_s=15.0,
    )
    assert failed_activity, "expected a Failed scaling activity naming the deleted target group, got none"

    # A launch still in flight when the Failed activity appeared must not complete later; the watch
    # window scales with the control scale-out's own latency.
    stall_window_s = max(15.0, min(3.0 * positive_scale_out_s, 240.0))
    stall_deadline = time.monotonic() + stall_window_s
    stall_interval_s = min(15.0, stall_window_s / 4)  # several reads even at the floor
    while time.monotonic() < stall_deadline:
        instances_now = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]
        assert len(instances_now) == 2, f"expected scale-out to 3 to stay blocked at 2 instances, but group has {len(instances_now)}"
        time.sleep(stall_interval_s)

    # Launch validation checks every attached target group, so the deleted one must be detached too;
    # attaching a fresh one alone keeps failing with "One or more target groups not found".
    tg2_arn = _create_target_group(ctx, vpc_id, "restore")
    asg.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg2_arn])
    asg.detach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_arn])
    asg.set_desired_capacity(AutoScalingGroupName=asg_name, DesiredCapacity=3, HonorCooldown=False)

    def _restore_probe():
        instances = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]
        recent_failed = [
            {"StatusCode": a.get("StatusCode"), "Detail": a.get("StatusMessage") or a.get("Description")}
            for a in asg.describe_scaling_activities(AutoScalingGroupName=asg_name)["Activities"]
            if a.get("StatusCode") == "Failed"
        ][:5]
        return {"instances": instances, "recent_failed_activities": recent_failed}

    restored = _poll_until(
        _restore_probe,
        lambda obs: len([i for i in obs["instances"] if i["LifecycleState"] == "InService"]) >= 3,
        timeout_s=600.0, interval_s=15.0,
    )
    inservice_ids_after_restore = [i["InstanceId"] for i in restored["instances"] if i["LifecycleState"] == "InService"]
    assert len(inservice_ids_after_restore) == 3, (
        f"expected desired capacity to be met once a target group was restored, got {len(inservice_ids_after_restore)}"
    )
    new_instance_ids = [i for i in inservice_ids_after_restore if i not in inservice_ids]
    assert new_instance_ids, f"expected at least one freshly launched instance, got {inservice_ids_after_restore}"
    third_instance_id = new_instance_ids[0]
    tg2_ids = _poll_until(
        lambda: [t["Target"]["Id"] for t in elbv2.describe_target_health(TargetGroupArn=tg2_arn)["TargetHealthDescriptions"]],
        lambda ids: third_instance_id in ids,
        timeout_s=180.0, interval_s=10.0,
    )
    assert third_instance_id in tg2_ids, f"expected restored instance {third_instance_id} registered in {tg2_arn}, got {tg2_ids}"


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
    """Force-delete the group and wait until it is gone. A missing group is already gone; a
    scaling activity in progress or an in-use refusal is retried every 2 s; anything else raises."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + 400.0
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            break
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            if err["Code"] not in ("ScalingActivityInProgress", "ResourceInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
        if not resp:
            return
        time.sleep(2.0)
    raise RuntimeError(f"Auto Scaling group {name} still listed 400 s after its delete")


def _wait_for_inservice_instances(ctx, asg_name: str, count: int, timeout_s: float = 400.0, interval_s: float = 15.0) -> list[str]:
    asg = ctx.client("autoscaling")

    def probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["Instances"]

    def pred(instances):
        return len([i for i in instances if i["LifecycleState"] == "InService"]) >= count

    instances = _poll_until(probe, pred, timeout_s, interval_s)
    return [i["InstanceId"] for i in instances if i["LifecycleState"] == "InService"]


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it
    (ResourceInUse)."""
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
