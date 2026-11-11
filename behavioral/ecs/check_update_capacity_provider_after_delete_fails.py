"""update-capacity-provider-after-delete-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-after-delete-fails"
GROUP = "concurrency"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider against a concurrently-deleted provider fails, doesn't apply stale updates."""

    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ssm = ctx.client("ssm")

    try:
        ami_param = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended")
        ami_id = json.loads(ami_param["Parameter"]["Value"])["image_id"]
    except (ClientError, KeyError, ValueError) as e:
        raise AssertionError(f"could not resolve an ECS-optimized AMI id via SSM: {e}")

    azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    if not azs:
        raise AssertionError("no availability zones available in this Region")
    az = azs[0]["ZoneName"]

    lt_name = ctx.unique_name("sim2real-ecs-cp-lt-")
    try:
        lt = ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
            TagSpecifications=[
                {
                    "ResourceType": "launch-template",
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                }
            ],
        )["LaunchTemplate"]
    except ClientError as e:
        raise AssertionError(f"CreateLaunchTemplate rejected: {_code(e)}")
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-ecs-cp-asg-")
    try:
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=[az],
            NewInstancesProtectedFromScaleIn=False,
            Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    except ClientError as e:
        raise AssertionError(f"CreateAutoScalingGroup rejected: {_code(e)}")
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    asg = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
    asg_arn = asg["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-ecs-cp-")
    try:
        ecs.create_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={
                "autoScalingGroupArn": asg_arn,
                "managedScaling": {"status": "DISABLED"},
                "managedTerminationProtection": "DISABLED",
            },
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    except ClientError as e:
        raise AssertionError(f"CreateCapacityProvider rejected: {_code(e)}")

    def _cleanup_cp():
        try:
            ecs.delete_capacity_provider(capacityProvider=cp_name)
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "ClusterNotFoundException"
                and not (err["Code"] == "ClientException" and "The specified capacity provider does not exist" in err.get("Message", ""))
            ):
                raise

    ctx.on_cleanup(_cleanup_cp)

    active = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["status"] == "ACTIVE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert active["status"] == "ACTIVE", f"expected ACTIVE after create, got {active['status']!r}"

    # --- positive control: updating an ACTIVE capacity provider succeeds. ---
    ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 100,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 1,
            }
        },
    )
    updated = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["autoScalingGroupProvider"]["managedScaling"]["status"] == "ENABLED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert updated["autoScalingGroupProvider"]["managedScaling"]["status"] == "ENABLED", (
        f"expected the positive-control update to take effect, got "
        f"{updated['autoScalingGroupProvider']['managedScaling']['status']!r}"
    )

    # --- delete the capacity provider, then race an update against it. ---
    ecs.delete_capacity_provider(capacityProvider=cp_name)
    deleted = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["status"] == "INACTIVE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert deleted["status"] == "INACTIVE", f"expected INACTIVE after delete, got {deleted['status']!r}"

    try:
        ecs.update_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={"managedScaling": {"status": "DISABLED"}},
        )
        raise AssertionError("UpdateCapacityProvider on a deleted (INACTIVE) capacity provider unexpectedly succeeded")
    except ClientError as e:
        error = (_code(e), e.response.get("Error", {}).get("Message"))
        expected = ("ClientException", "The capacity provider could not be updated because it has been deleted.")
        assert error == expected, (
            f"expected {expected!r} for a stale update on a deleted capacity provider, got {error!r}"
        )

    # The stale update must not have applied: still INACTIVE, managedScaling still reflects the
    # last successful (pre-delete) update, not the rejected post-delete attempt.
    recheck = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    assert recheck["status"] == "INACTIVE", f"expected INACTIVE to persist, got {recheck['status']!r}"
    assert recheck["autoScalingGroupProvider"]["managedScaling"]["status"] == "ENABLED", (
        "rejected post-delete update leaked into the capacity provider's managedScaling state"
    )


def _code(e: ClientError):
    return e.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
