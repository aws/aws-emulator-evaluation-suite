"""launch-instances-idempotency-token-dedup."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "launch-instances-idempotency-token-dedup"
GROUP = "ordering"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeating LaunchInstances with the same ClientToken dedups the launch; reusing the
    token with different params yields IdempotentParameterMismatch and does not disturb the
    original result, which remains replayable with its original params afterward."""

    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    if not hasattr(asg, "launch_instances"):
        raise AssertionError("installed boto3 autoscaling client lacks launch_instances API")

    subnet_id = _get_default_subnet(ctx)
    lt_name = _create_launch_template(ctx)
    group_name = _create_asg_with_template(ctx, lt_name, subnet_id, min_size=0, max_size=5, desired=0)

    token = ctx.unique_name("sim2real-tok-")

    resp1 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet_id],
        RetryStrategy="none",
    )
    assert not resp1.get("Errors"), f"unexpected launch errors: {resp1.get('Errors')}"
    instances1 = resp1["Instances"]
    assert len(instances1) == 1 and len(instances1[0]["InstanceIds"]) == 1
    instance_id = instances1[0]["InstanceIds"][0]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    # Independent read: the group really tracks the launch, not just the mutating
    # call's own echoed response.
    tracked = _group_instance_ids(asg, group_name)
    assert tracked == [instance_id], f"expected group to track exactly [{instance_id}], found {tracked}"

    # Replaying with the identical ClientToken + identical params must return the SAME
    # cached result (no second instance launched).
    resp2 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet_id],
        RetryStrategy="none",
    )
    instances2 = resp2["Instances"]
    assert len(instances2) == 1 and instances2[0]["InstanceIds"] == [instance_id], (
        f"idempotent replay launched a different/new instance: {instances2}"
    )
    tracked = _group_instance_ids(asg, group_name)
    assert tracked == [instance_id], (
        f"idempotent replay must not add a second tracked instance, found {tracked}"
    )

    # Reusing the same token with DIFFERENT params must be rejected.
    code, message = _error(
        lambda: asg.launch_instances(
            AutoScalingGroupName=group_name,
            RequestedCapacity=2,
            ClientToken=token,
            SubnetIds=[subnet_id],
            RetryStrategy="none",
        )
    )
    assert code == "IdempotentParameterMismatch", f"expected IdempotentParameterMismatch, got {code}"
    expected_message = "Different request parameters found in the last request used with the provided token name"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected mismatched call must not have launched an extra instance.
    tracked = _group_instance_ids(asg, group_name)
    assert tracked == [instance_id], (
        f"rejected mismatched-token retry must not change tracked instances, found {tracked}"
    )

    # The token is not poisoned by the rejected mismatch: replaying with the ORIGINAL
    # params still succeeds and returns the identical cached result (positive control).
    resp3 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet_id],
        RetryStrategy="none",
    )
    instances3 = resp3["Instances"]
    assert len(instances3) == 1 and instances3[0]["InstanceIds"] == [instance_id], (
        f"replaying the original params after a rejected mismatch must still return the "
        f"cached instance, got {instances3}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected IdempotentParameterMismatch, but the call SUCCEEDED: {result!r}")


def _group_instance_ids(asg, group_name: str) -> list[str]:
    resp = asg.describe_auto_scaling_instances(MaxRecords=50)
    return sorted(
        i["InstanceId"] for i in resp["AutoScalingInstances"] if i["AutoScalingGroupName"] == group_name
    )


def _get_launch_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
    return resp["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        # No shared network in this account: fall back to any available subnet rather than
        # failing with an environment-shaped IndexError/AssertionError.
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ami = _get_launch_ami(ctx)
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_asg_with_template(
    ctx, lt_name: str, subnet_id: str, min_size: int, max_size: int, desired: int, **extra: Any
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asg-")
    params = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    params.update(extra)
    asg.create_auto_scaling_group(**params)
    ctx.on_cleanup(lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
