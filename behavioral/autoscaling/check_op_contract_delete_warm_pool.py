"""op-contract-deleteWarmPool."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteWarmPool"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWarmPool removes a configured warm pool (DescribeWarmPool no longer
    returns a WarmPoolConfiguration); calling it again once already deleted is
    rejected with ValidationError, not treated as idempotent."""
    asg = ctx.client("autoscaling")
    group_name = _create_empty_asg(ctx, max_size=2)

    asg.put_warm_pool(AutoScalingGroupName=group_name, MaxGroupPreparedCapacity=1)

    def _probe():
        return asg.describe_warm_pool(AutoScalingGroupName=group_name)

    _poll_until(
        _probe, lambda r: r.get("WarmPoolConfiguration") is not None, timeout_s=60.0, interval_s=3.0
    )

    delete_resp = asg.delete_warm_pool(AutoScalingGroupName=group_name)
    status = delete_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected DeleteWarmPool to return HTTP 200, got {status}"

    gone = _poll_until(
        _probe, lambda r: r.get("WarmPoolConfiguration") is None, timeout_s=180.0, interval_s=5.0
    )
    assert gone.get("WarmPoolConfiguration") is None, (
        f"expected WarmPoolConfiguration to be absent after delete, got {gone.get('WarmPoolConfiguration')!r}"
    )
    assert gone["Instances"] == [], f"expected no warm pool instances after delete, got {gone['Instances']!r}"

    # --- boundary: deleting an already-absent warm pool is rejected with ValidationError ---
    code, message = _error(lambda: asg.delete_warm_pool(AutoScalingGroupName=group_name))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"No warm pool found for Auto Scaling group '{group_name}'."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still_gone = asg.describe_warm_pool(AutoScalingGroupName=group_name)
    assert still_gone.get("WarmPoolConfiguration") is None, (
        f"expected WarmPoolConfiguration to remain absent, got {still_gone.get('WarmPoolConfiguration')!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# ===== helpers =====
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

    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in shared network")
    return subnets[0]["SubnetId"], vpc_id


def _create_launch_template(ctx, ami_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_empty_asg(ctx, max_size=2):
    asg = ctx.client("autoscaling")
    ami_id = _latest_al2023_ami(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=max_size,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
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
