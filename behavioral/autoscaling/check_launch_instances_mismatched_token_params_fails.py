"""launch-instances-mismatched-token-params-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "launch-instances-mismatched-token-params-fails"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LaunchInstances reusing a ClientToken with a different RequestedCapacity is rejected with
    IdempotentParameterMismatch and launches nothing; the original parameters still succeed."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet = _default_subnet(ctx)
    lt_name = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-asg-")

    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        MinSize=0,
        MaxSize=10,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=subnet["subnet_id"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: _delete_group(ctx, group_name))

    token = ctx.unique_name("tok-")
    resp1 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet["subnet_id"]],
    )
    assert resp1["Errors"] == []
    ids1 = sorted(iid for e in resp1["Instances"] for iid in e["InstanceIds"])
    assert len(ids1) == 1
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=ids1))

    code, message = _error(
        lambda: asg.launch_instances(
            AutoScalingGroupName=group_name,
            RequestedCapacity=2,  # mismatched: same token, different capacity
            ClientToken=token,
            SubnetIds=[subnet["subnet_id"]],
        )
    )
    assert code == "IdempotentParameterMismatch", (
        f"expected IdempotentParameterMismatch, got {code}"
    )
    expected_message = (
        "Different request parameters found in the last request used with the provided token name"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected mismatched call must not have launched a second instance.
    group_instances = [
        i
        for page in asg.get_paginator("describe_auto_scaling_instances").paginate(
            PaginationConfig={"PageSize": 50}
        )
        for i in page["AutoScalingInstances"]
        if i["AutoScalingGroupName"] == group_name
    ]
    assert len(group_instances) == 1, (
        f"mismatched-token retry must not launch extra instances, found "
        f"{[i['InstanceId'] for i in group_instances]}"
    )

    # Positive control: replaying the SAME token with the ORIGINAL params
    # still succeeds and returns the cached (identical) result.
    resp3 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet["subnet_id"]],
    )
    ids3 = sorted(iid for e in resp3["Instances"] for iid in e["InstanceIds"])
    assert ids3 == ids1, "matching replay must return the original cached instances"

    # Independent read at the destination: the matching-token replay must not
    # have launched a second instance either -- the group still tracks
    # exactly the original instance, not the response body's say-so alone.
    final_instances = [
        i
        for page in asg.get_paginator("describe_auto_scaling_instances").paginate(
            PaginationConfig={"PageSize": 50}
        )
        for i in page["AutoScalingInstances"]
        if i["AutoScalingGroupName"] == group_name
    ]
    assert [i["InstanceId"] for i in final_instances] == ids1, (
        f"idempotent replay must not change the group's tracked instances, "
        f"expected {ids1}, found {[i['InstanceId'] for i in final_instances]}"
    )




def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises,
    so accepting what AWS refuses is not reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected IdempotentParameterMismatch, but the call SUCCEEDED: {result!r}")


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    subnet = subnets[0]
    return {"subnet_id": subnet["SubnetId"], "az": subnet["AvailabilityZone"]}


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_group(ctx, group_name: str) -> None:
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    try:
        asg.delete_auto_scaling_group(
            AutoScalingGroupName=group_name, ForceDelete=True
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    _poll_until(
        lambda: len(
            asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[group_name]
            )["AutoScalingGroups"]
        ),
        lambda n: n == 0,
        timeout_s=90.0,
        interval_s=3.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
