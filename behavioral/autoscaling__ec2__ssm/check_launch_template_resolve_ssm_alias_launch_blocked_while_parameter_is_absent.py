"""launch-template-resolve-ssm-alias-launch-blocked-while-parameter-is-absent."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-template-resolve-ssm-alias-launch-blocked-while-parameter-is-absent"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "ssm"]

_INSTANCE_TYPE = "t3.micro"


def _poll(probe, predicate, *, timeout_s: float, interval_s: float = 5.0, description: str):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)


def _usable_subnet(ctx: Any) -> str:
    """A shared-network subnet whose AZ actually offers the instance type this check launches."""
    ec2 = ctx.client("ec2")
    net = ctx.network()
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    for az in net.availability_zones:
        if az in offered:
            return net.subnets[az]
    raise AssertionError(f"no shared-network AZ among {sorted(net.subnets)} offers {_INSTANCE_TYPE}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A launch template's resolve:ssm ImageId launches an instance carrying the parameter's
    current AMI, and a scale-out attempt made while the parameter is absent leaves the group's
    running instance count unchanged until the parameter exists again."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")

    subnet_id = _usable_subnet(ctx)
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    param_name = ctx.unique_name("sim2real-lthoame-param-")
    ssm.put_parameter(Name=param_name, Value=ami_id, Type="String", DataType="aws:ec2:image")
    ctx.on_cleanup(lambda: _delete_param_if_present(ssm, param_name))

    # A parameter this check just created can lag briefly before CreateLaunchTemplate's own
    # resolve:ssm validation sees it; retry that one bounded window, never the create itself.
    def _create_template():
        return ec2.create_launch_template(
            LaunchTemplateName=ctx.unique_name("sim2real-lthoame-lt-"),
            LaunchTemplateData={
                "ImageId": f"resolve:ssm:{param_name}",
                "InstanceType": _INSTANCE_TYPE,
            },
            TagSpecifications=[{"ResourceType": "launch-template",
                                 "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
        )["LaunchTemplate"]["LaunchTemplateId"]

    deadline = time.monotonic() + 30.0
    while True:
        try:
            lt_id = _create_template()
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "SsmInvalidParameter" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    group_name = ctx.unique_name("sim2real-lthoame-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=1, MaxSize=2, DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(
        AutoScalingGroupName=group_name, ForceDelete=True))

    def _group_instance_ids() -> list[str]:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
        return [i["InstanceId"] for i in groups[0]["Instances"]] if groups else []

    first_ids = _poll(
        _group_instance_ids, lambda ids: len(ids) == 1,
        timeout_s=180.0, description=f"group {group_name!r} launching its first instance",
    )

    # Positive control: the launched instance carries the AMI the parameter held at launch time,
    # not the literal alias string.
    launched = ec2.describe_instances(InstanceIds=first_ids)["Reservations"][0]["Instances"][0]
    assert launched["ImageId"] == ami_id, (
        f"the instance resolve:ssm launched carries ImageId {launched['ImageId']!r}, "
        f"expected the parameter's value {ami_id!r}"
    )

    # Break exactly one thing: the parameter the launch template's alias names disappears.
    ssm.delete_parameter(Name=param_name)

    def _activity_cause_for_second_instance() -> str | None:
        acts = autoscaling.describe_scaling_activities(
            AutoScalingGroupName=group_name)["Activities"]
        for act in acts:
            if act["StatusCode"] == "Failed" and param_name in act.get("StatusMessage", ""):
                return act["StatusMessage"]
        return None

    autoscaling.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=2)
    cause = _poll(
        _activity_cause_for_second_instance, lambda c: c is not None,
        timeout_s=240.0, interval_s=10.0,
        description=f"group {group_name!r} recording a failed launch naming {param_name!r}",
    )
    assert cause == (
        f"The following aliases are invalid: {param_name}. Launching EC2 instance failed."
    ), f"unexpected failed-launch cause: {cause!r}"

    # The effect is absent at the destination: no second instance ever actually ran.
    stuck_ids = _group_instance_ids()
    assert stuck_ids == first_ids, (
        f"a second instance appeared ({stuck_ids!r}) while the parameter was still absent"
    )

    # Restore the one thing that was broken; the identical scale-out demand now succeeds.
    ssm.put_parameter(Name=param_name, Value=ami_id, Type="String", DataType="aws:ec2:image")
    second_ids = _poll(
        _group_instance_ids, lambda ids: len(ids) == 2,
        timeout_s=240.0, description=f"group {group_name!r} launching its second instance after repair",
    )
    new_id = [i for i in second_ids if i not in first_ids]
    assert len(new_id) == 1, f"expected exactly one new instance id, got {second_ids!r}"
    repaired = ec2.describe_instances(InstanceIds=new_id)["Reservations"][0]["Instances"][0]
    assert repaired["ImageId"] == ami_id, (
        f"the repaired launch carries ImageId {repaired['ImageId']!r}, expected {ami_id!r}"
    )


def _delete_param_if_present(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
