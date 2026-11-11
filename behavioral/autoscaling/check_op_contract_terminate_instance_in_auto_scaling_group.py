"""op-contract-terminate-instance-in-auto-scaling-group."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-terminate-instance-in-auto-scaling-group"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateInstanceInAutoScalingGroup without decrement gets a replacement instance; with
    ShouldDecrementDesiredCapacity=True it is accepted above MinSize, rejected with ValidationError
    (instance left running) when it would drop below MinSize, and accepted once MinSize is lowered."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    _vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ctx.client("ec2"))
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-terminst-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=1, max_size=2, desired=1)

    instances = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    first_instance_id = instances[0]["InstanceId"]

    resp = autoscaling.terminate_instance_in_auto_scaling_group(
        InstanceId=first_instance_id, ShouldDecrementDesiredCapacity=False
    )
    activity = resp["Activity"]
    assert activity["StatusCode"] in ("InProgress", "PreInService", "Successful"), (
        f"expected an in-flight or successful activity, got {activity!r}"
    )
    assert first_instance_id in activity["Description"], (
        f"expected {first_instance_id} in the activity description, got {activity['Description']!r}"
    )
    assert "Terminating" in activity["Description"], (
        f"expected 'Terminating' in the activity description, got {activity['Description']!r}"
    )

    # DesiredCapacity is unchanged, and Amazon EC2 Auto Scaling launches a replacement instance
    # to converge back to 1 InService instance under a *different* instance ID.
    replacement_instances = _poll_until(
        lambda: [i for i in _group_instances(ctx, name) if i["LifecycleState"] == "InService"],
        lambda ins: len(ins) == 1 and ins[0]["InstanceId"] != first_instance_id,
        timeout_s=300.0,
        interval_s=10.0,
    )
    second_instance_id = replacement_instances[0]["InstanceId"]
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert group["DesiredCapacity"] == 1, f"expected DesiredCapacity 1, got {group['DesiredCapacity']}"
    assert group["MinSize"] == 1, f"expected MinSize 1, got {group['MinSize']}"

    # --- Positive control: ShouldDecrementDesiredCapacity=True must be ACCEPTED when it does not
    # cross MinSize. Give the group headroom above MinSize first, so the boundary case below is
    # not indistinguishable from "this account/target rejects every decrementing termination".
    autoscaling.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2, HonorCooldown=False)
    scaled_out = _poll_until(
        lambda: [i for i in _group_instances(ctx, name) if i["LifecycleState"] == "InService"],
        lambda ins: len(ins) == 2 and any(i["InstanceId"] == second_instance_id for i in ins),
        timeout_s=300.0,
        interval_s=10.0,
    )
    third_instance_id = next(i["InstanceId"] for i in scaled_out if i["InstanceId"] != second_instance_id)

    control_resp = autoscaling.terminate_instance_in_auto_scaling_group(
        InstanceId=third_instance_id, ShouldDecrementDesiredCapacity=True
    )
    control_activity = control_resp["Activity"]
    assert control_activity["StatusCode"] in ("InProgress", "PreInService", "Successful"), (
        f"positive control: decrementing from above MinSize must be accepted, got {control_activity!r}"
    )
    assert third_instance_id in control_activity["Description"], (
        f"expected {third_instance_id} in the activity description, got {control_activity['Description']!r}"
    )
    assert "Terminating" in control_activity["Description"], (
        f"expected 'Terminating' in the activity description, got {control_activity['Description']!r}"
    )

    at_boundary = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0],
        lambda g: g["DesiredCapacity"] == 1
        and [i["InstanceId"] for i in g["Instances"] if i["LifecycleState"] == "InService"] == [second_instance_id],
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert at_boundary["DesiredCapacity"] == 1, (
        f"positive control must land DesiredCapacity back at MinSize (1), got {at_boundary['DesiredCapacity']}"
    )

    # Error boundary: decrementing desired capacity here would take DesiredCapacity (1) below
    # MinSize (1), so the call is rejected and the remaining instance is left running.
    code, message = _error(
        lambda: autoscaling.terminate_instance_in_auto_scaling_group(
            InstanceId=second_instance_id, ShouldDecrementDesiredCapacity=True
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = (
        "Currently, desiredSize equals minSize (1). Terminating instance without replacement will "
        "violate group's min size constraint. Either set shouldDecrementDesiredCapacity flag to "
        "false or lower group's min size."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    final = _group_instances(ctx, name)
    surviving = next(i for i in final if i["InstanceId"] == second_instance_id)
    assert surviving["LifecycleState"] == "InService", (
        f"expected {second_instance_id} to remain InService after the rejected call, got {surviving['LifecycleState']!r}"
    )
    unchanged_group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert unchanged_group["DesiredCapacity"] == 1, (
        f"expected DesiredCapacity to remain 1 after the rejected call, got {unchanged_group['DesiredCapacity']}"
    )

    # --- Restore: lower MinSize so the identical call is no longer forbidden, and demand it now
    # succeeds. Without this leg the rejection above is indistinguishable from "this target never
    # allows a decrementing termination on this group at all".
    autoscaling.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0)
    restored_group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert restored_group["MinSize"] == 0, f"expected MinSize 0 after restore, got {restored_group['MinSize']}"

    restored_resp = autoscaling.terminate_instance_in_auto_scaling_group(
        InstanceId=second_instance_id, ShouldDecrementDesiredCapacity=True
    )
    restored_activity = restored_resp["Activity"]
    assert restored_activity["StatusCode"] in ("InProgress", "PreInService", "Successful"), (
        f"the identical call must now succeed once MinSize no longer forbids it, got {restored_activity!r}"
    )
    assert second_instance_id in restored_activity["Description"], (
        f"expected {second_instance_id} in the activity description, got {restored_activity['Description']!r}"
    )
    assert "Terminating" in restored_activity["Description"], (
        f"expected 'Terminating' in the activity description, got {restored_activity['Description']!r}"
    )

    drained = _poll_until(
        lambda: autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0],
        lambda g: g["DesiredCapacity"] == 0
        and not [i for i in g["Instances"] if i["LifecycleState"] == "InService"],
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert drained["DesiredCapacity"] == 0, f"expected DesiredCapacity 0 once drained, got {drained['DesiredCapacity']}"
    assert not [i for i in drained["Instances"] if i["LifecycleState"] == "InService"], (
        f"expected no InService instances once drained, got {drained['Instances']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore ``(code, message)``. An unexpected SUCCESS raises: accepting
    input real AWS refuses is a failure in its own right, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _own_vpc_and_subnet(ctx, ec2, instance_type="t3.micro", cidr="10.81.0.0/16",
                        subnet_cidr="10.81.1.0/24"):
    """A VPC and one subnet this check creates, in an available AZ that offers
    ``instance_type``. Each create registers its cleanup immediately."""
    tag = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ offers {instance_type!r}"
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=zones[0],
                                  TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}]
                                  )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


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


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


def _group_instances(ctx, name: str) -> list[dict[str, Any]]:
    autoscaling = ctx.client("autoscaling")
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
