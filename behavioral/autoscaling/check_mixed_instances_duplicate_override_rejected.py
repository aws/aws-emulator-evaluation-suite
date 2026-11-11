"""mixed-instances-duplicate-override-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "mixed-instances-duplicate-override-rejected"
GROUP = "mixed-instances"
SERVICES = ["autoscaling"]


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "cap:c5",
    "plane:control",
)
def run(ctx) -> None:
    """A mixed-instances policy naming the same instance type twice is rejected and leaves the group
    on its plain launch template; distinct overrides are accepted and kept in the order sent
    (reversed reads back reversed), as the order is the prioritized on-demand launch order.
    """
    asg = ctx.client("autoscaling")
    name = _empty_group(ctx)
    lt = _group(ctx, name)["LaunchTemplate"]["LaunchTemplateName"]

    def policy(types):
        return {"LaunchTemplate": {
            "LaunchTemplateSpecification": {"LaunchTemplateName": lt, "Version": "$Latest"},
            "Overrides": [{"InstanceType": t} for t in types]}}

    code, msg = _error_code(lambda: asg.update_auto_scaling_group(
        AutoScalingGroupName=name, MixedInstancesPolicy=policy(["t3.micro", "t3.micro"])))
    assert code == "ValidationError", f"a duplicate override returned {code!r}: {msg!r}"
    expected_message = (
        "Cannot add same instance type override more than once. "
        "Remove these duplicates from the request and try again: [t3.micro]"
    )
    assert msg == expected_message, (
        f"expected message {expected_message!r}, got {msg!r}"
    )
    group = _group(ctx, name)
    assert "MixedInstancesPolicy" not in group, (
        f"a rejected update still installed a policy: {group.get('MixedInstancesPolicy')!r}"
    )
    assert group["LaunchTemplate"]["LaunchTemplateName"] == lt, (
        f"a rejected update changed the launch template: {group.get('LaunchTemplate')!r}"
    )

    # Positive control: distinct overrides are accepted, in order -- and the reverse, reversed.
    for types in (["t3.micro", "t3a.micro"], ["t3a.micro", "t3.micro"]):
        asg.update_auto_scaling_group(AutoScalingGroupName=name, MixedInstancesPolicy=policy(types))
        got = [o["InstanceType"] for o in
               _group(ctx, name)["MixedInstancesPolicy"]["LaunchTemplate"]["Overrides"]]
        assert got == types, f"overrides were sent as {types!r} but read back as {got!r}"


_TAGS = [{"Key": "sim2real", "Value": "autoscaling-refresh-prefs"}]


def _swallow(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


def _error_code(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; raises if fn succeeds instead."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        if not err:
            raise
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the request was ACCEPTED; real AWS rejects it with ValidationError")


def _poll(fn, pred, *, timeout_s, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _refreshes(ctx, name: str) -> list[dict]:
    asg = ctx.client("autoscaling")
    out, token = [], None
    while True:
        kw = {"AutoScalingGroupName": name}
        if token:
            kw["NextToken"] = token
        page = asg.describe_instance_refreshes(**kw)
        out += page["InstanceRefreshes"]
        token = page.get("NextToken")
        if not token:
            return out


def _empty_group(ctx) -> str:
    """A zero-capacity ASG in a VPC this check owns (no default VPC), on a launch template."""
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    base = ctx.unique_name("sim2real-behav-asrp-")
    vpc = ec2.create_vpc(CidrBlock="10.61.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _TAGS + [{"Key": "Name", "Value": base}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc))
    offered = None
    for t in ("t3.micro", "t3a.micro"):
        locs = {o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [t]}])["InstanceTypeOfferings"]}
        offered = locs if offered is None else offered & locs
    az = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert az, f"no available AZ offers both t3.micro and t3a.micro: {sorted(offered)!r}"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.61.1.0/24", AvailabilityZone=az[0],
                               TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}]
                               )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet))
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    lt = f"{base}-lt"
    ec2.create_launch_template(
        LaunchTemplateName=lt,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "TagSpecifications": [
            {"ResourceType": "instance", "Tags": _TAGS}]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _TAGS}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt))
    name = f"{base}-asg"
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet,
        LaunchTemplate={"LaunchTemplateName": lt, "Version": "$Latest"},
        Tags=[{"Key": "sim2real", "Value": "autoscaling-refresh-prefs",
               "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_group(ctx, name))
    return name


def _delete_group(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    _poll(lambda: asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
        "AutoScalingGroups"], lambda g: not g, timeout_s=300, interval_s=5,
        description=f"{name} deleted")


def _group(ctx, name: str) -> dict:
    groups = ctx.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[name])["AutoScalingGroups"]
    assert groups, f"group {name!r} does not exist"
    return groups[0]


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
