"""deep-autoscaling-1-asg-recon-max-healthy-without-min-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deep-autoscaling-1-asg-recon-max-healthy-without-min-rejected"
GROUP = "instance-maintenance-policy-validation"
SERVICES = ["autoscaling"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
LIVE_STATES = {"pending", "running"}

# Returned for every rejection below (UpdateAutoScalingGroup, CreateAutoScalingGroup and
# StartInstanceRefresh alike). The model declares no fault for it.
EXPECTED_CODE = "ValidationError"
_PAIR = ("MinHealthyPercentage", "MaxHealthyPercentage")


def _poll(fn, pred, *, timeout_s, interval_s=5, description="condition"):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _usable_az(ec2):
    """An available AZ that offers INSTANCE_TYPE -- never AWS's arbitrary pick, never a literal."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _tagspec(rtype, tag):
    return [{"ResourceType": rtype, "Tags": [{"Key": "sim2real", "Value": tag}]}]


def _group_instance_ids_at_ec2(ec2, asg_name):
    """{instance_id: state} for every instance EC2 attributes to this group, any state."""
    out = {}
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]}]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                out[inst["InstanceId"]] = inst["State"]["Name"]
    return out


def _provision_group(ctx, as_, ec2, ssm, *, desired, min_size, max_size, tag, **asg_kwargs):
    """Own VPC + subnet + launch template + group; every create is paired with its cleanup
    immediately. Returns (group name, teardown). Teardown (LIFO): group, launch template,
    subnet, VPC."""
    vpc_id = ec2.create_vpc(CidrBlock="10.80.0.0/16",
                            TagSpecifications=_tagspec("vpc", tag))["Vpc"]["VpcId"]

    def _delete_vpc():
        for _ in range(3):
            try:
                _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "DependencyViolation":
                    raise
                time.sleep(3)
        raise RuntimeError(f"vpc {vpc_id} still has dependencies after teardown")
    ctx.on_cleanup(_delete_vpc)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.80.1.0/24",
                                  AvailabilityZone=_usable_az(ec2),
                                  TagSpecifications=_tagspec("subnet", tag))["Subnet"]["SubnetId"]

    def _delete_subnet():
        for _ in range(6):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "DependencyViolation":
                    raise
                time.sleep(3)
        raise RuntimeError(f"subnet {subnet_id} still has dependencies after teardown")
    ctx.on_cleanup(_delete_subnet)

    image_id = ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
    lt_name = ctx.unique_name("sim2real-asgr-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": image_id,
            "InstanceType": INSTANCE_TYPE,
            "TagSpecifications": _tagspec("instance", tag) + _tagspec("volume", tag),
        },
        TagSpecifications=_tagspec("launch-template", tag),
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asgr-grp-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size, MaxSize=max_size, DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": tag, "PropagateAtLaunch": True}],
        **asg_kwargs,
    )

    def _teardown(wait_s):
        """Force-delete the group, then wait up to ``wait_s`` for EC2 to report every member
        terminated. Returns True once converged. Idempotent."""
        try:
            as_.cancel_instance_refresh(AutoScalingGroupName=asg_name)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ActiveInstanceRefreshNotFound" and "not found" not in err.get("Message", ""):
                raise
        try:
            as_.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise
        deadline = time.monotonic() + wait_s
        while True:
            gone = not as_.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
            states = _group_instance_ids_at_ec2(ec2, asg_name)
            if gone and all(s == "terminated" for s in states.values()):
                return True
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"group {asg_name} / members not gone after {wait_s}s: {states!r}"
                )
            time.sleep(5)
    # The engine bounds the WHOLE cleanup chain at 60 s, and instance termination takes longer,
    # so the safety net only waits briefly; the pass path tears down inside run() instead (below).
    ctx.on_cleanup(lambda: _teardown(30))
    return asg_name, _teardown


def _asg_instances(as_, asg_name):
    """DescribeAutoScalingInstances, paginated, narrowed to this group."""
    out = []
    for page in as_.get_paginator("describe_auto_scaling_instances").paginate():
        out.extend(i for i in page["AutoScalingInstances"] if i["AutoScalingGroupName"] == asg_name)
    return out


def _refresh(as_, asg_name, refresh_id):
    r = as_.describe_instance_refreshes(AutoScalingGroupName=asg_name,
                                        InstanceRefreshIds=[refresh_id])["InstanceRefreshes"]
    assert len(r) == 1, f"refresh {refresh_id} not describable: {r!r}"
    return r[0]


def _both_message(qualifier):
    """The paired-field refusal; AWS may name the two fields in either order, so both orders are accepted."""
    return tuple(f"Both {a} and {b} must be specified{qualifier} or not at all."
                 for a, b in (_PAIR, _PAIR[::-1]))


def _error(fn):
    """Run ``fn``; return the ClientError (code, message) it raised. An unexpected SUCCESS is the strongest
    signal that a target accepts what real AWS refuses, so it raises rather than returning a
    falsy sentinel that would read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _policy(as_, asg_name):
    g = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert len(g) == 1, f"group {asg_name} not describable: {g!r}"
    return g[0].get("InstanceMaintenancePolicy")


def _cancel_quietly(as_, asg):
    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=asg)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ActiveInstanceRefreshNotFound":
            raise


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """MaxHealthyPercentage without MinHealthyPercentage is rejected with ValidationError on update,
    create and instance refresh, leaving state unchanged; adding the Min value is accepted.
    """
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    tag = ctx.unique_name("asgr-maxonly-")

    asg, _teardown = _provision_group(ctx, as_, ec2, ssm, desired=0, min_size=0, max_size=2,
                                     tag=tag)
    ctx.on_cleanup(lambda: _cancel_quietly(as_, asg))

    as_.update_auto_scaling_group(AutoScalingGroupName=asg, InstanceMaintenancePolicy={
        "MinHealthyPercentage": 90, "MaxHealthyPercentage": 120})
    good = {"MinHealthyPercentage": 90, "MaxHealthyPercentage": 120}
    assert _policy(as_, asg) == good, f"positive control not stored: {_policy(as_, asg)!r}"

    code, message = _error(lambda: as_.update_auto_scaling_group(
        AutoScalingGroupName=asg, InstanceMaintenancePolicy={"MaxHealthyPercentage": 150}))
    assert code == EXPECTED_CODE, f"Max-only policy update: expected {EXPECTED_CODE!r}, got {code!r}"
    expected = _both_message(" (excluding -1)")
    assert message in expected, f"Max-only policy update: expected one of {expected!r}, got {message!r}"
    assert _policy(as_, asg) == good, (
        f"a rejected policy update must leave the stored policy unchanged: {_policy(as_, asg)!r}")

    lt_name = as_.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg])["AutoScalingGroups"][0]["LaunchTemplate"]["LaunchTemplateName"]
    subnet = as_.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg])["AutoScalingGroups"][0]["VPCZoneIdentifier"]
    twin = ctx.unique_name("sim2real-asgr-grp-")

    def _create_twin():
        r = as_.create_auto_scaling_group(
            AutoScalingGroupName=twin,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=0, MaxSize=2, DesiredCapacity=0, VPCZoneIdentifier=subnet,
            InstanceMaintenancePolicy={"MaxHealthyPercentage": 150},
            Tags=[{"Key": "sim2real", "Value": tag, "PropagateAtLaunch": True}])
        # Accepted where AWS refuses: register its teardown before the helper raises.
        ctx.on_cleanup(lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=twin,
                                                             ForceDelete=True))
        return r
    code, message = _error(_create_twin)
    assert code == EXPECTED_CODE, f"Max-only policy at create: expected {EXPECTED_CODE!r}, got {code!r}"
    expected = _both_message("")
    assert message in expected, f"Max-only policy at create: expected one of {expected!r}, got {message!r}"
    leaked = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[twin])["AutoScalingGroups"]
    assert leaked == [], f"a rejected create must not create the group: {leaked!r}"

    def _refreshes():
        return as_.describe_instance_refreshes(AutoScalingGroupName=asg)["InstanceRefreshes"]
    assert _refreshes() == [], f"fresh group already has refreshes: {_refreshes()!r}"
    code, message = _error(lambda: as_.start_instance_refresh(
        AutoScalingGroupName=asg, Preferences={"MaxHealthyPercentage": 150}))
    assert code == EXPECTED_CODE, f"Max-only refresh preference: expected {EXPECTED_CODE!r}, got {code!r}"
    expected = ("MinHealthyPercentage is required to use MaxHealthyPercentage. Specify "
                "MinHealthyPercentage, or remove MaxHealthyPercentage, and try again.")
    assert message == expected, f"Max-only refresh preference: expected {expected!r}, got {message!r}"
    assert _refreshes() == [], f"a rejected refresh must not be recorded: {_refreshes()!r}"

    # Positive control differing by exactly the missing field.
    rid = as_.start_instance_refresh(AutoScalingGroupName=asg, Preferences={
        "MinHealthyPercentage": 50, "MaxHealthyPercentage": 150})["InstanceRefreshId"]
    seen = _refreshes()
    assert [r["InstanceRefreshId"] for r in seen] == [rid], f"refreshes after control: {seen!r}"
    prefs = seen[0].get("Preferences", {})
    assert (prefs.get("MinHealthyPercentage"), prefs.get("MaxHealthyPercentage")) == (50, 150), (
        f"accepted refresh must echo its preferences: {prefs!r}")
    assert _policy(as_, asg) == good, f"policy drifted during refresh calls: {_policy(as_, asg)!r}"


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation, and swallowing that leaks the VPC.
# So wait (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window,
# and raise a final failure naming the ENIs still attached. Every other error propagates unchanged.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits a 900s cleanup budget.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
