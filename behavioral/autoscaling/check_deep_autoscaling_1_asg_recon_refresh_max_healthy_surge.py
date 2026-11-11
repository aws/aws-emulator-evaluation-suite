"""deep-autoscaling-1-asg-recon-refresh-max-healthy-surge."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deep-autoscaling-1-asg-recon-refresh-max-healthy-surge"
GROUP = "reconciliation"
SERVICES = ["autoscaling"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
LIVE_STATES = {"pending", "running"}
TERMINAL = {"Successful", "Failed", "Cancelled", "RollbackFailed", "RollbackSuccessful"}

DESIRED = 2
PREFERENCES = {"MinHealthyPercentage": 100, "MaxHealthyPercentage": 200,
               "InstanceWarmup": 0, "SkipMatching": False}


# ===== helpers =====
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
# ===== end helpers =====


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """MaxHealthyPercentage=200 surges launch-before-terminate, observed at EC2: the 2-instance
    group holds at least 3 live instances at some sampled point and never drops below 2 InService."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    tag = ctx.unique_name("asgr-surge-")

    asg, teardown = _provision_group(ctx, as_, ec2, ssm, desired=DESIRED, min_size=0,
                                     max_size=2 * DESIRED, tag=tag)

    def _healthy_in_service():
        return sorted(i["InstanceId"] for i in _asg_instances(as_, asg)
                      if i["LifecycleState"] == "InService" and i["HealthStatus"] == "HEALTHY")

    original = _poll(_healthy_in_service, lambda ids: len(ids) == DESIRED, timeout_s=600,
                     description=f"group reaches {DESIRED} healthy InService instances")

    refresh_id = as_.start_instance_refresh(AutoScalingGroupName=asg,
                                            Preferences=PREFERENCES)["InstanceRefreshId"]
    ctx.on_cleanup(lambda: _cancel_quietly(as_, asg))

    # One sample = what EC2 says (the fleet as it physically exists) + what the group says.
    samples = []  # (elapsed_s, {iid: ec2_state}, healthy_in_service_count, refresh_status)
    t0 = time.monotonic()
    deadline = t0 + 1800
    while time.monotonic() < deadline:
        states = _group_instance_ids_at_ec2(ec2, asg)
        healthy = len(_healthy_in_service())
        status = _refresh(as_, asg, refresh_id)["Status"]
        samples.append((round(time.monotonic() - t0), states, healthy, status))
        if status in TERMINAL:
            break
        time.sleep(5)

    final = _refresh(as_, asg, refresh_id)
    brief = [(t, sum(1 for s in st.values() if s in LIVE_STATES), h, rs)
             for t, st, h, rs in samples]
    assert final["Status"] == "Successful", (
        f"refresh must finish Successful, got {final['Status']!r} ({final.get('StatusReason')!r}); "
        f"(t, live, healthy, status) samples={brief!r}")
    live_counts = [sum(1 for s in st.values() if s in LIVE_STATES) for _, st, _, _ in samples]
    first_new = next((k for k, (_, st, _, _) in enumerate(samples)
                      if any(i not in original and s in LIVE_STATES for i, s in st.items())), None)
    first_old_gone = next((k for k, (_, st, _, _) in enumerate(samples)
                           if any(i in original and s not in LIVE_STATES for i, s in st.items())),
                          None)
    assert max(live_counts) >= DESIRED + 1, (
        f"MaxHealthyPercentage=200 must surge: EC2 never held more than {max(live_counts)} live "
        f"instances; (t, live, healthy, status) samples={brief!r}")
    assert max(live_counts) <= 2 * DESIRED, (
        f"surge exceeded MaxHealthyPercentage=200 of {DESIRED}: {max(live_counts)} live; "
        f"samples={brief!r}")
    assert first_new is not None and first_old_gone is not None, (
        f"refresh must both launch new and terminate original instances: "
        f"first_new={first_new!r} first_old_gone={first_old_gone!r} samples={brief!r}")
    assert first_new < first_old_gone, (
        f"launch-before-terminate violated: an original left pending/running at sample "
        f"{first_old_gone} but the first replacement appeared at sample {first_new}; "
        f"samples={brief!r}")
    below = [b for b in brief if b[2] < DESIRED]
    assert not below, (
        f"MinHealthyPercentage=100 must keep {DESIRED} healthy InService throughout: {below!r}")

    after = _poll(_healthy_in_service, lambda ids: len(ids) == DESIRED, timeout_s=300,
                  description=f"group holds {DESIRED} healthy InService after the refresh")
    assert set(after).isdisjoint(original), (
        f"a Successful refresh must replace every original instance; survivors="
        f"{sorted(set(after) & set(original))!r}")
    end_states = _group_instance_ids_at_ec2(ec2, asg)
    live = sorted(i for i, s in end_states.items() if s in LIVE_STATES)
    assert live == after, f"EC2 live members {live!r} disagree with the group's {after!r}"

    # Tear down inside the check: the engine's cleanup chain is bounded at 60 s, which instance
    # termination cannot meet, and a cut-off chain strands the subnet and VPC behind it.
    assert teardown(900), f"ForceDelete of {asg} did not terminate every member within 900s"


def _cancel_quietly(as_, asg):
    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=asg)
    except ClientError as exc:
        # No refresh in progress, or the group itself is already deleted: nothing to cancel.
        err = exc.response["Error"]
        if err["Code"] != "ActiveInstanceRefreshNotFound" and not (
                err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


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
