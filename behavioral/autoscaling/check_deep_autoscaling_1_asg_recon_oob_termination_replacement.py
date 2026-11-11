"""deep-autoscaling-1-asg-recon-oob-termination-replacement."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deep-autoscaling-1-asg-recon-oob-termination-replacement"
GROUP = "reconciliation"
SERVICES = ["autoscaling"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
LIVE_STATES = {"pending", "running"}


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
# ===== end helpers =====


@tags("dp:api", "plane:data", "concern:data-plane", "axis:happy-path", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Out-of-band EC2 termination of one member triggers a replacement, never a resize: a new
    instance id appears, the killed one reaches terminated at EC2, and DesiredCapacity stays 2."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    tag = ctx.unique_name("asgr-oob-")

    # MaxSize=3 / MinSize=0 so a resize to 1 would be LEGAL: "desired stays 2" is then a real
    # claim about the reconciliation loop, not something the bounds force.
    asg, teardown = _provision_group(ctx, as_, ec2, ssm, desired=2, min_size=0, max_size=3,
                                     tag=tag)

    def _group():
        return as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg])["AutoScalingGroups"][0]

    def _in_service(g):
        return sorted(i["InstanceId"] for i in g["Instances"]
                      if i["LifecycleState"] == "InService")

    before = _poll(_group, lambda g: len(_in_service(g)) == 2, timeout_s=600, interval_s=5,
                   description="group reaches 2 InService instances")
    original = _in_service(before)
    assert before["DesiredCapacity"] == 2, f"DesiredCapacity before kill: {before['DesiredCapacity']!r}"
    killed, survivor = original[0], original[1]

    # The out-of-band act: EC2 directly, not TerminateInstanceInAutoScalingGroup.
    ec2.terminate_instances(InstanceIds=[killed])

    desired_seen = []

    def _sample():
        g = _group()
        desired_seen.append(g["DesiredCapacity"])
        return g

    def _healed(g):
        ids = _in_service(g)
        return len(ids) == 2 and killed not in ids and survivor in ids

    healed = _poll(_sample, _healed, timeout_s=1200, interval_s=5,
                   description=f"group replaces out-of-band-terminated {killed} back to 2 InService")
    assert set(desired_seen) == {2}, (
        f"DesiredCapacity must stay 2 throughout reconciliation (replacement, not resize); "
        f"sampled values were {desired_seen!r}")
    new_ids = sorted(set(_in_service(healed)) - set(original))
    assert len(new_ids) == 1, (
        f"exactly one NEW instance must replace {killed}; InService now {_in_service(healed)!r}, "
        f"originals {original!r}")
    new_id = new_ids[0]
    assert new_id != killed, f"replacement id {new_id!r} equals the killed id"

    # EC2 is the independent witness: the killed id is terminated, the replacement runs.
    def _ec2_state(iid):
        r = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
        return r[0]["Instances"][0]["State"]["Name"]

    killed_state = _poll(lambda: _ec2_state(killed), lambda s: s == "terminated",
                         timeout_s=300, description=f"EC2 reports {killed} terminated")
    assert killed_state == "terminated", f"killed instance state {killed_state!r}"
    new_state = _poll(lambda: _ec2_state(new_id), lambda s: s == "running",
                      timeout_s=300, description=f"EC2 reports replacement {new_id} running")
    assert new_state == "running", f"replacement instance state {new_state!r}"
    live = sorted(i for i, s in _group_instance_ids_at_ec2(ec2, asg).items() if s in LIVE_STATES)
    assert live == sorted([survivor, new_id]), (
        f"EC2 must attribute exactly the survivor and the replacement to the group; live={live!r}")

    # The activity log must explain the replacement: one activity taking the killed instance
    # out of service, and one launching the replacement because actual < desired.
    acts = []
    for page in as_.get_paginator("describe_scaling_activities").paginate(AutoScalingGroupName=asg):
        acts.extend(page["Activities"])
    term = [a for a in acts if killed in a.get("Description", "")
            and a["Description"].startswith("Terminating EC2 instance")]
    launch = [a for a in acts if new_id in a.get("Description", "")
              and a["Description"].startswith("Launching a new EC2 instance")]
    summary = [(a.get("Description"), a.get("Cause"), a.get("StatusCode")) for a in acts]
    assert len(term) == 1, f"expected one terminate activity naming {killed}; activities={summary!r}"
    assert "taken out of service in response to an EC2 health check" in term[0]["Cause"], (
        f"terminate activity Cause must attribute it to the EC2 health check: {term[0]['Cause']!r}")
    assert len(launch) == 1, f"expected one launch activity naming {new_id}; activities={summary!r}"
    # AWS's Cause reads "At <ts> an instance was launched in response to an unhealthy
    # instance needing to be replaced." -- a REPLACEMENT cause, not a capacity change.
    assert "launched in response to an unhealthy instance needing to be replaced" \
        in launch[0]["Cause"], (
            f"launch activity Cause must name the replacement of the unhealthy (killed) "
            f"instance: {launch[0]['Cause']!r}")
    assert launch[0]["StartTime"] >= term[0]["StartTime"], (
        f"the replacement launch ({launch[0]['StartTime']!r}) must follow the out-of-service "
        f"activity for {killed} ({term[0]['StartTime']!r})")
    assert launch[0]["StatusCode"] == "Successful", f"launch activity {launch[0]!r}"

    # Tear down inside the check: the engine's cleanup chain is bounded at 60 s, which instance
    # termination cannot meet, and a cut-off chain strands the subnet and VPC behind it.
    assert teardown(900), f"ForceDelete of {asg} did not terminate every member within 900s"


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
