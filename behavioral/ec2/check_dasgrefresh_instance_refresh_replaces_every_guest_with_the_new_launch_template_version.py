"""dasgrefresh-instance-refresh-replaces-every-guest-with-the-new-launch-template-version."""
from __future__ import annotations

import base64
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dasgrefresh-instance-refresh-replaces-every-guest-with-the-new-launch-template-version"
GROUP = 'instance-refresh'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_DESIRED = 2
_MIN_HEALTHY_PERCENTAGE = 100
_VPC_CIDR = "10.77.0.0/16"
_SUBNET_CIDR = "10.77.1.0/24"
_TERMINAL_INVOCATION = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_TERMINAL_REFRESH = (
    "Successful", "Failed", "Cancelled", "RollbackSuccessful", "RollbackFailed",
)
_THROTTLE = (
    "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates",
    "ScalingActivityInProgress",
)
_GONE = (
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "Gateway.NotAttached",
)
_GUEST_REPORT = re.compile(r"iid=(\S+)\s+gen=(\S+)")

# The guest proves two things the control plane cannot: which instance it actually is (read from
# in-guest IMDSv2, not from the API that told us) and which launch-template generation's user data
# actually ran on it (a file only that generation's boot script writes).
_GUEST_SCRIPT = [
    "set -euo pipefail",
    # The SSM agent can come Online before cloud-init has run the user data, so wait for the
    # observable condition rather than assuming an ordering between two independent services.
    "for _ in $(seq 1 90); do [ -s /etc/sim2real-ltgen ] && break; sleep 2; done",
    'T=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token"'
    ' -H "X-aws-ec2-metadata-token-ttl-seconds: 60")',
    'IID=$(curl -sf -H "X-aws-ec2-metadata-token: $T"'
    " http://169.254.169.254/latest/meta-data/instance-id)",
    'echo "iid=$IID gen=$(cat /etc/sim2real-ltgen)"',
]


# ===== helpers =====
def _client_error(fn):
    """Return the botocore Error dict raised by fn. An unexpected SUCCESS is itself a failure."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        "the call was expected to be rejected by real AWS but it succeeded — an emulator that "
        "accepts it is over-permissive, which is the defect this assertion exists to catch"
    )


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _swallow(fn, ok=_GONE):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ok:
            raise


def _create_group_when_profile_resolves(asg, timeout_s=120.0, **kwargs):
    """CreateAutoScalingGroup validates the launch template's instance profile at once; retry only
    while that profile is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return asg.create_auto_scaling_group(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "ValidationError"
                           and "Invalid IAM Instance Profile" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _retry_delete(fn, retries=60, delay=10.0):
    """Deleting network plumbing races the ENIs of instances that are still shutting down."""
    for attempt in range(retries):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code in ("DependencyViolation", "InvalidParameterDependency") and attempt < retries - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, want):
    """An AZ that BOTH offers the instance type and is available; neither API reports both."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {want!r}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r} — this region cannot run this check"
    )
    return usable[0]


def _drain_enis(ec2, vpc_id, timeout_s=600):
    """Wait until nothing in the VPC holds a network interface any more.

    A departed instance still `shutting-down` holds an ENI on the security group.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )["NetworkInterfaces"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                raise
            return
        if not enis or time.monotonic() >= deadline:
            return
        time.sleep(2)


def _teardown_network(ec2, st):
    """One net for the whole network, deleted in dependency order after the group is gone."""
    _drain_enis(ec2, st["vpc"])
    if st.get("assoc"):
        _swallow(lambda: ec2.disassociate_route_table(AssociationId=st["assoc"]))
    if st.get("rt"):
        _retry_delete(lambda: ec2.delete_route_table(RouteTableId=st["rt"]))
    if st.get("subnet"):
        _retry_delete(lambda: ec2.delete_subnet(SubnetId=st["subnet"]))
    if st.get("sg"):
        _retry_delete(lambda: ec2.delete_security_group(GroupId=st["sg"]))
    if st.get("igw"):
        _retry_delete(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])
        )
        _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]))
    _retry_delete(lambda: ec2.delete_vpc(VpcId=st["vpc"]))


def _make_network(ctx, ec2, tagv):
    """A public subnet of this check's own making — no ambient default VPC is touched.

    The guest's SSM agent must reach the SSM endpoint: IGW, default route and public addressing.
    """
    az = _usable_az(ec2, _INSTANCE_TYPE)
    spec = [{"Key": "Name", "Value": tagv}, {"Key": "sim2real", "Value": tagv}]
    vpc = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    st = {"vpc": vpc, "igw": None, "subnet": None, "rt": None, "assoc": None, "sg": None}
    ctx.on_cleanup(lambda: _teardown_network(ec2, st))

    st["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": spec}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=st["igw"], VpcId=vpc)

    st["subnet"] = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock=_SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(
        SubnetId=st["subnet"], MapPublicIpOnLaunch={"Value": True}
    )

    st["rt"] = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=[{"ResourceType": "route-table", "Tags": spec}]
    )["RouteTable"]["RouteTableId"]
    ec2.create_route(
        RouteTableId=st["rt"], DestinationCidrBlock="0.0.0.0/0", GatewayId=st["igw"]
    )
    st["assoc"] = ec2.associate_route_table(
        RouteTableId=st["rt"], SubnetId=st["subnet"]
    )["AssociationId"]

    st["sg"] = ec2.create_security_group(
        GroupName=tagv,
        Description="sim2real-behav dasgrefresh egress-only",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    return st, az


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(24):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                break
            if attempt == 23:
                raise
            time.sleep(5)
    for attempt in range(24):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 23:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(24):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return
            if attempt == 23:
                raise
            time.sleep(5)


def _managed_instance_profile(ctx, iam, name, tagv):
    """A profile granting only AmazonSSMManagedInstanceCore, created by this check."""
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav dasgrefresh managed instance role",
        Tags=[{"Key": "sim2real", "Value": tagv}],
    )
    ctx.on_cleanup(lambda: _drop_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(
        InstanceProfileName=name, Tags=[{"Key": "sim2real", "Value": tagv}]
    )
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, name, name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    # IAM exposes no condition that says "this profile is now resolvable by a launch": the poll
    # below is the closest observable, and creating the group retries while the profile propagates.
    _poll(
        lambda: iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"],
        lambda p: any(r["RoleName"] == name for r in p.get("Roles", [])),
        timeout_s=120,
        interval_s=3.0,
        what=f"instance profile {name!r} carrying its role",
    )
    return name


def _user_data(generation):
    script = "\n".join(
        [
            "#!/bin/bash",
            f"echo {generation} > /etc/sim2real-ltgen",
        ]
    )
    return base64.b64encode(script.encode()).decode()


def _lt_data(ami, profile, sg, generation, tagv):
    return {
        "ImageId": ami,
        "InstanceType": _INSTANCE_TYPE,
        "IamInstanceProfile": {"Name": profile},
        "SecurityGroupIds": [sg],
        "UserData": _user_data(generation),
        "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"},
        "TagSpecifications": [
            {
                "ResourceType": rt,
                "Tags": [{"Key": "Name", "Value": tagv}, {"Key": "sim2real", "Value": tagv}],
            }
            for rt in ("instance", "volume")
        ],
    }


def _delete_asg_and_wait(asg, name, timeout_s=900):
    """ForceDelete terminates the group's instances with it; wait so the ENIs release."""
    try:
        _call_with_retry(
            lambda: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True
            ),
            retries=30,
            delay=10.0,
        )
    except ClientError as exc:
        if "not found" not in str(exc):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = _asg_groups(asg, name)
        if not groups:
            return
        time.sleep(10)


def _asg_groups(asg, name):
    found = []
    for page in asg.get_paginator("describe_auto_scaling_groups").paginate(
        AutoScalingGroupNames=[name]
    ):
        found += page["AutoScalingGroups"]
    return found


def _group(asg, name):
    groups = _asg_groups(asg, name)
    assert len(groups) == 1, f"expected exactly one group named {name!r}, got {groups!r}"
    return groups[0]


def _in_service(group):
    return {
        i["InstanceId"]
        for i in group.get("Instances", [])
        if i.get("LifecycleState") == "InService"
    }


def _invocation(ssm, command_id, instance_id):
    try:
        return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
            return None
        raise


def _await_agents(ssm, instance_ids, timeout_s=420):
    """Every guest must register with the agent. A guest that never does is a FAIL."""

    def _online():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in instance_ids:
                    seen[info["InstanceId"]] = info.get("PingStatus")
        return seen

    seen = _poll(
        _online,
        lambda s: set(s) == set(instance_ids) and all(v == "Online" for v in s.values()),
        timeout_s=timeout_s,
        interval_s=10.0,
        what=f"the SSM agent coming Online on all of {sorted(instance_ids)!r}",
    )
    return seen


def _guest_generations(ssm, instance_ids, what):
    """Read the launch-template generation out of each guest, via a command that runs there."""
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=sorted(instance_ids),
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": _GUEST_SCRIPT},
            TimeoutSeconds=300,
            Comment="sim2real-behav dasgrefresh guest generation",
        ),
        codes=_THROTTLE + ("InvalidInstanceId",),
        retries=30,
        delay=10.0,
    )
    command_id = sent["Command"]["CommandId"]
    out = {}
    for iid in sorted(instance_ids):
        inv = _poll(
            lambda iid=iid: _invocation(ssm, command_id, iid),
            lambda i: i is not None and i.get("Status") in _TERMINAL_INVOCATION,
            timeout_s=360,
            interval_s=5.0,
            what=f"{what}: invocation on {iid}",
        )
        assert inv["Status"] == "Success", (
            f"{what}: the in-guest read on {iid} was {inv['Status']!r} "
            f"({inv.get('StatusDetails')!r}), stderr={inv.get('StandardErrorContent')!r}"
        )
        assert inv["ResponseCode"] == 0, (
            f"{what}: the in-guest script on {iid} exited {inv['ResponseCode']!r}"
        )
        stdout = inv["StandardOutputContent"].strip()
        m = _GUEST_REPORT.search(stdout)
        assert m, f"{what}: the guest on {iid} printed {stdout!r}, not 'iid=<id> gen=<n>'"
        reported_iid, generation = m.group(1), m.group(2)
        assert reported_iid == iid, (
            f"{what}: the guest reached through {iid!r} says its own IMDS instance id is "
            f"{reported_iid!r} — the command ran on a different host than the API claims"
        )
        out[iid] = generation
    return out


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An instance refresh replaces every guest, each replacement reporting in-guest that it booted
    the new launch-template version; a repeat refresh replaces nothing, and no original stops
    serving before a replacement is InService nor does the group drop below its healthy floor.
    """
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    tagv = ctx.unique_name("sim2real-behav-dasgrefresh-ir-")

    # --- network of this check's own making ----------------------------------
    net, az = _make_network(ctx, ec2, tagv)

    # --- an instance role the SSM agent can register under -------------------
    profile = _managed_instance_profile(ctx, iam, tagv, tagv)

    # --- two launch-template generations, distinguishable only in the guest ---
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    lt = ec2.create_launch_template(
        LaunchTemplateName=tagv,
        LaunchTemplateData=_lt_data(ami, profile, net["sg"], 1, tagv),
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": tagv}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    assert lt["LatestVersionNumber"] == 1, (
        f"a fresh launch template must start at version 1, got {lt['LatestVersionNumber']!r}"
    )

    v2 = ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        SourceVersion="1",
        LaunchTemplateData={"UserData": _user_data(2)},
    )["LaunchTemplateVersion"]
    assert v2["VersionNumber"] == 2, (
        f"the second version must be numbered 2, got {v2['VersionNumber']!r}"
    )

    # --- the group, pinned to version 1 --------------------------------------
    group_name = tagv
    _create_group_when_profile_resolves(
        asg,
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "1"},
        MinSize=_DESIRED,
        MaxSize=_DESIRED + 2,
        DesiredCapacity=_DESIRED,
        DefaultCooldown=0,
        HealthCheckType="EC2",
        HealthCheckGracePeriod=0,
        VPCZoneIdentifier=net["subnet"],
        Tags=[{"Key": "sim2real", "Value": tagv, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(asg, group_name))

    original = _poll(
        lambda: _in_service(_group(asg, group_name)),
        lambda s: len(s) == _DESIRED,
        timeout_s=600,
        interval_s=10.0,
        what=f"{_DESIRED} instances reaching InService in {group_name!r}",
    )
    assert len(original) == _DESIRED, f"the group settled on {sorted(original)!r}"
    placements = {
        i["InstanceId"]: i["AvailabilityZone"] for i in _group(asg, group_name)["Instances"]
    }
    assert set(placements.values()) == {az}, (
        f"every instance must land in the derived AZ {az!r}, got {placements!r}"
    )

    # --- the guests' own account of which generation booted them -------------
    _await_agents(ssm, original)
    before = _guest_generations(ssm, original, "before the refresh")
    assert set(before.values()) == {"1"}, (
        "every original guest must report that launch-template generation 1's user data ran on "
        f"it; the guests said {before!r}"
    )

    # --- the refresh, with the capacity floor sampled throughout -------------
    desired_config = {"LaunchTemplate": {"LaunchTemplateId": lt_id, "Version": "2"}}
    preferences = {
        "MinHealthyPercentage": _MIN_HEALTHY_PERCENTAGE,
        "InstanceWarmup": 0,
        "SkipMatching": True,
        "ScaleInProtectedInstances": "Ignore",
        "StandbyInstances": "Ignore",
        "AutoRollback": False,
    }
    refresh_id = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Strategy="Rolling",
        DesiredConfiguration=desired_config,
        Preferences=preferences,
    )["InstanceRefreshId"]

    floor = (_DESIRED * _MIN_HEALTHY_PERCENTAGE) // 100
    # A floor at the full desired capacity leaves room for exactly one instance to drain at a time.
    allowed_out = _DESIRED - floor + 1
    acc = {
        "attached_floor": len(original),
        "max_out": 0,
        "seen": set(original),
        "serving_replacements": set(),
        # (original instance id, how many replacements were already InService when it left)
        "departures": [],
        "still_serving": set(original),
    }

    def _sample():
        """One observation of the group, folded into the accumulators above.

        Shared by the refresh and settle polls so the timeline has no gap between loops.
        """
        group = _call_with_retry(lambda: _group(asg, group_name))
        live = _in_service(group)
        # AWS moves the outgoing instance to Terminating BEFORE its replacement is Pending, so the
        # InService count dips; a draining instance is still attached and counts until it is gone.
        outgoing = {
            i["InstanceId"]
            for i in group["Instances"]
            if i["LifecycleState"].startswith("Terminating")
        }
        acc["seen"] |= live
        acc["serving_replacements"] |= live - original
        acc["attached_floor"] = min(acc["attached_floor"], len(live | outgoing))
        acc["max_out"] = max(acc["max_out"], len(outgoing))
        for gone in sorted(acc["still_serving"] - live):
            acc["departures"].append((gone, len(acc["serving_replacements"])))
        acc["still_serving"] &= live
        return live

    deadline = time.monotonic() + 1200
    record = None
    while True:
        _sample()
        records = _call_with_retry(
            lambda: asg.describe_instance_refreshes(
                AutoScalingGroupName=group_name, InstanceRefreshIds=[refresh_id]
            )["InstanceRefreshes"]
        )
        assert len(records) == 1, f"expected one refresh record, got {records!r}"
        record = records[0]
        if record["Status"] in _TERMINAL_REFRESH:
            break
        assert time.monotonic() < deadline, (
            f"the instance refresh {refresh_id!r} did not reach a terminal status within 1200s; "
            f"last record {record!r}"
        )
        time.sleep(5)

    assert record["Status"] == "Successful", (
        f"the refresh ended {record['Status']!r}: {record.get('StatusReason')!r}"
    )
    assert record["PercentageComplete"] == 100, (
        f"a Successful refresh must report 100% complete, got {record['PercentageComplete']!r}"
    )
    # --- the replacement is observable as NEW hosts, in their own words ------
    replaced = _poll(
        _sample,
        lambda s: len(s) == _DESIRED and not (s & original),
        timeout_s=300,
        interval_s=5.0,
        what="the group holding only post-refresh instance ids",
    )
    assert not (replaced & original), (
        f"the refresh must replace the original instances; {sorted(replaced & original)!r} "
        f"survived (original {sorted(original)!r}, now {sorted(replaced)!r})"
    )
    assert len(replaced) == _DESIRED, f"the group settled on {sorted(replaced)!r}"
    seen_in_service = acc["seen"]
    assert seen_in_service <= (original | replaced), (
        "no host outside the two originals and their two replacements may ever have served; the "
        f"refresh also put {sorted(seen_in_service - (original | replaced))!r} InService"
    )

    # --- what MinHealthyPercentage actually bought, over the sampled timeline -
    assert acc["max_out"] <= allowed_out, (
        f"MinHealthyPercentage {_MIN_HEALTHY_PERCENTAGE} of desired {_DESIRED} leaves room for "
        f"{allowed_out} instance(s) to be draining at a time, but {acc['max_out']} were in a "
        "Terminating state in the same sample — the refresh removed capacity it was not allowed to"
    )
    assert acc["attached_floor"] >= floor, (
        f"the group must keep at least {floor} instance(s) attached — InService, or draining but "
        f"not yet gone — at every moment of the refresh; it was sampled at {acc['attached_floor']}"
    )
    assert len(acc["departures"]) == _DESIRED, (
        f"every original instance must have been observed leaving service, got {acc['departures']!r} "
        f"for originals {sorted(original)!r}"
    )
    for index, (instance_id, ready) in enumerate(acc["departures"]):
        assert ready >= index, (
            f"the refresh must not stop serving from {instance_id!r} (departure {index + 1} of "
            f"{len(acc['departures'])}) until {index} replacement(s) are already InService; only "
            f"{ready} were — this is the ordering MinHealthyPercentage buys, and the one an "
            "emulator that terminates first and launches afterwards gets wrong"
        )

    versions = {
        i["InstanceId"]: i.get("LaunchTemplate", {}).get("Version")
        for i in _group(asg, group_name)["Instances"]
    }
    assert set(versions.values()) == {"2"}, (
        f"every replacement must be recorded against launch-template version 2, got {versions!r}"
    )
    group_lt = _group(asg, group_name)["LaunchTemplate"]
    assert group_lt["Version"] == "2", (
        f"the refresh must advance the group's own launch-template version, got {group_lt!r}"
    )

    _await_agents(ssm, replaced)
    after = _guest_generations(ssm, replaced, "after the refresh")
    assert set(after.values()) == {"2"}, (
        "every replacement guest must report that launch-template generation 2's user data ran "
        f"on it — this is the only evidence a host actually rebooted from the new version; the "
        f"guests said {after!r}"
    )
    assert set(after) & set(before) == set(), (
        f"the guests answering after the refresh must be different hosts: before {sorted(before)!r}, "
        f"after {sorted(after)!r}"
    )

    # --- absent leg: the identical refresh must now replace nothing ----------
    second_id = asg.start_instance_refresh(
        AutoScalingGroupName=group_name,
        Strategy="Rolling",
        DesiredConfiguration=desired_config,
        Preferences=preferences,
    )["InstanceRefreshId"]
    assert second_id != refresh_id, (
        f"a second refresh must mint a new id, got {second_id!r} twice"
    )
    second = _poll(
        lambda: asg.describe_instance_refreshes(
            AutoScalingGroupName=group_name, InstanceRefreshIds=[second_id]
        )["InstanceRefreshes"][0],
        lambda r: r["Status"] in _TERMINAL_REFRESH,
        timeout_s=300,
        interval_s=10.0,
        what=f"the no-op refresh {second_id!r} reaching a terminal status",
    )
    assert second["Status"] == "Successful", (
        f"the no-op refresh ended {second['Status']!r}: {second.get('StatusReason')!r}"
    )
    unchanged = _in_service(_group(asg, group_name))
    assert unchanged == replaced, (
        "with SkipMatching enabled and every instance already on the desired configuration, the "
        f"refresh must replace nothing; the group went from {sorted(replaced)!r} to "
        f"{sorted(unchanged)!r}"
    )
    still = _guest_generations(ssm, unchanged, "after the no-op refresh")
    assert still == after, (
        "the same hosts must still be answering with the same generation after a refresh that "
        f"had nothing to do; was {after!r}, now {still!r}"
    )

    # --- negative: the group's own MaxSize still bounds it after a refresh ---
    #     The refresh rewrote the group's launch template; it must not have loosened the capacity
    #     bounds the group was created with.
    before_capacity = _group(asg, group_name)
    over = _client_error(
        lambda: asg.set_desired_capacity(
            AutoScalingGroupName=group_name,
            DesiredCapacity=before_capacity["MaxSize"] + 1,
            HonorCooldown=False,
        )
    )
    assert over.get("Code") == "ValidationError", (
        "asking for more capacity than MaxSize must be refused; got "
        f"{over!r} for desired {before_capacity['MaxSize'] + 1} against MaxSize "
        f"{before_capacity['MaxSize']}"
    )
    over_message = (
        f"New SetDesiredCapacity value {before_capacity['MaxSize'] + 1} is above max value "
        f"{before_capacity['MaxSize']} for the AutoScalingGroup."
    )
    assert over.get("Message") == over_message, (
        f"expected the over-MaxSize refusal message {over_message!r}, got {over!r}"
    )
    after_capacity = _group(asg, group_name)
    assert after_capacity["DesiredCapacity"] == before_capacity["DesiredCapacity"], (
        "a refused scale-out must leave the desired capacity alone; it moved from "
        f"{before_capacity['DesiredCapacity']!r} to {after_capacity['DesiredCapacity']!r}"
    )
    assert _in_service(after_capacity) == unchanged, (
        "a refused scale-out must launch nothing; the group went from "
        f"{sorted(unchanged)!r} to {sorted(_in_service(after_capacity))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
