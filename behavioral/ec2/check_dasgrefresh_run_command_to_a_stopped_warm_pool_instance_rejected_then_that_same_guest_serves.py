"""dasgrefresh-run-command-to-a-stopped-warm-pool-instance-rejected-then-that-same-guest-serves."""
from __future__ import annotations

import base64
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dasgrefresh-run-command-to-a-stopped-warm-pool-instance-rejected-then-that-same-guest-serves"
GROUP = 'warm-pool'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.78.0.0/16"
_SUBNET_CIDR = "10.78.1.0/24"
_TERMINAL_INVOCATION = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_THROTTLE = (
    "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates",
    "ScalingActivityInProgress",
)
_GONE = (
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "Gateway.NotAttached",
)
_MARKER = "/etc/sim2real-warm-init"
_GUEST_REPORT = re.compile(
    r"iid=(\S+)\s+init=(\d+)\s+boot=(\d+)\s+initboot=(\S+)\s+bootid=(\S+)"
)

# The user data APPENDS rather than overwrites, so a second cloud-init pass cannot erase the line
# the pool's initialisation wrote; the guest reports the FIRST line: the epoch and the kernel boot
# id of the boot that initialised the host.
_USER_DATA = (
    f"#!/bin/bash\necho \"$(date +%s) $(cat /proc/sys/kernel/random/boot_id)\" >> {_MARKER}\n"
)

# Nothing in this script touches an AWS API. It reads the host's own identity from in-guest IMDSv2,
# the epoch at which this filesystem was first initialised, and the epoch of the boot that is
# running right now, plus the boot ids of both boots. A different boot id means the host was
# prepared in an EARLIER boot than the one serving, which is precisely what "pre-initialised" means
# and is not a fact any control-plane record contains.
_GUEST_SCRIPT = [
    "set -euo pipefail",
    # The SSM agent can come Online before cloud-init has run the user data, so wait for the
    # observable condition rather than assuming an ordering between two independent services.
    f"for _ in $(seq 1 90); do [ -s {_MARKER} ] && break; sleep 2; done",
    'T=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token"'
    ' -H "X-aws-ec2-metadata-token-ttl-seconds: 60")',
    'IID=$(curl -sf -H "X-aws-ec2-metadata-token: $T"'
    " http://169.254.169.254/latest/meta-data/instance-id)",
    f"INIT=$(head -n1 {_MARKER} | cut -d' ' -f1)",
    f"INITBOOT=$(head -n1 {_MARKER} | cut -d' ' -f2)",
    "NOW=$(date +%s)",
    "UP=$(cut -d. -f1 /proc/uptime)",
    "BOOTID=$(cat /proc/sys/kernel/random/boot_id)",
    'echo "iid=$IID init=$INIT boot=$((NOW-UP)) initboot=$INITBOOT bootid=$BOOTID"',
]


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


def _bounded(ctx, cap_s, reserve_s=10.0):
    """`cap_s`, shortened so the wait ends `reserve_s` before the runner stops the check."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


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
    """An AZ that BOTH offers the instance type and is itself available.

    describe_instance_type_offerings does not report zone state and describe_availability_zones
    says nothing about instance types, so only the intersection is safe to launch into.
    """
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

    A `shutting-down` instance's ENI still references the security group, so deleting it first
    fails with DependencyViolation; waiting makes every later delete succeed first time.
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

    The SSM agent has to reach the SSM endpoint from the guest to register at all, so the subnet
    needs an internet gateway, a default route and auto-assigned public addressing.
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
    ec2.modify_subnet_attribute(SubnetId=st["subnet"], MapPublicIpOnLaunch={"Value": True})

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
        Description="sim2real-behav dasgrefresh warm-pool managed instance role",
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
        timeout_s=_bounded(ctx, 120),
        interval_s=2.0,
        what=f"instance profile {name!r} carrying its role",
    )
    return name


def _delete_asg_and_wait(asg, name, timeout_s=900):
    """ForceDelete terminates the group's instances AND its warm pool; wait so the ENIs release."""
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
        if not _asg_groups(asg, name):
            return
        time.sleep(10)


def _delete_warm_pool(asg, name):
    _swallow_validation(
        lambda: _call_with_retry(
            lambda: asg.delete_warm_pool(AutoScalingGroupName=name, ForceDelete=True),
            retries=30,
            delay=10.0,
        )
    )


def _swallow_validation(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ValidationError":
            raise


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


def _warm_instances(asg, name):
    found = []
    for page in asg.get_paginator("describe_warm_pool").paginate(AutoScalingGroupName=name):
        found += page["Instances"]
    return found


def _instance(ec2, instance_id):
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id!r} is not describable")


def _root_volume(inst):
    root = inst["RootDeviceName"]
    for bd in inst.get("BlockDeviceMappings", []):
        if bd.get("DeviceName") == root:
            return bd["Ebs"]["VolumeId"]
    raise AssertionError(
        f"instance {inst['InstanceId']!r} exposes no EBS mapping for its root device "
        f"{root!r}: {inst.get('BlockDeviceMappings')!r}"
    )


def _agent_record(ssm, instance_id):
    for page in ssm.get_paginator("describe_instance_information").paginate():
        for info in page["InstanceInformationList"]:
            if info.get("InstanceId") == instance_id:
                return info
    return None


def _invocation(ssm, command_id, instance_id):
    try:
        return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
            return None
        raise


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A Stopped warm-pool instance refuses Run Command and has no Online agent; scaling out then
    promotes THAT instance (same id, same root volume), whose guest reports its own IMDS id and an
    initialisation epoch strictly before the boot now serving.
    """
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    tagv = ctx.unique_name("sim2real-behav-dasgrefresh-wp-")

    net, az = _make_network(ctx, ec2, tagv)
    profile = _managed_instance_profile(ctx, iam, tagv, tagv)

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=tagv,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": _INSTANCE_TYPE,
            "IamInstanceProfile": {"Name": profile},
            "SecurityGroupIds": [net["sg"]],
            "UserData": base64.b64encode(_USER_DATA.encode()).decode(),
            "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required"},
            "TagSpecifications": [
                {
                    "ResourceType": rt,
                    "Tags": [
                        {"Key": "Name", "Value": tagv},
                        {"Key": "sim2real", "Value": tagv},
                    ],
                }
                for rt in ("instance", "volume")
            ],
        },
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": tagv}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    group_name = tagv
    _create_group_when_profile_resolves(
        asg,
        timeout_s=_bounded(ctx, 120.0),
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "1"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        DefaultCooldown=0,
        HealthCheckType="EC2",
        HealthCheckGracePeriod=0,
        VPCZoneIdentifier=net["subnet"],
        Tags=[{"Key": "sim2real", "Value": tagv, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_asg_and_wait(asg, group_name))
    assert _in_service(_group(asg, group_name)) == set(), (
        "a group created at desired capacity 0 must hold no InService instances, got "
        f"{sorted(_in_service(_group(asg, group_name)))!r}"
    )

    # --- the warm pool: one pre-initialised host, parked Stopped -------------
    asg.put_warm_pool(AutoScalingGroupName=group_name, PoolState="Stopped")
    ctx.on_cleanup(lambda: _delete_warm_pool(asg, group_name))

    parked = _poll(
        lambda: _warm_instances(asg, group_name),
        lambda ins: len(ins) == 1 and ins[0].get("LifecycleState") == "Warmed:Stopped",
        timeout_s=_bounded(ctx, 900),
        interval_s=2.0,
        what=f"one instance reaching Warmed:Stopped in {group_name!r}'s warm pool",
    )
    warm_id = parked[0]["InstanceId"]
    assert parked[0]["LifecycleState"] == "Warmed:Stopped", (
        f"the parked instance is {parked[0]!r}, not Warmed:Stopped"
    )
    config = asg.describe_warm_pool(AutoScalingGroupName=group_name)["WarmPoolConfiguration"]
    assert config["PoolState"] == "Stopped", (
        f"the pool was configured Stopped; DescribeWarmPool reports {config!r}"
    )

    parked_instance = _instance(ec2, warm_id)
    assert parked_instance["State"]["Name"] == "stopped", (
        f"a Warmed:Stopped instance must really be stopped in EC2, got "
        f"{parked_instance['State']!r} for {warm_id!r}"
    )
    assert parked_instance["Placement"]["AvailabilityZone"] == az, (
        f"the warm instance landed in {parked_instance['Placement']!r}, not the derived AZ {az!r}"
    )
    warm_volume = _root_volume(parked_instance)
    assert _in_service(_group(asg, group_name)) == set(), (
        "a warm-pool instance is not serving capacity, so it must not appear as InService in the "
        f"group; the group holds {sorted(_in_service(_group(asg, group_name)))!r}"
    )

    # --- the absent leg: this host is parked, so nothing can run on it -------
    parked = _client_error(
        lambda: ssm.send_command(
            InstanceIds=[warm_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["echo parked"]},
            TimeoutSeconds=120,
            Comment="sim2real-behav dasgrefresh parked probe",
        )
    )
    assert parked.get("Code") == "InvalidInstanceId", (
        f"Run Command against the parked warm-pool instance {warm_id!r} must be refused with "
        f"InvalidInstanceId; got {parked!r}"
    )
    parked_message = "Instances not in a valid state for account"
    assert parked.get("Message") == parked_message, (
        f"expected the parked-instance refusal message {parked_message!r}, got {parked!r}"
    )
    parked_agent = _agent_record(ssm, warm_id)
    parked_ping = parked_agent.get("PingStatus") if parked_agent else "no-agent-record"
    assert parked_ping != "Online", (
        f"the parked instance {warm_id!r} must have no reachable guest while it sits in the warm "
        f"pool; its agent record says {parked_ping!r}"
    )

    # --- scale out: the promotion must consume THAT instance -----------------
    asg.set_desired_capacity(
        AutoScalingGroupName=group_name, DesiredCapacity=1, HonorCooldown=False
    )

    ever_in_service = set()

    def _serving():
        live = _in_service(_call_with_retry(lambda: _group(asg, group_name)))
        ever_in_service.update(live)
        return live

    serving = _poll(
        _serving,
        lambda s: len(s) == 1,
        timeout_s=_bounded(ctx, 600),
        interval_s=2.0,
        what=f"the scale-out of {group_name!r} producing one InService instance",
    )
    assert serving == {warm_id}, (
        f"scaling out must promote the pre-initialised warm-pool instance {warm_id!r}, not launch "
        f"a cold one; the group is serving {sorted(serving)!r}"
    )
    assert ever_in_service == {warm_id}, (
        f"no instance other than the warm-pool one may have served; {sorted(ever_in_service)!r} "
        "reached InService"
    )
    promoted_record = [
        i for i in _group(asg, group_name)["Instances"] if i["InstanceId"] == warm_id
    ]
    assert len(promoted_record) == 1, (
        f"the promoted instance must appear exactly once in the group, got {promoted_record!r}"
    )
    assert promoted_record[0]["HealthStatus"] == "Healthy", (
        f"the promoted instance must be Healthy, got {promoted_record[0]!r}"
    )

    promoted_instance = _instance(ec2, warm_id)
    assert promoted_instance["State"]["Name"] == "running", (
        f"the promoted instance must be running, got {promoted_instance['State']!r}"
    )
    assert _root_volume(promoted_instance) == warm_volume, (
        "the promotion must start the very filesystem that was pre-initialised in the pool; the "
        f"root volume changed from {warm_volume!r} to {_root_volume(promoted_instance)!r}, which "
        "means a cold instance was built instead"
    )

    # --- the positive control: the same id now really does serve -------------
    agent = _poll(
        lambda: _agent_record(ssm, warm_id),
        lambda a: a is not None and a.get("PingStatus") == "Online",
        timeout_s=_bounded(ctx, 420),
        interval_s=2.0,
        what=f"the SSM agent on the promoted instance {warm_id!r} coming Online",
    )
    assert agent["PingStatus"] == "Online", f"the promoted guest is {agent!r}"

    def _send_probe():
        try:
            return ssm.send_command(
                InstanceIds=[warm_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": _GUEST_SCRIPT},
                TimeoutSeconds=300,
                Comment="sim2real-behav dasgrefresh promoted probe",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in _THROTTLE + ("InvalidInstanceId",):
                return None
            raise

    sent = _poll(
        _send_probe,
        lambda r: r is not None,
        timeout_s=_bounded(ctx, 300),
        interval_s=2.0,
        what=f"Run Command accepting the in-guest probe for the promoted instance {warm_id!r}",
    )
    command_id = sent["Command"]["CommandId"]
    inv = _poll(
        lambda: _invocation(ssm, command_id, warm_id),
        lambda i: i is not None and i.get("Status") in _TERMINAL_INVOCATION,
        timeout_s=_bounded(ctx, 360),
        interval_s=2.0,
        what=f"the in-guest probe on the promoted instance {warm_id!r}",
    )
    assert inv["Status"] == "Success", (
        f"the in-guest probe on the promoted instance was {inv['Status']!r} "
        f"({inv.get('StatusDetails')!r}), stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"the in-guest probe exited {inv['ResponseCode']!r}: "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    stdout = inv["StandardOutputContent"].strip()
    m = _GUEST_REPORT.search(stdout)
    assert m, (
        f"the promoted guest printed {stdout!r}, not "
        "'iid=<id> init=<epoch> boot=<epoch> initboot=<boot id> bootid=<boot id>'"
    )
    reported_id, init_epoch, boot_epoch = m.group(1), int(m.group(2)), int(m.group(3))
    init_boot_id, boot_id = m.group(4), m.group(5)
    assert reported_id == warm_id, (
        f"the guest reached at {warm_id!r} says its own IMDS instance id is {reported_id!r} — the "
        "command ran on a different host than the API claims"
    )
    assert init_boot_id != boot_id and init_epoch <= boot_epoch, (
        "the promoted guest must have been initialised in an EARLIER boot than the one now serving "
        f"— that is what a warm pool prepares — but the host says it was initialised at "
        f"{init_epoch} in boot {init_boot_id!r} and the serving boot {boot_id!r} began at "
        f"{boot_epoch}, which is what a cold launch produces; the guest printed {stdout!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
