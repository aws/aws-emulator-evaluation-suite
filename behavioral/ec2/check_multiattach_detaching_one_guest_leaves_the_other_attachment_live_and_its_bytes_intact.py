"""multiattach-detaching-one-guest-leaves-the-other-attachment-live-and-its-bytes-intact."""
from __future__ import annotations

import json
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiattach-detaching-one-guest-leaves-the-other-attachment-live-and-its-bytes-intact"
GROUP = 'multiattach-data-plane'
SERVICES = ['ec2']

#: Multi-Attach is an io2/io1 feature on Nitro instances, and m5.large is the smallest m5 that
#: exhibits it. The family is named because the behaviour does not exist on every one.
INSTANCE_TYPE = 'm5.large'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
SSM_CORE_POLICY = 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
#: 4 GiB is io2's minimum, and it differs from the AL2023 root volume (8 GiB), which is how each
#: guest identifies the shared device by size rather than by a device name Nitro does not honour.
SHARED_GIB = 4
SHARED_BYTES = SHARED_GIB * 1024 * 1024 * 1024
SHARED_IOPS = 100
BLOCK = 4096
#: Two disjoint 1 MiB regions, at 1 MiB and 2 MiB, both clear of any superblock either guest writes.
REGION_A_BLOCKS = 256
REGION_B_BLOCKS = 512
REGION_LEN_BLOCKS = 256

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_az(ctx, instance_type=INSTANCE_TYPE):
    """One AZ that is BOTH 'available' and offers the instance type, intersected rather than guessed.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either catalogue alone picks a zone that cannot run the check. An empty
    intersection means this region cannot exercise Multi-Attach at all, which is a finding rather
    than an AZ to guess at.
    """
    ec2 = ctx.client("ec2")
    offered = set()
    for page in ec2.get_paginator("describe_instance_type_offerings").paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}]):
        offered.update(off["Location"] for off in page["InstanceTypeOfferings"])
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r} — this region cannot run a Multi-Attach check"
    )
    return usable[0]


def _network(ctx, scenario, az):
    """A VPC of this check's own, with one public subnet in az and egress to the internet.

    Nothing ambient: a fresh account may have no default VPC. Egress
    exists because the SSM Agent has to reach the Systems Manager endpoints before it can carry the
    commands this check's assertions are read from. The CIDR is random in 10/8 because overlapping
    VPC CIDRs are legal (these VPCs are never peered), so a sibling run cannot collide.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-multiattach-")}]
    second = random.randint(64, 191)
    vpc_id = ec2.create_vpc(CidrBlock=f"10.{second}.0.0/16",
                            TagSpecifications=[{"ResourceType": "vpc", "Tags": kv}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", timeout_s=120, interval_s=3,
                description=f"vpc {vpc_id} reaches 'available'")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": kv}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_igw(ctx, igw_id, vpc_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rtb = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=f"10.{second}.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ctx, subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    return subnet_id


def _delete_subnet(ctx, subnet_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if _code(exc) != "InvalidSubnetID.NotFound":
            raise


def _delete_igw(ctx, igw_id, vpc_id):
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if _code(exc) != "InvalidInternetGatewayID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if _code(exc) != "InvalidVpcID.NotFound":
            raise


def _ssm_instance_profile(ctx):
    """A role the SSM Agent can register with, and an instance profile carrying it.

    Created rather than looked up: "the account already has one" is account configuration, not a
    service contract, and a fresh account has none.
    """
    iam = ctx.client("iam")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_name = ctx.unique_name("sim2real-multiattach-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name,
                                                  PolicyArn=SSM_CORE_POLICY))
    profile_name = ctx.unique_name("sim2real-multiattach-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name))
    _poll_until(lambda: _instance_profile_roles(ctx, profile_name),
                lambda roles: roles == [role_name], timeout_s=120, interval_s=3,
                description=f"instance profile {profile_name} carries role {role_name}")
    return profile_name


def _instance_profile_roles(ctx, profile_name):
    iam = ctx.client("iam")
    try:
        profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    except ClientError as exc:
        if _code(exc) == "NoSuchEntity":
            return []
        raise
    return [r["RoleName"] for r in profile.get("Roles", [])]


def _run_instance(ctx, *, ami, subnet_id, profile_name, scenario, role):
    """Launch ONE instance, tagged in the SAME call that creates it.

    Tagging at launch leaves no window in which an abort strands an untagged instance. RunInstances
    is retried on InvalidParameterValue because a freshly created instance profile reaches the EC2
    control plane later than it reaches IAM.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "role", "Value": role},
          {"Key": "Name", "Value": ctx.unique_name(f"sim2real-multiattach-{role}-")}]
    kwargs = dict(
        ImageId=ami, InstanceType=INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        IamInstanceProfile={"Name": profile_name},
        TagSpecifications=[{"ResourceType": "instance", "Tags": kv},
                           {"ResourceType": "volume", "Tags": kv}],
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            return ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]
        except ClientError as exc:
            if _code(exc) == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _instance_state(ctx, instance_id):
    ec2 = ctx.client("ec2")
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _wait_ssm_online(ctx, instance_id, timeout_s=600):
    """Poll DescribeInstanceInformation until the agent on THIS instance pings Online.

    Paginated and filtered to the one instance id: the account may hold other managed instances.
    """
    ssm = ctx.client("ssm")

    def _ping():
        for page in ssm.get_paginator("describe_instance_information").paginate(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]):
            for item in page.get("InstanceInformationList", []):
                if item.get("InstanceId") == instance_id:
                    return item.get("PingStatus")
        return None

    return _poll_until(_ping, lambda p: p == "Online", timeout_s=timeout_s, interval_s=10,
                       description=f"the SSM Agent on {instance_id} reports PingStatus 'Online'")


def _guest(ctx, instance_id, script, *, marker, timeout_s=420):
    """Run script INSIDE instance_id and return the whitespace fields of its marker line.

    This is the whole point of the check: every claim about what the guest can see is read from
    what the guest itself printed (get_command_invocation's StandardOutputContent), never from a
    DescribeInstances field echoing back what an API call accepted.
    """
    ssm = ctx.client("ssm")
    command_id = ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
    )["Command"]["CommandId"]

    terminal = {"Success", "Cancelled", "TimedOut", "Failed"}

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    result = _poll_until(_invocation, lambda r: r is not None and r["Status"] in terminal,
                         timeout_s=timeout_s, interval_s=5,
                         description=f"command {command_id} reaches a terminal status on "
                                     f"{instance_id}")
    stdout = result.get("StandardOutputContent", "")
    assert result["Status"] == "Success" and result["ResponseCode"] == 0, (
        f"the guest command on {instance_id} ended Status {result['Status']!r} ResponseCode "
        f"{result['ResponseCode']!r}; stdout={stdout[-1200:]!r} "
        f"stderr={result.get('StandardErrorContent', '')[-1200:]!r}"
    )
    for line in reversed(stdout.splitlines()):
        fields = line.strip().split()
        if fields and fields[0] == marker:
            return fields
    raise AssertionError(
        f"the guest on {instance_id} never printed a {marker!r} line; stdout={stdout[-1200:]!r} "
        f"stderr={result.get('StandardErrorContent', '')[-1200:]!r}"
    )


_FIND_SHARED = (
    "DEV=\n"
    "for i in $(seq 1 60); do\n"
    f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {SHARED_BYTES} {{print $1; exit}}')\n"
    '  [ -n "$DEV" ] && break\n'
    "  sleep 2\n"
    "done\n"
    'if [ -z "$DEV" ]; then echo "MA-NODEV"; exit 1; fi\n'
    "DEV=/dev/$DEV\n"
)


def _write_script(nonce, offset_blocks, marker):
    """Write 1 MiB of nonce-derived bytes into one region with O_DIRECT, then read it back.

    Raw block IO, deliberately: Multi-Attach gives two machines concurrent access to the same
    blocks and AWS guarantees the block layer, not filesystem coherence — a filesystem assertion
    here would fail a faithful implementation. O_DIRECT on both sides takes the page cache out,
    which is what makes each read evidence about the volume rather than about the guest's own RAM.
    """
    return (
        "set -u\n"
        + _FIND_SHARED +
        'DEVB=$(blockdev --getsize64 "$DEV")\n'
        f'yes "{nonce}" | head -c {REGION_LEN_BLOCKS * BLOCK} > /tmp/pat-{nonce}\n'
        f'dd if=/tmp/pat-{nonce} of="$DEV" bs={BLOCK} seek={offset_blocks} '
        f"count={REGION_LEN_BLOCKS} oflag=direct conv=notrunc status=none\n"
        "sync\n"
        f'dd if="$DEV" of=/tmp/back-{nonce} bs={BLOCK} skip={offset_blocks} '
        f"count={REGION_LEN_BLOCKS} iflag=direct status=none\n"
        f"PSHA=$(sha256sum /tmp/pat-{nonce} | cut -d' ' -f1)\n"
        f"BSHA=$(sha256sum /tmp/back-{nonce} | cut -d' ' -f1)\n"
        f'echo "{marker} $DEV $DEVB $PSHA $BSHA"\n'
    )


def _read_script(nonce, offset_blocks, marker):
    """Poll one region with O_DIRECT until the other machine's bytes appear, then report them."""
    return (
        "set -u\n"
        + _FIND_SHARED +
        'DEVB=$(blockdev --getsize64 "$DEV")\n'
        "for i in $(seq 1 60); do\n"
        f'  dd if="$DEV" of=/tmp/got-{nonce} bs={BLOCK} skip={offset_blocks} '
        f"count={REGION_LEN_BLOCKS} iflag=direct status=none\n"
        f'  if grep -qa "{nonce}" /tmp/got-{nonce}; then\n'
        f"    SHA=$(sha256sum /tmp/got-{nonce} | cut -d' ' -f1)\n"
        f'    echo "{marker} $DEV $DEVB $SHA"\n'
        "    exit 0\n"
        "  fi\n"
        "  sleep 5\n"
        "done\n"
        f'echo "MA-NOPATTERN $DEV $DEVB"\n'
        "exit 1\n"
    )


def _read_two_regions_script(nonce_one, nonce_two, marker):
    """Write region two, then report BOTH regions' sha256 as read back off the device."""
    return (
        "set -u\n"
        + _FIND_SHARED +
        'DEVB=$(blockdev --getsize64 "$DEV")\n'
        f'yes "{nonce_two}" | head -c {REGION_LEN_BLOCKS * BLOCK} > /tmp/pat2\n'
        f'dd if=/tmp/pat2 of="$DEV" bs={BLOCK} seek={REGION_B_BLOCKS} '
        f"count={REGION_LEN_BLOCKS} oflag=direct conv=notrunc status=none\n"
        "sync\n"
        f'dd if="$DEV" of=/tmp/one bs={BLOCK} skip={REGION_A_BLOCKS} '
        f"count={REGION_LEN_BLOCKS} iflag=direct status=none\n"
        f'dd if="$DEV" of=/tmp/two bs={BLOCK} skip={REGION_B_BLOCKS} '
        f"count={REGION_LEN_BLOCKS} iflag=direct status=none\n"
        f'grep -qa "{nonce_one}" /tmp/one || {{ echo "MA-REGION1-LOST"; exit 1; }}\n'
        f'grep -qa "{nonce_two}" /tmp/two || {{ echo "MA-REGION2-LOST"; exit 1; }}\n'
        "ONE=$(sha256sum /tmp/one | cut -d' ' -f1)\n"
        "TWO=$(sha256sum /tmp/two | cut -d' ' -f1)\n"
        "PAT2=$(sha256sum /tmp/pat2 | cut -d' ' -f1)\n"
        f'echo "{marker} $DEV $DEVB $ONE $TWO $PAT2"\n'
    )


def _device_gone_script(marker):
    """Poll from inside the guest until NO block device of the shared volume's size is present."""
    return (
        "set -u\n"
        "for i in $(seq 1 60); do\n"
        f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {SHARED_BYTES} {{print $1; exit}}')\n"
        f'  if [ -z "$DEV" ]; then echo "{marker} absent"; exit 0; fi\n'
        "  sleep 5\n"
        "done\n"
        f'echo "{marker} $DEV"\n'
    )


def _describe_volume(ctx, volume_id):
    """DescribeVolumes for one id, paginated: the account may hold other volumes."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_all_and_wait(ctx, volume_id, timeout_s=300):
    """Detach EVERY attachment — a Multi-Attach volume has more than one, and delete refuses while
    any of them survives."""
    ec2 = ctx.client("ec2")
    try:
        for att in _describe_volume(ctx, volume_id)["Attachments"]:
            try:
                ec2.detach_volume(VolumeId=volume_id, InstanceId=att["InstanceId"], Force=True)
            except ClientError as exc:
                if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound",
                                      "InvalidAttachment.NotFound"):
                    raise
    except (ClientError, AssertionError):
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if _describe_volume(ctx, volume_id)["State"] == "available":
                return
        except (ClientError, AssertionError):
            return
        time.sleep(5)


def _delete_volume_when_free(ctx, volume_id, timeout_s=120):
    """Delete the volume, retrying only VolumeInUse while its detaches finish."""
    ec2 = ctx.client("ec2")
    _detach_all_and_wait(ctx, volume_id)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            if _code(exc) != "VolumeInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


# ===== end helpers =====


@tags("cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """The two attachments of one Multi-Attach io2 volume are independent: bytes guest A writes read back
    identically inside guest B, and detaching A alone removes A's block device while B keeps a live
    device that still holds A's bytes and takes new writes, all read from inside the guests."""
    ec2 = ctx.client("ec2")
    scenario = "multiattach-detach-independence"
    nonce_one = "manonce1-" + uuid.uuid4().hex
    nonce_two = "manonce2-" + uuid.uuid4().hex

    ami = _ssm_ami(ctx)
    az = _usable_az(ctx)
    subnet_id = _network(ctx, scenario, az)
    profile_name = _ssm_instance_profile(ctx)

    a_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, profile_name=profile_name,
                         scenario=scenario, role="a")
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, profile_name=profile_name,
                         scenario=scenario, role="b")
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))

    shared = ec2.create_volume(
        AvailabilityZone=az, Size=SHARED_GIB, VolumeType="io2", Iops=SHARED_IOPS,
        MultiAttachEnabled=True,
        TagSpecifications=[{"ResourceType": "volume", "Tags": [
            {"Key": "sim2real", "Value": scenario},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-multiattach-vol-")}]}])
    shared_id = shared["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, shared_id))
    assert shared.get("MultiAttachEnabled") is True, (
        f"the io2 volume {shared_id} reported MultiAttachEnabled "
        f"{shared.get('MultiAttachEnabled')!r} at creation, expected True — without the flag the "
        f"second attach below would be refused and this check would grade nothing"
    )

    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance A {a_id} reaches 'running'")
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance B {b_id} reaches 'running'")
    _wait_ssm_online(ctx, a_id)
    _wait_ssm_online(ctx, b_id)
    _poll_until(lambda: _describe_volume(ctx, shared_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"Multi-Attach volume {shared_id} reaches 'available'")

    # --- both attachments live at once: the state the guests are about to disagree or agree about
    ec2.attach_volume(VolumeId=shared_id, InstanceId=a_id, Device="/dev/sdf")
    ec2.attach_volume(VolumeId=shared_id, InstanceId=b_id, Device="/dev/sdf")
    both = _poll_until(
        lambda: _describe_volume(ctx, shared_id)["Attachments"],
        lambda at: len(at) == 2 and all(x["State"] == "attached" for x in at),
        timeout_s=300, interval_s=5,
        description=f"Multi-Attach volume {shared_id} reaches 'attached' on BOTH instances")
    assert {x["InstanceId"] for x in both} == {a_id, b_id}, (
        f"the Multi-Attach volume is attached to {[x['InstanceId'] for x in both]!r}, expected both "
        f"A {a_id!r} and B {b_id!r}"
    )

    # --- A writes region one from inside the guest and reads its own bytes back off the device ---
    a_fields = _guest(ctx, a_id, _write_script(nonce_one, REGION_A_BLOCKS, "MA-A-WROTE"),
                      marker="MA-A-WROTE")
    assert len(a_fields) == 5, (
        f"A's report must carry the device, its size, the sha256 written and the sha256 read back, "
        f"got {a_fields!r}"
    )
    a_dev, a_devbytes, a_pattern_sha, a_readback_sha = (
        a_fields[1], int(a_fields[2]), a_fields[3], a_fields[4])
    assert a_devbytes == SHARED_BYTES, (
        f"the device guest A found at {a_dev!r} reports {a_devbytes} bytes, expected {SHARED_BYTES} "
        f"— A is not looking at the Multi-Attach volume"
    )
    assert a_readback_sha == a_pattern_sha, (
        f"guest A read {a_readback_sha!r} back from the region it wrote as {a_pattern_sha!r} — the "
        f"volume did not return A's own bytes"
    )

    # --- and B, attached to the same volume at the same time, reads exactly those bytes ---
    b_fields = _guest(ctx, b_id, _read_script(nonce_one, REGION_A_BLOCKS, "MA-B-READ"),
                      marker="MA-B-READ")
    assert len(b_fields) == 4, (
        f"B's report must carry the device, its size and the sha256 it read, got {b_fields!r}"
    )
    b_dev, b_devbytes, b_sha = b_fields[1], int(b_fields[2]), b_fields[3]
    assert b_devbytes == SHARED_BYTES, (
        f"the device guest B found at {b_dev!r} reports {b_devbytes} bytes, expected {SHARED_BYTES}"
    )
    assert b_sha == a_readback_sha, (
        f"guest B read {b_sha!r} from the region where guest A wrote {a_readback_sha!r} — the two "
        f"attachments are not the same blocks"
    )

    # --- break exactly one attachment: A is detached, B is left alone ---
    ec2.detach_volume(VolumeId=shared_id, InstanceId=a_id)
    remaining = _poll_until(
        lambda: _describe_volume(ctx, shared_id)["Attachments"],
        lambda at: len(at) == 1 and at[0]["State"] == "attached",
        timeout_s=300, interval_s=5,
        description=f"volume {shared_id} is left with exactly one 'attached' attachment")
    assert remaining[0]["InstanceId"] == b_id, (
        f"after detaching A the surviving attachment is {remaining[0]['InstanceId']!r}, expected B "
        f"{b_id!r}"
    )
    still_in_use = _describe_volume(ctx, shared_id)
    assert still_in_use["State"] == "in-use", (
        f"detaching one of two attachments moved {shared_id} to state "
        f"{still_in_use['State']!r}, expected 'in-use' — B still holds it"
    )

    # --- the detach reached A's kernel: no device of that size remains, read from inside A ---
    gone_fields = _guest(ctx, a_id, _device_gone_script("MA-A-DEV"), marker="MA-A-DEV")
    assert gone_fields[1] == "absent", (
        f"guest A still reports a block device of the shared volume's size ({gone_fields[1]!r}) "
        f"after DescribeVolumes stopped listing A's attachment — the detach did not reach the guest"
    )

    # --- and B's attachment is still live: A's bytes intact, and B's own new write lands ---
    b2_fields = _guest(ctx, b_id, _read_two_regions_script(nonce_one, nonce_two, "MA-B-AFTER"),
                       marker="MA-B-AFTER")
    assert len(b2_fields) == 6, (
        f"B's post-detach report must carry the device, its size, both regions' sha256 and the "
        f"sha256 it wrote, got {b2_fields!r}"
    )
    b2_dev, b2_devbytes, region_one_sha, region_two_sha, b2_pattern_sha = (
        b2_fields[1], int(b2_fields[2]), b2_fields[3], b2_fields[4], b2_fields[5])
    assert b2_devbytes == SHARED_BYTES, (
        f"after A's detach the device guest B found at {b2_dev!r} reports {b2_devbytes} bytes, "
        f"expected {SHARED_BYTES} — B's attachment did not survive its sibling's detach"
    )
    assert region_one_sha == a_readback_sha, (
        f"after A was detached guest B reads {region_one_sha!r} where A had written "
        f"{a_readback_sha!r} — releasing one attachment discarded the other's data"
    )
    assert region_two_sha == b2_pattern_sha, (
        f"guest B read {region_two_sha!r} back from the region it wrote as {b2_pattern_sha!r} after "
        f"A's detach — the surviving attachment is listed as attached but no longer writable"
    )


# A resource in this VPC deletes asynchronously, so its ENIs can hold the subnet or VPC and an
# immediate delete fails with DependencyViolation. Wait (bounded) for the ENIs to go, retry that one
# code in the same window, then raise naming the ENIs still attached; every other error propagates.
# The window is shared by all of one check's network deletes and fits the 900 s cleanup budget.
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
