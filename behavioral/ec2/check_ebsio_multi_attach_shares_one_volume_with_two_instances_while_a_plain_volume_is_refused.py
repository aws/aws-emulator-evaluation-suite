"""ebsio-multi-attach-shares-one-volume-with-two-instances-while-a-plain-volume-is-refused."""
from __future__ import annotations

import json
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ebsio-multi-attach-shares-one-volume-with-two-instances-while-a-plain-volume-is-refused"
GROUP = 'ebsio-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
#: The break: an ordinary gp3 volume, 1 GiB.
SINGLE_GIB = 1
SINGLE_BYTES = SINGLE_GIB * 1024 * 1024 * 1024
#: The positive control: io2 is the only volume type that takes MultiAttachEnabled, and 4 GiB is
#: its minimum. Both sizes differ from each other and from the AL2023 root volume (8 GiB), which is
#: how each guest identifies its device by size rather than by a name Nitro does not honour.
SHARED_GIB = 4
SHARED_BYTES = SHARED_GIB * 1024 * 1024 * 1024
SHARED_IOPS = 100
#: The shared region: 1 MiB at a 1 MiB offset, clear of any superblock either guest might write.
REGION_OFFSET_BLOCKS = 256
REGION_BLOCKS = 256
BLOCK = 4096
ERR_VOLUME_IN_USE = 'VolumeInUse'


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The (code, message) of the AWS error fn raises, or a RAISE if it unexpectedly succeeds.

    Never returns a falsy sentinel, so accepting input AWS rejects cannot read as a code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, ctx, interval_s=2.0, description="condition"):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s:.0f}s. Last observation: {last!r}"
    )


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    """AZs that are BOTH available and offer the instance type, intersected rather than guessed.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either alone picks a zone that cannot run the check.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable


def _network(ctx, scenario, azs):
    """A VPC of this check's own, with one subnet per requested AZ and egress to the internet.

    A fresh account may have no default VPC. The CIDR is random in 10/8 so sibling runs do not
    collide, and egress exists because cloud-init needs the network before running the user-data.
    """
    ec2 = ctx.client("ec2")
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-ebsio-")}]
    second = random.randint(64, 191)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{second}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": kv}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    _poll_until(lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
                lambda s: s == "available", timeout_s=120, interval_s=2, ctx=ctx,
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

    subnets = {}
    for i, az in enumerate(azs, start=1):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.{second}.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": kv}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _delete_subnet(ctx, s))
        ec2.modify_subnet_attribute(SubnetId=subnet_id,
                                    MapPublicIpOnLaunch={"Value": True})
        subnets[az] = subnet_id
    return vpc_id, subnets


def _delete_subnet(ctx, subnet_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidSubnetID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"subnet {subnet_id} was not deleted: {last!r}")


def _delete_igw(ctx, igw_id, vpc_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        except ClientError as exc:
            if _code(exc) not in ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"):
                last = exc
                time.sleep(2)
                continue
        try:
            _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidInternetGatewayID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"internet gateway {igw_id} was not deleted: {last!r}")


def _delete_vpc(ctx, vpc_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVpcID.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"vpc {vpc_id} was not deleted: {last!r}")


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE):
    """Launch ONE instance, tagged in the same call that creates it.

    An instance tagged in a follow-up call that an abort skips would be untagged and never reaped.
    """
    kv = [{"Key": "sim2real", "Value": scenario},
          {"Key": "Name", "Value": ctx.unique_name("sim2real-ebsio-")}]
    return ctx.client("ec2").run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": kv},
            {"ResourceType": "volume", "Tags": kv},
        ],
    )["Instances"][0]


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
    state = None
    while time.monotonic() < deadline:
        state = _instance_state(ctx, instance_id)
        if state in ("terminated", "__gone__"):
            return
        time.sleep(2)
    raise RuntimeError(f"instance {instance_id} was not terminated: still {state!r} after {timeout_s}s")


def _create_volume(ctx, az, scenario, *, size_gib, **kw):
    return ctx.client("ec2").create_volume(
        AvailabilityZone=az, Size=size_gib,
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-ebsio-")}]}],
        **kw,
    )


def _describe_volume(ctx, volume_id):
    """DescribeVolumes for one id, paginated."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_all_and_wait(ctx, volume_id, timeout_s=300):
    """Detach EVERY attachment — a multi-attach volume has more than one and delete refuses while
    any survives."""
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
        time.sleep(2)


def _delete_volume_when_free(ctx, volume_id, timeout_s=300):
    """Detach everything, then delete on a bounded retry: a volume cannot be deleted mid-detach."""
    ec2 = ctx.client("ec2")
    _detach_all_and_wait(ctx, volume_id)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"volume {volume_id} was not deleted: {last!r}")


def _console(ctx, instance_id):
    """The instance's serial console text AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro types. Not decoded here: botocore's decode_console_output
    handler already base64-decodes in place, so decoding again turns the guest's words into noise.
    """
    return ctx.client("ec2").get_console_output(
        InstanceId=instance_id, Latest=True).get("Output") or ""


def _console_fields(text, marker):
    """Whitespace fields of the last console line containing marker, sliced AT the marker.

    /dev/console is shared with the login getty, which prepends 'ip-… login:' to whatever the
    guest writes, so any parser that indexes from either end of the line reads the getty instead.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


_FIND_SHARED = (
    "DEV=\n"
    "for i in $(seq 1 160); do\n"
    f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {SHARED_BYTES} {{print $1; exit}}')\n"
    '  [ -n "$DEV" ] && break\n'
    "  sleep 3\n"
    "done\n"
    'if [ -z "$DEV" ]; then echo "SIM2REAL-NODEV" > /dev/console; exit 1; fi\n'
    "DEV=/dev/$DEV\n"
)


def _writer_script(nonce):
    """Write 1 MiB of nonce-derived bytes into the shared region with O_DIRECT, then read it back.

    Raw block IO: AWS guarantees the block layer under Multi-Attach, not filesystem coherence, and
    O_DIRECT keeps the page cache out of the evidence.
    """
    return (
        "#!/bin/bash\n"
        + _FIND_SHARED +
        'DEVB=$(blockdev --getsize64 "$DEV")\n'
        f'yes "{nonce}" | head -c {REGION_BLOCKS * BLOCK} > /tmp/pat\n'
        f'dd if=/tmp/pat of="$DEV" bs={BLOCK} seek={REGION_OFFSET_BLOCKS} count={REGION_BLOCKS} '
        "oflag=direct conv=notrunc status=none\n"
        "sync\n"
        f'dd if="$DEV" of=/tmp/back bs={BLOCK} skip={REGION_OFFSET_BLOCKS} count={REGION_BLOCKS} '
        "iflag=direct status=none\n"
        "PSHA=$(sha256sum /tmp/pat | cut -d' ' -f1)\n"
        "BSHA=$(sha256sum /tmp/back | cut -d' ' -f1)\n"
        f'echo "SIM2REAL-WROTE {nonce} $BSHA $DEVB $PSHA" > /dev/console\n'
    )


def _reader_script(nonce):
    """Poll the shared region with O_DIRECT until the writer's bytes appear, then report them.

    The single-attach volume's absence is sampled when the shared device appears, strictly after
    the refused attach.
    """
    return (
        "#!/bin/bash\n"
        + _FIND_SHARED +
        'DEVB=$(blockdev --getsize64 "$DEV")\n'
        f"SINGLE=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {SINGLE_BYTES} {{print $1; exit}}')\n"
        '[ -z "$SINGLE" ] && SINGLE=absent\n'
        "for i in $(seq 1 600); do\n"
        f'  dd if="$DEV" of=/tmp/got bs={BLOCK} skip={REGION_OFFSET_BLOCKS} '
        f"count={REGION_BLOCKS} iflag=direct status=none\n"
        f'  if grep -qa "{nonce}" /tmp/got; then\n'
        "    SHA=$(sha256sum /tmp/got | cut -d' ' -f1)\n"
        f'    echo "SIM2REAL-READ {nonce} $SHA $DEVB $SINGLE" > /dev/console\n'
        "    exit 0\n"
        "  fi\n"
        "  sleep 1\n"
        "done\n"
        'echo "SIM2REAL-NOPATTERN $DEVB $SINGLE" > /dev/console\n'
        "exit 1\n"
    )


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A second concurrent AttachVolume fails with VolumeInUse for an ordinary volume but succeeds
    for a Multi-Attach io2 volume, and bytes one guest writes read back identically on the other.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volumes-multi.html
    """
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ebsio-multi-attach"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    _vpc_id, subnets = _network(ctx, scenario, [az])

    # Both instances up front: each guest blocks on its device appearing, so the boots overlap.
    a_id = _run_instance(ctx, ami=ami, subnet_id=subnets[az], scenario=scenario,
                         user_data=_writer_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnets[az], scenario=scenario,
                         user_data=_reader_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))

    # --- the break: an ordinary gp3 volume, attached to A, refused to B ---
    single = _create_volume(ctx, az, scenario, size_gib=SINGLE_GIB, VolumeType="gp3")
    single_id = single["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, single_id))
    assert single.get("MultiAttachEnabled") is False, (
        f"a gp3 volume reported MultiAttachEnabled {single.get('MultiAttachEnabled')!r} at "
        f"creation, expected False — the break and the control would not differ"
    )
    _poll_until(lambda: _describe_volume(ctx, single_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=2, ctx=ctx,
                description=f"single-attach volume {single_id} reaches 'available'")

    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=600, interval_s=2, ctx=ctx,
                description=f"instance A {a_id} reaches 'running'")
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=600, interval_s=2, ctx=ctx,
                description=f"instance B {b_id} reaches 'running'")

    ec2.attach_volume(VolumeId=single_id, InstanceId=a_id, Device="/dev/sdf")
    _poll_until(lambda: _describe_volume(ctx, single_id)["Attachments"],
                lambda at: bool(at) and at[0]["State"] == "attached",
                timeout_s=300, interval_s=2, ctx=ctx,
                description=f"single-attach volume {single_id} attaches to A {a_id}")

    code, message = _error(lambda: ec2.attach_volume(VolumeId=single_id, InstanceId=b_id,
                                                 Device="/dev/sdh"))
    assert code == ERR_VOLUME_IN_USE, (
        f"attaching the already-attached single-attach volume {single_id} to B {b_id} was refused "
        f"with {code!r}, expected exactly {ERR_VOLUME_IN_USE!r}"
    )
    assert message == f"{single_id} is already attached to an instance", (
        f"unexpected VolumeInUse message: {message!r}"
    )
    refused = _describe_volume(ctx, single_id)
    assert [a["InstanceId"] for a in refused["Attachments"]] == [a_id], (
        f"after the refusal the single-attach volume's attachment set is "
        f"{refused['Attachments']!r}, expected exactly A {a_id!r}"
    )
    assert refused["State"] == "in-use", (
        f"the refused attach changed the volume's state to {refused['State']!r}, expected 'in-use'"
    )

    # --- the control: the same second attach, with MultiAttachEnabled the only difference ---
    shared = _create_volume(ctx, az, scenario, size_gib=SHARED_GIB, VolumeType="io2",
                            Iops=SHARED_IOPS, MultiAttachEnabled=True)
    shared_id = shared["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, shared_id))
    assert shared.get("MultiAttachEnabled") is True, (
        f"the io2 volume reported MultiAttachEnabled {shared.get('MultiAttachEnabled')!r} at "
        f"creation, expected True"
    )
    _poll_until(lambda: _describe_volume(ctx, shared_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=2, ctx=ctx,
                description=f"multi-attach volume {shared_id} reaches 'available'")

    ec2.attach_volume(VolumeId=shared_id, InstanceId=a_id, Device="/dev/sdg")
    ec2.attach_volume(VolumeId=shared_id, InstanceId=b_id, Device="/dev/sdg")
    both = _poll_until(
        lambda: _describe_volume(ctx, shared_id)["Attachments"],
        lambda at: len(at) == 2 and all(x["State"] == "attached" for x in at),
        timeout_s=300, interval_s=2, ctx=ctx,
        description=f"multi-attach volume {shared_id} reaches 'attached' on BOTH instances")
    assert {a["InstanceId"] for a in both} == {a_id, b_id}, (
        f"the multi-attach volume is attached to {[a['InstanceId'] for a in both]!r}, expected "
        f"both A {a_id!r} and B {b_id!r}"
    )
    described_shared = _describe_volume(ctx, shared_id)
    assert described_shared["MultiAttachEnabled"] is True, (
        f"DescribeVolumes reports MultiAttachEnabled "
        f"{described_shared['MultiAttachEnabled']!r} for {shared_id}, expected True"
    )

    # --- A writes the shared region and reads its own bytes back off the device ---
    a_text = _poll_until(lambda: _console(ctx, a_id),
                         lambda t: "SIM2REAL-WROTE" in t or "SIM2REAL-NODEV" in t,
                         timeout_s=900, interval_s=2, ctx=ctx,
                         description=f"guest A {a_id} reports what it wrote to {shared_id}")
    a_fields = _console_fields(a_text, "SIM2REAL-WROTE")
    assert a_fields is not None, (
        f"guest A never reported a write — it said {_console_fields(a_text, 'SIM2REAL-')!r}; last "
        f"2KB of console was {a_text[-2048:]!r}"
    )
    assert len(a_fields) >= 5, (
        f"A's report must carry a nonce, the sha256 read back, the device size and the sha256 "
        f"written, got {a_fields!r}"
    )
    a_nonce, a_sha, a_devbytes, a_pattern_sha = (
        a_fields[1], a_fields[2], int(a_fields[3]), a_fields[4])
    assert a_nonce == nonce, f"guest A echoed nonce {a_nonce!r}, expected {nonce!r}"
    assert a_devbytes == SHARED_BYTES, (
        f"guest A's shared device reports {a_devbytes} bytes, expected {SHARED_BYTES}"
    )
    assert a_sha == a_pattern_sha, (
        f"guest A read back {a_sha!r} from the region it wrote as {a_pattern_sha!r} — the volume "
        f"did not return A's own bytes"
    )

    # --- and B, attached to the same volume at the same time, reads exactly those bytes ---
    b_text = _poll_until(lambda: _console(ctx, b_id),
                         lambda t: "SIM2REAL-READ" in t or "SIM2REAL-NOPATTERN" in t
                         or "SIM2REAL-NODEV" in t,
                         timeout_s=900, interval_s=2, ctx=ctx,
                         description=f"guest B {b_id} reports what it read from {shared_id}")
    b_fields = _console_fields(b_text, "SIM2REAL-READ")
    assert b_fields is not None, (
        f"guest B never read A's bytes off the shared volume — it said "
        f"{_console_fields(b_text, 'SIM2REAL-NOPATTERN') or _console_fields(b_text, 'SIM2REAL-')!r}"
        f"; last 2KB of console was {b_text[-2048:]!r}"
    )
    assert len(b_fields) >= 5, (
        f"B's report must carry a nonce, a sha256, the device size and the single-attach device it "
        f"saw, got {b_fields!r}"
    )
    b_nonce, b_sha, b_devbytes, b_single = (
        b_fields[1], b_fields[2], int(b_fields[3]), b_fields[4])
    assert b_nonce == nonce, f"guest B echoed nonce {b_nonce!r}, expected {nonce!r}"
    assert b_devbytes == SHARED_BYTES, (
        f"guest B's shared device reports {b_devbytes} bytes, expected {SHARED_BYTES}"
    )
    assert b_sha == a_sha, (
        f"guest B read {b_sha!r} from the shared region where guest A wrote {a_sha!r} — the two "
        f"attachments are not the same blocks"
    )
    assert b_single == "absent", (
        f"guest B reports a block device of the single-attach volume's size ({b_single!r}) — the "
        f"attach that was refused with {ERR_VOLUME_IN_USE} took effect in the guest anyway"
    )


# Resources in this VPC delete asynchronously and leave ENIs behind for a while, so an immediate
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for
# the ENIs to go, retry DependencyViolation in the same window, then fail naming the ENIs left.
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
