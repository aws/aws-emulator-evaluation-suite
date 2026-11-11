"""dvolgrow-capacity-added-by-modify-volume-is-unusable-until-resize2fs."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dvolgrow-capacity-added-by-modify-volume-is-unusable-until-resize2fs"
GROUP = 'dvolgrow-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"

#: 1 GiB start, 4 GiB target. The start size is deliberately distinct from the AL2023 root volume
#: (8 GiB) so the GUEST can identify the data disk by its exact byte size rather than by a device
#: path Nitro does not honour.
_START_GIB = 1
_TARGET_GIB = 4
_START_BYTES = _START_GIB * 1024 * 1024 * 1024
_TARGET_BYTES = _TARGET_GIB * 1024 * 1024 * 1024
#: 1 MiB of nonce-derived payload, written BEFORE the grow. A canned or truncating implementation
#: cannot reproduce its digest.
_PAYLOAD_BYTES = 1024 * 1024
#: The write that decides both legs: 1500 MiB cannot fit in a 1 GiB filesystem, and does fit in a
#: 4 GiB one. It must fail with ENOSPC before resize2fs and succeed in full after it.
_BEYOND_MIB = 1500
_BEYOND_BYTES = _BEYOND_MIB * 1024 * 1024

# ===== helpers =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
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


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded: a DependencyViolation that never clears is a leak to declare, not a loop to sit in.
    """
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                              "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                              "InvalidAssociationID.NotFound", "InvalidVolume.NotFound",
                              "Gateway.NotAttached"):
                return None
            raise


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH reported available AND offers the instance type, intersected.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either catalogue alone picks a zone that cannot run this check. An empty
    intersection is a finding about the region, not an AZ to guess at.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r} and "
        f"available zones were {sorted(available)!r}"
    )
    return usable[0]


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    Deliberately not the account's default VPC: a fresh account need not have one.
    The SSM agent needs egress to reach its endpoint, so the subnet gets an internet
    gateway, a default route and auto-assigned public addressing. The CIDR is randomised in 10/8
    because overlapping VPC CIDRs are legal (these VPCs are never peered) and a sibling run in the
    same account must not collide. Every object is tagged in the call that creates it — an untagged
    VPC object cannot be found for cleanup.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name",
                                               "Value": ctx.unique_name("sim2real-dvolgrow-")}]}]

    second = random.randint(64, 191)
    vpc = ec2.create_vpc(CidrBlock=f"10.{second}.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.{second}.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return subnet


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-dvg-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav online volume grow role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(12):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI and the instance
    profile association only clear at the end, and the subnet/VPC teardown registered earlier
    cannot proceed until they do."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _describe_volume(ec2, volume_id):
    """DescribeVolumes for one id, paginated."""
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_and_delete_volume(ec2, volume_id, timeout_s=300):
    """Detach if attached, wait for 'available', then delete.

    Self-sufficient rather than order-dependent: the volume is created after the instance, so LIFO
    runs this BEFORE the terminate, and a delete of an in-use volume is refused.
    """
    def _vol():
        try:
            return _describe_volume(ec2, volume_id)
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return None
            raise
        except AssertionError:
            return None

    vol = _vol()
    if vol is None:
        return
    if vol.get("Attachments"):
        try:
            ec2.detach_volume(VolumeId=volume_id, Force=True)
        except ClientError as exc:
            if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound"):
                raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vol = _vol()
        if vol is None:
            return
        if vol["State"] == "available":
            break
        time.sleep(5)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=600):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects
    SendCommand with InvalidInstanceId until its agent has registered, so retrying that call polls
    an observable condition instead of sleeping a guessed interval. A host that never accepts a
    command is a FAIL — 'the machine never came up' is a fidelity defect, not an environment
    limitation.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav online volume grow",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=run_timeout_s, interval_s=5.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: the guest script exited {inv['ResponseCode']!r}; "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _report(stdout, marker):
    """The `key=value` fields of the last line starting with `marker`, as a dict.

    The guest emits one machine-readable line per phase, so nothing here depends on the order or
    the wording of the rest of its output.
    """
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith(marker):
            continue
        out = {}
        for field in line[len(marker):].split():
            if "=" in field:
                k, _, v = field.partition("=")
                out[k] = v
        return out
    return None


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """ModifyVolume grows the block device under a mounted filesystem, but the added capacity is unusable
    until the guest runs resize2fs: the same 1500 MiB write fails ENOSPC before it and lands in full after
    it, with the pre-grow payload digest unchanged throughout."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dvolgrow-resize2fs-boundary"
    nonce = ctx.unique_name("sim2real-nonce-")

    # --- everything decidable, before anything is created ---------------------
    az = _usable_az(ec2)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one instance, tagged in the call that creates it ---------------------
    tag_spec = [
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": profile},
                                      {"Key": "sim2real", "Value": scenario}]}
        for rt in ("instance", "volume")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            IamInstanceProfile={"Name": profile}, TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # --- a 1 GiB gp3 data volume, attached to that running instance -----------
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_START_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-dvolgrow-")}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: _describe_volume(ec2, volume_id)["State"], lambda s: s == "available",
          timeout_s=300, interval_s=3.0, what=f"volume {volume_id} reaching 'available'")
    created = _describe_volume(ec2, volume_id)
    assert created["Size"] == _START_GIB, (
        f"the volume was created at Size {created['Size']!r}, expected {_START_GIB!r}"
    )
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    attachments = _poll(lambda: _describe_volume(ec2, volume_id)["Attachments"],
                        lambda a: bool(a) and a[0]["State"] == "attached",
                        timeout_s=300, interval_s=3.0,
                        what=f"volume {volume_id} reaching 'attached' on {instance_id}")
    assert attachments[0]["InstanceId"] == instance_id, (
        f"the attachment names {attachments[0]['InstanceId']!r}, expected {instance_id!r}"
    )

    # --- phase 1: the guest makes a filesystem and writes the payload ---------
    # The device is found by exact byte size, never by path: Nitro presents EBS as /dev/nvme?n1 in
    # an order that is not the attachment order, so '/dev/sdf' is only a request. Later phases find
    # the same device through the mount point, because its size is the thing that changes.
    provision = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        "DEV=",
        "for i in $(seq 1 60); do",
        f"  DEV=$(lsblk -dn -b -o NAME,SIZE | awk -v w={_START_BYTES} '$2==w {{print $1; exit}}')",
        '  [ -n "$DEV" ] && break',
        "  sleep 2",
        "done",
        'if [ -z "$DEV" ]; then echo "NO-DATA-DEVICE"; lsblk -dn -b -o NAME,SIZE; exit 1; fi',
        'DEV=/dev/$DEV',
        'mkfs.ext4 -qF "$DEV"',
        "mkdir -p /mnt/grow",
        'mount "$DEV" /mnt/grow',
        f'yes "{nonce}" | head -c {_PAYLOAD_BYTES} > /mnt/grow/payload.bin',
        "sync",
        'echo "SIM2REAL-BASE dev=$DEV bytes=$(blockdev --getsize64 $DEV)'
        ' fs=$(df -B1 --output=size /mnt/grow | tail -1 | tr -d \' \')'
        ' sha=$(sha256sum /mnt/grow/payload.bin | cut -d\' \' -f1)'
        ' payload=$(stat -c %s /mnt/grow/payload.bin)"',
    ]
    base = _report(_run_guest(ssm, instance_id, provision,
                              "provisioning the filesystem and writing the payload"),
                   "SIM2REAL-BASE")
    assert base is not None and {"dev", "bytes", "fs", "sha", "payload"} <= set(base), (
        f"the guest did not report a provisioned filesystem, it reported {base!r}"
    )
    assert int(base["payload"]) == _PAYLOAD_BYTES, (
        f"the guest wrote {base['payload']!r} bytes of payload, expected {_PAYLOAD_BYTES!r}"
    )
    assert len(base["sha"]) == 64, f"the guest reported a malformed sha256 {base['sha']!r}"
    assert int(base["bytes"]) == _START_BYTES, (
        f"the guest's block device is {base['bytes']!r} bytes, expected {_START_BYTES!r} — it is "
        f"not looking at the volume this check attached"
    )
    sha_before, fs_before = base["sha"], int(base["fs"])
    assert 0 < fs_before <= _START_BYTES, (
        f"the filesystem reports {fs_before} bytes on a {_START_BYTES}-byte device, which is "
        f"impossible"
    )

    # --- the grow itself, while that filesystem stays mounted and in use ------
    ec2.modify_volume(VolumeId=volume_id, Size=_TARGET_GIB)
    mod = _poll(lambda: ec2.describe_volumes_modifications(
                    VolumeIds=[volume_id])["VolumesModifications"][0],
                lambda m: m["ModificationState"] == "completed",
                timeout_s=900, interval_s=5.0,
                what=f"the modification of {volume_id} reaching 'completed'")
    assert mod["OriginalSize"] == _START_GIB, (
        f"the modification record says the volume started at {mod['OriginalSize']!r}, expected "
        f"{_START_GIB!r}"
    )
    assert mod["TargetSize"] == _TARGET_GIB, (
        f"the modification record targets {mod['TargetSize']!r}, expected {_TARGET_GIB!r}"
    )
    grown_api = _describe_volume(ec2, volume_id)
    assert grown_api["Size"] == _TARGET_GIB, (
        f"the modification reached 'completed' but DescribeVolumes still reports Size "
        f"{grown_api['Size']!r}, expected {_TARGET_GIB!r}"
    )
    assert grown_api["State"] == "in-use", (
        f"the volume left 'in-use' during an ONLINE grow: {grown_api['State']!r}"
    )

    # --- phase 2: the device grew, the filesystem did NOT, and the write fails -
    # The guest polls for the kernel to observe the new device size, which is an observable
    # condition, and reports what it last saw either way rather than hanging.
    probe_grow = [
        "set -u",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        'DEV=$(findmnt -no SOURCE /mnt/grow)',
        'if [ -z "$DEV" ]; then echo "NOT-MOUNTED"; findmnt -no SOURCE,TARGET; exit 1; fi',
        "BYTES=0",
        "for i in $(seq 1 120); do",
        '  BYTES=$(blockdev --getsize64 "$DEV")',
        f'  [ "$BYTES" = "{_TARGET_BYTES}" ] && break',
        "  sleep 2",
        "done",
        "FS=$(df -B1 --output=size /mnt/grow | tail -1 | tr -d ' ')",
        "SHA=$(sha256sum /mnt/grow/payload.bin | cut -d' ' -f1)",
        "rm -f /mnt/grow/beyond.bin",
        f"if dd if=/dev/zero of=/mnt/grow/beyond.bin bs=1M count={_BEYOND_MIB} status=none "
        "2>/tmp/dd.err; then WRITE=accepted;",
        'elif grep -qi "No space left on device" /tmp/dd.err; then WRITE=enospc;',
        "else WRITE=other; fi",
        "PARTIAL=$(stat -c %s /mnt/grow/beyond.bin 2>/dev/null || echo 0)",
        "rm -f /mnt/grow/beyond.bin",
        "sync",
        'echo "SIM2REAL-GROWN dev=$DEV bytes=$BYTES fs=$FS sha=$SHA write=$WRITE'
        ' partial=$PARTIAL err=$(tr -d \' \\n\' < /tmp/dd.err | tail -c 120)"',
    ]
    grown = _report(_run_guest(ssm, instance_id, probe_grow,
                               "reading the grown device before resize2fs"),
                    "SIM2REAL-GROWN")
    assert grown is not None and {"bytes", "fs", "sha", "write", "partial"} <= set(grown), (
        f"the guest did not report the post-grow state, it reported {grown!r}"
    )
    assert int(grown["bytes"]) == _TARGET_BYTES, (
        f"the guest's block device reports {grown['bytes']!r} bytes after the modification "
        f"completed, expected {_TARGET_BYTES!r} — the API granted capacity the device never got"
    )
    assert grown["sha"] == sha_before, (
        f"the pre-grow payload hashes to {grown['sha']!r} after the grow but was written as "
        f"{sha_before!r} — the bytes did not survive the resize"
    )
    assert int(grown["fs"]) == fs_before, (
        f"the MOUNTED FILESYSTEM is {grown['fs']!r} bytes after the grow but was {fs_before!r} "
        f"before, and nothing has run resize2fs yet — a filesystem cannot learn its device grew"
    )
    assert grown["write"] == "enospc", (
        f"a {_BEYOND_MIB} MiB write into a {_START_GIB} GiB filesystem must fail with ENOSPC "
        f"until resize2fs runs, but the guest reported write={grown['write']!r} "
        f"(partial={grown.get('partial')!r}, dd said {grown.get('err')!r})"
    )
    assert int(grown["partial"]) < _BEYOND_BYTES, (
        f"the refused write still landed {grown['partial']!r} of {_BEYOND_BYTES} bytes, so it was "
        f"not refused at all"
    )

    # --- phase 3: resize2fs, and the identical write now lands in full --------
    resize = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        'DEV=$(findmnt -no SOURCE /mnt/grow)',
        'resize2fs "$DEV" >/dev/null 2>&1',
        "FS=$(df -B1 --output=size /mnt/grow | tail -1 | tr -d ' ')",
        f"dd if=/dev/zero of=/mnt/grow/beyond.bin bs=1M count={_BEYOND_MIB} status=none",
        "sync",
        'echo "SIM2REAL-RESIZED dev=$DEV bytes=$(blockdev --getsize64 $DEV) fs=$FS'
        ' wrote=$(stat -c %s /mnt/grow/beyond.bin)'
        ' sha=$(sha256sum /mnt/grow/payload.bin | cut -d\' \' -f1)"',
    ]
    resized = _report(_run_guest(ssm, instance_id, resize,
                                 "growing the filesystem and repeating the write"),
                      "SIM2REAL-RESIZED")
    assert resized is not None and {"bytes", "fs", "wrote", "sha"} <= set(resized), (
        f"the guest did not report the post-resize2fs state, it reported {resized!r}"
    )
    assert int(resized["wrote"]) == _BEYOND_BYTES, (
        f"after resize2fs the same write landed {resized['wrote']!r} bytes, expected "
        f"{_BEYOND_BYTES!r} — the capacity the grow added is reported but not usable"
    )
    assert _BEYOND_BYTES > _START_BYTES, (
        f"the post-resize2fs write of {_BEYOND_BYTES} bytes would have fitted in the original "
        f"{_START_BYTES}-byte volume, so it proves nothing about the added capacity"
    )
    assert int(resized["fs"]) > fs_before * 2, (
        f"the mounted filesystem is {resized['fs']!r} bytes after resize2fs and was {fs_before!r} "
        f"before; a {_START_GIB} -> {_TARGET_GIB} GiB grow must more than double it"
    )
    assert int(resized["bytes"]) == _TARGET_BYTES, (
        f"the block device is {resized['bytes']!r} bytes after resize2fs, expected {_TARGET_BYTES!r}"
    )
    assert resized["sha"] == sha_before, (
        f"after filling the grown volume the pre-grow payload hashes to {resized['sha']!r}, but it "
        f"was written as {sha_before!r} — the added capacity overwrote the old bytes"
    )

    # --- and the control plane still agrees, on the same attachment ----------
    final = _describe_volume(ec2, volume_id)
    assert final["Size"] == _TARGET_GIB, (
        f"the volume's final Size is {final['Size']!r}, expected {_TARGET_GIB!r}"
    )
    assert [a["InstanceId"] for a in final["Attachments"]] == [instance_id], (
        f"the grow changed the attachment set to {final['Attachments']!r}, expected exactly "
        f"{instance_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
