"""dvolgrow-root-volume-grows-online-and-only-growpart-reaches-the-live-root-filesystem."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dvolgrow-root-volume-grows-online-and-only-growpart-reaches-the-live-root-filesystem"
GROUP = 'dvolgrow-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"
_GIB = 1024 * 1024 * 1024
#: How much to add to whatever the AMI's root volume is. Enough that the filesystem's growth is
#: unmistakable and small enough to complete in seconds.
_ADD_GIB = 4
#: 1 MiB of nonce-derived payload on the ROOT filesystem, written before the grow.
_PAYLOAD_BYTES = 1024 * 1024

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
                    Description="sim2real-behav root volume grow role",
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


def _instance(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _instance_state(ec2, instance_id):
    inst = _instance(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI and the instance
    profile association only clear at the end, and the subnet/VPC teardown registered earlier
    cannot proceed until they do. The root volume has DeleteOnTermination true, so this is also
    what deletes it."""
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
                Comment="sim2real-behav root volume grow",
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


#: Resolve the root disk, its partition and the partition number by PROPERTY, from the mount table
#: — never by a literal path. Nitro presents the root volume as /dev/nvme0n1 whatever the API was
#: told the device name was, and the partition layout of an AL2023 image is not ours to assume.
_FIND_ROOT = (
    'SRC=$(findmnt -no SOURCE /)\n'
    'if [ -z "$SRC" ]; then echo "NO-ROOT-SOURCE"; findmnt -no SOURCE,TARGET; exit 1; fi\n'
    'KNAME=$(basename "$SRC")\n'
    'PK=$(lsblk -no pkname "$SRC" | head -1 | tr -d " ")\n'
    'if [ -z "$PK" ]; then echo "ROOT-NOT-PARTITIONED $SRC"; lsblk; exit 1; fi\n'
    'DISK=/dev/$PK\n'
    'PN=$(cat /sys/class/block/$KNAME/partition)\n'
)
#: One reporting line per phase, so every phase is read the same way.
_ROOT_REPORT = (
    'echo "%s src=$SRC disk=$DISK part=$PN'
    ' disk_bytes=$(blockdev --getsize64 $DISK)'
    ' part_bytes=$(blockdev --getsize64 $SRC)'
    ' fs_bytes=$(df -B1 --output=size / | tail -1 | tr -d \' \')'
    ' fstype=$(findmnt -no FSTYPE /)'
    ' boot=$(cat /proc/sys/kernel/random/boot_id)'
    ' sha=$(sha256sum /root/payload.bin | cut -d\' \' -f1)'
    ' payload=$(stat -c %%s /root/payload.bin)%s"'
)


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Growing a running instance's root volume grows only the disk: the partition and `/` are unchanged
    until growpart, `/` until xfs_growfs, with boot_id and the payload digest constant in every phase."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dvolgrow-root-growpart"
    nonce = ctx.unique_name("sim2real-nonce-")

    # --- everything decidable, before anything is created ---------------------
    az = _usable_az(ec2)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    root_device = image["RootDeviceName"]
    root_mapping = [m for m in image["BlockDeviceMappings"] if m["DeviceName"] == root_device]
    assert root_mapping and root_mapping[0].get("Ebs", {}).get("VolumeSize"), (
        f"the AMI {ami!r} declares no EBS size for its root device {root_device!r}: "
        f"{image['BlockDeviceMappings']!r}"
    )
    start_gib = int(root_mapping[0]["Ebs"]["VolumeSize"])
    target_gib = start_gib + _ADD_GIB
    assert start_gib > 0, f"the AMI's root volume size is {start_gib!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one instance whose root volume size is stated explicitly -------------
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
            BlockDeviceMappings=[{"DeviceName": root_device,
                                  "Ebs": {"VolumeSize": start_gib, "VolumeType": "gp3",
                                          "DeleteOnTermination": True}}],
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

    # --- the root volume is the one the instance says is on its root device ----
    inst = _instance(ec2, instance_id)
    assert inst["RootDeviceName"] == root_device, (
        f"the instance reports root device {inst['RootDeviceName']!r}, expected {root_device!r}"
    )
    roots = [m for m in inst["BlockDeviceMappings"] if m["DeviceName"] == root_device]
    assert roots and roots[0].get("Ebs", {}).get("VolumeId"), (
        f"the instance exposes no EBS volume on its root device: "
        f"{inst['BlockDeviceMappings']!r}"
    )
    volume_id = roots[0]["Ebs"]["VolumeId"]
    root_vol = _describe_volume(ec2, volume_id)
    assert root_vol["Size"] == start_gib, (
        f"the root volume was created at Size {root_vol['Size']!r}, expected {start_gib!r}"
    )
    assert root_vol["State"] == "in-use", (
        f"the root volume of a running instance is {root_vol['State']!r}, expected 'in-use'"
    )

    # --- phase 1: a payload on the ROOT filesystem, and the three sizes -------
    provision = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        _FIND_ROOT,
        f'yes "{nonce}" | head -c {_PAYLOAD_BYTES} > /root/payload.bin',
        "sync",
        _ROOT_REPORT % ("SIM2REAL-BASE", ""),
    ]
    base = _report(_run_guest(ssm, instance_id, provision,
                              "writing the payload and measuring the root stack"),
                   "SIM2REAL-BASE")
    assert base is not None and {"disk", "part", "disk_bytes", "part_bytes", "fs_bytes",
                                 "fstype", "boot", "sha", "payload"} <= set(base), (
        f"the guest did not report the root stack, it reported {base!r}"
    )
    assert int(base["payload"]) == _PAYLOAD_BYTES, (
        f"the guest wrote {base['payload']!r} bytes of payload, expected {_PAYLOAD_BYTES!r}"
    )
    assert len(base["sha"]) == 64, f"the guest reported a malformed sha256 {base['sha']!r}"
    disk_before, part_before = int(base["disk_bytes"]), int(base["part_bytes"])
    fs_before, boot, sha, fstype = int(base["fs_bytes"]), base["boot"], base["sha"], base["fstype"]
    assert disk_before == start_gib * _GIB, (
        f"the guest's root DISK is {disk_before} bytes, expected {start_gib * _GIB} — it is not "
        f"looking at the volume this check launched"
    )
    assert part_before < disk_before, (
        f"the root partition ({part_before} bytes) is not smaller than its disk ({disk_before} "
        f"bytes), so there is no partition table to grow and this check cannot mean anything"
    )
    assert 0 < fs_before <= part_before, (
        f"the root filesystem reports {fs_before} bytes inside a {part_before}-byte partition, "
        f"which is impossible"
    )

    # --- grow the root volume of the RUNNING instance -------------------------
    ec2.modify_volume(VolumeId=volume_id, Size=target_gib)
    mod = _poll(lambda: ec2.describe_volumes_modifications(
                    VolumeIds=[volume_id])["VolumesModifications"][0],
                lambda m: m["ModificationState"] == "completed",
                timeout_s=900, interval_s=5.0,
                what=f"the modification of root volume {volume_id} reaching 'completed'")
    assert mod["OriginalSize"] == start_gib, (
        f"the modification record says the root volume started at {mod['OriginalSize']!r}, "
        f"expected {start_gib!r}"
    )
    assert mod["TargetSize"] == target_gib, (
        f"the modification record targets {mod['TargetSize']!r}, expected {target_gib!r}"
    )
    grown_api = _describe_volume(ec2, volume_id)
    assert grown_api["Size"] == target_gib, (
        f"the modification reached 'completed' but DescribeVolumes still reports Size "
        f"{grown_api['Size']!r}, expected {target_gib!r}"
    )
    assert grown_api["State"] == "in-use", (
        f"the root volume left 'in-use' during an ONLINE grow: {grown_api['State']!r}"
    )
    assert _instance_state(ec2, instance_id) == "running", (
        f"the instance is {_instance_state(ec2, instance_id)!r} after growing its root volume; an "
        f"online grow must not stop it"
    )

    # --- phase 2: the disk grew; the partition and / did NOT ------------------
    probe = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        _FIND_ROOT,
        "for i in $(seq 1 120); do",
        f'  [ "$(blockdev --getsize64 $DISK)" = "{target_gib * _GIB}" ] && break',
        "  sleep 2",
        "done",
        _ROOT_REPORT % ("SIM2REAL-DISK", ""),
    ]
    after_disk = _report(_run_guest(ssm, instance_id, probe,
                                    "reading the root stack after the modification completed"),
                         "SIM2REAL-DISK")
    assert after_disk is not None and "disk_bytes" in after_disk, (
        f"the guest did not report the root stack after the grow, it reported {after_disk!r}"
    )
    assert int(after_disk["disk_bytes"]) == target_gib * _GIB, (
        f"the guest's root DISK is {after_disk['disk_bytes']!r} bytes after the modification "
        f"completed, expected {target_gib * _GIB} — the API granted capacity the disk never got"
    )
    assert int(after_disk["part_bytes"]) == part_before, (
        f"the root PARTITION is {after_disk['part_bytes']!r} bytes after the grow but was "
        f"{part_before!r} before, and nothing has run growpart yet — the added capacity lands "
        f"outside the partition table and cannot enter it on its own"
    )
    assert int(after_disk["fs_bytes"]) == fs_before, (
        f"the root FILESYSTEM is {after_disk['fs_bytes']!r} bytes after the grow but was "
        f"{fs_before!r} before, and neither growpart nor a filesystem grow has run"
    )
    assert after_disk["boot"] == boot, (
        f"the instance rebooted during the grow (boot id {boot!r} -> {after_disk['boot']!r}), so "
        f"nothing here is evidence about an ONLINE resize"
    )
    assert after_disk["sha"] == sha, (
        f"the payload written before the grow hashes to {after_disk['sha']!r}, but it was written "
        f"as {sha!r} — the root bytes did not survive the resize"
    )

    # --- phase 3: growpart moves the partition; / still does not -------------
    grow_part = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        _FIND_ROOT,
        'if growpart "$DISK" "$PN" >/tmp/gp.out 2>&1; then GP=changed; else GP=rc$?; fi',
        'udevadm settle || true',
        _ROOT_REPORT % ("SIM2REAL-PART", " growpart=$GP"),
    ]
    after_part = _report(_run_guest(ssm, instance_id, grow_part, "running growpart in the guest"),
                         "SIM2REAL-PART")
    assert after_part is not None and "part_bytes" in after_part, (
        f"the guest did not report the root stack after growpart, it reported {after_part!r}"
    )
    assert after_part.get("growpart") == "changed", (
        f"growpart did not extend the root partition: it reported {after_part.get('growpart')!r}"
    )
    assert int(after_part["part_bytes"]) > part_before, (
        f"the root PARTITION is {after_part['part_bytes']!r} bytes after growpart and was "
        f"{part_before!r} before; growpart must extend it into the added capacity"
    )
    assert int(after_part["part_bytes"]) <= target_gib * _GIB, (
        f"the root PARTITION is {after_part['part_bytes']!r} bytes, which does not fit in the "
        f"{target_gib * _GIB}-byte disk it lives on"
    )
    assert int(after_part["fs_bytes"]) == fs_before, (
        f"the root FILESYSTEM is {after_part['fs_bytes']!r} bytes after growpart but was "
        f"{fs_before!r} before; a partition table edit is not a filesystem grow"
    )
    assert after_part["boot"] == boot, (
        f"the instance rebooted before growpart (boot id {boot!r} -> {after_part['boot']!r}), so "
        f"the partition change cannot be attributed to growpart on a live root device"
    )
    assert after_part["sha"] == sha, (
        f"the payload hashes to {after_part['sha']!r} after growpart, but it was written as "
        f"{sha!r} — extending the partition must not touch the bytes inside it"
    )

    # --- phase 4: and the filesystem finally grows into it -------------------
    grow_fs = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        _FIND_ROOT,
        'FSTYPE=$(findmnt -no FSTYPE /)',
        'case "$FSTYPE" in',
        '  xfs) xfs_growfs / >/tmp/fs.out 2>&1 ;;',
        '  ext2|ext3|ext4) resize2fs "$SRC" >/tmp/fs.out 2>&1 ;;',
        '  *) echo "UNSUPPORTED-ROOT-FSTYPE $FSTYPE"; exit 1 ;;',
        'esac',
        _ROOT_REPORT % ("SIM2REAL-FS", ""),
    ]
    after_fs = _report(_run_guest(ssm, instance_id, grow_fs,
                                  "growing the root filesystem into the new partition"),
                       "SIM2REAL-FS")
    assert after_fs is not None and "fs_bytes" in after_fs, (
        f"the guest did not report the root stack after the filesystem grow, it reported "
        f"{after_fs!r}"
    )
    fs_after = int(after_fs["fs_bytes"])
    assert fs_after > fs_before, (
        f"the root FILESYSTEM is {fs_after} bytes after the grow and was {fs_before} before; "
        f"growing it into a partition that is now {after_part['part_bytes']!r} bytes must enlarge it"
    )
    assert fs_after - fs_before > 3 * _GIB, (
        f"the root filesystem gained only {fs_after - fs_before} bytes from a {_ADD_GIB} GiB "
        f"volume grow (was {fs_before}, now {fs_after})"
    )
    assert fs_after <= int(after_part["part_bytes"]), (
        f"the root filesystem is {fs_after} bytes inside a {after_part['part_bytes']!r}-byte "
        f"partition, which is impossible"
    )
    assert after_fs["fstype"] == fstype, (
        f"the root filesystem type changed from {fstype!r} to {after_fs['fstype']!r} across the "
        f"grow"
    )
    assert after_fs["boot"] == boot, (
        f"the instance rebooted at some point (boot id {boot!r} -> {after_fs['boot']!r}); every "
        f"step here had to happen on one boot for this to be an online resize"
    )
    assert after_fs["sha"] == sha, (
        f"after the whole grow the payload hashes to {after_fs['sha']!r}, but it was written as "
        f"{sha!r} — data written before an online root resize must be intact after it"
    )
    assert int(after_fs["disk_bytes"]) == target_gib * _GIB, (
        f"the root disk is {after_fs['disk_bytes']!r} bytes at the end, expected "
        f"{target_gib * _GIB}"
    )

    # --- the control plane still agrees, on the same instance ---------------
    final = _describe_volume(ec2, volume_id)
    assert final["Size"] == target_gib, (
        f"the root volume's final Size is {final['Size']!r}, expected {target_gib!r}"
    )
    assert [a["InstanceId"] for a in final["Attachments"]] == [instance_id], (
        f"the grow changed the root attachment set to {final['Attachments']!r}, expected exactly "
        f"{instance_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
