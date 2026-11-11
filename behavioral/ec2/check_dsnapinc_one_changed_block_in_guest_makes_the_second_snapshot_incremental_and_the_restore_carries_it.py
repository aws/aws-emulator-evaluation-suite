"""dsnapinc-one-changed-block-in-guest-makes-the-second-snapshot-incremental-and-the-restore-carries-it."""
from __future__ import annotations

import hashlib
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dsnapinc-one-changed-block-in-guest-makes-the-second-snapshot-incremental-and-the-restore-carries-it"
GROUP = 'dsnapinc-block-storage-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"
#: The EBS snapshot block size, as reported by ListSnapshotBlocks itself — asserted below rather
#: than trusted, because every block index in this check is an offset derived from it.
_BLOCK = 524288
#: Eight blocks = 4 MiB of payload on a 1 GiB volume. 1 GiB is deliberately distinct from the
#: AL2023 root volume (8 GiB) so the GUEST can find the device by size; Nitro does not honour
#: /dev/sdf, so a device PATH is only a request and can never be asserted on.
_N_BLOCKS = 8
_DATA_GIB = 1
_DATA_BYTES = _DATA_GIB * 1024 * 1024 * 1024
#: The restored volume is grown by one GiB purely so the guest can tell the two attached devices
#: apart by size while BOTH are attached — a restore into an equally sized volume would leave two
#: 1 GiB block devices and no property to select on. Growing does not move any snapshot block:
#: the restored blocks stay at their original offsets and the extra space reads as zeros.
_RESTORED_GIB = _DATA_GIB + 1
_RESTORED_BYTES = _RESTORED_GIB * 1024 * 1024 * 1024
#: The one block this check rewrites. Interior, so an implementation that tracks "everything from
#: the last written offset onwards" cannot pass by accident.
_CHANGED_INDEX = 3


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="", ctx=None):
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=60, delay=2.0):
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


def _usable_az(ctx, instance_type=_INSTANCE_TYPE):
    """An AZ that is both available and offers the instance type.

    Neither catalogue alone answers that, and AZ names are per-account aliases.
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
        f"no available AZ in {ctx.region} offers {instance_type!r}; the offering set was "
        f"{sorted(offered)!r}"
    )
    return usable[0]


def _public_vpc(ctx, ec2, az, scenario):
    """A dedicated VPC with a public subnet in `az`; an account need not have a default VPC.

    The SSM agent needs egress, hence the IGW, default route and public addressing.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

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
    role = ctx.unique_name("sim2real-dsnapinc-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav dsnapinc incremental-snapshot role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(30):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 29:
                raise
            time.sleep(2)
    for attempt in range(30):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    for attempt in range(30):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


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
    state = None
    while time.monotonic() < deadline:
        state = _instance_state(ec2, instance_id)
        if state in ("terminated", "__gone__"):
            return
        time.sleep(2)
    raise RuntimeError(f"instance {instance_id} was not terminated: still {state!r} after {timeout_s}s")


def _describe_volume(ec2, volume_id):
    """DescribeVolumes for one id, paginated."""
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_and_delete_volume(ec2, volume_id, timeout_s=300):
    """Detach if attached, wait for 'available', then delete.

    Self-sufficient rather than order-dependent: the volumes are created after the instance, so
    LIFO runs this BEFORE the terminate, and a delete of an in-use volume is refused.
    """
    def _vol():
        try:
            return _describe_volume(ec2, volume_id)
        except AssertionError:
            return None
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return None
            raise

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
        time.sleep(2)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _delete_snapshot(ec2, snapshot_id, timeout_s=300):
    """Delete on a bounded retry: a snapshot still feeding a volume that is being created is
    refused with InvalidSnapshot.InUse, which converges once the restore finishes."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidSnapshot.NotFound":
                return
            last = exc
            time.sleep(2)
    raise RuntimeError(f"snapshot {snapshot_id} was not deleted: {last!r}")


def _describe_snapshot(ec2, snapshot_id):
    """DescribeSnapshots for one id, paginated."""
    for page in ec2.get_paginator("describe_snapshots").paginate(SnapshotIds=[snapshot_id]):
        for snap in page["Snapshots"]:
            if snap["SnapshotId"] == snapshot_id:
                return snap
    raise AssertionError(f"snapshot {snapshot_id} not found in any page of DescribeSnapshots")


def _snapshot_volume(ctx, ec2, volume_id, scenario, label):
    """CreateSnapshot and wait for 'completed'.

    Back-to-back snapshots of one volume hit SnapshotCreationPerVolumeRateExceeded; retried.
    """
    def _create():
        return ec2.create_snapshot(
            VolumeId=volume_id, Description=f"sim2real {scenario} {label}",
            TagSpecifications=[{"ResourceType": "snapshot",
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}],
        )["SnapshotId"]

    deadline = time.monotonic() + _budget_s(ctx, 400)
    while True:
        try:
            snapshot_id = _create()
            break
        except ClientError as exc:
            if (_code(exc) not in _THROTTLE + ("SnapshotCreationPerVolumeRateExceeded",)
                    or time.monotonic() >= deadline):
                if (_code(exc) in _THROTTLE + ("SnapshotCreationPerVolumeRateExceeded",)
                        and _budget_spent(ctx)):
                    raise TimeoutError(f"CreateSnapshot {label} of {volume_id} past its rate limit: "
                                       "the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))
    snap = _poll(lambda: _describe_snapshot(ec2, snapshot_id), lambda s: s["State"] == "completed",
                 timeout_s=1200, interval_s=1.0, ctx=ctx,
                 what=f"snapshot {label} ({snapshot_id}) of {volume_id} reaching 'completed'")
    assert snap["VolumeId"] == volume_id, (
        f"snapshot {label} names volume {snap['VolumeId']!r}, expected {volume_id!r}"
    )
    assert snap["Progress"] == "100%", (
        f"a completed snapshot must report Progress '100%', got {snap['Progress']!r} for {label}"
    )
    return snapshot_id


def _snapshot_blocks(ebs, snapshot_id, timeout_s=300, interval_s=1.0, ctx=None):
    """Every {BlockIndex: BlockToken} of a snapshot, PAGINATED and polled through the lag.

    The EBS direct-API plane can briefly trail EC2's completed-state signal with
    ResourceNotFoundException; the poll is bounded, so a snapshot the direct API never serves is a
    failure rather than a hang.
    """
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            blocks, token, block_size = {}, None, None
            while True:
                kw = {"SnapshotId": snapshot_id}
                if token:
                    kw["NextToken"] = token
                page = ebs.list_snapshot_blocks(**kw)
                block_size = page["BlockSize"]
                for blk in page["Blocks"]:
                    blocks[blk["BlockIndex"]] = blk["BlockToken"]
                token = page.get("NextToken")
                if not token:
                    return blocks, block_size
        except ClientError as exc:
            if _code(exc) != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"ListSnapshotBlocks serving {snapshot_id}: the run budget ended "
                                       "first; not graded") from exc
                raise AssertionError(
                    f"ListSnapshotBlocks never served {snapshot_id} within {timeout_s:.0f}s: {exc!r}"
                ) from exc
            time.sleep(interval_s)


def _changed_blocks(ebs, first_id, second_id, timeout_s=300, interval_s=1.0, ctx=None):
    """Every changed BlockIndex between two snapshots, PAGINATED and polled through the same lag."""
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            indices, token = set(), None
            while True:
                kw = {"FirstSnapshotId": first_id, "SecondSnapshotId": second_id}
                if token:
                    kw["NextToken"] = token
                page = ebs.list_changed_blocks(**kw)
                for blk in page.get("ChangedBlocks") or []:
                    indices.add(blk["BlockIndex"])
                token = page.get("NextToken")
                if not token:
                    return indices
        except ClientError as exc:
            if _code(exc) != "ResourceNotFoundException":
                raise
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"ListChangedBlocks serving {first_id} -> {second_id}: the run "
                                       "budget ended first; not graded") from exc
                raise AssertionError(
                    f"ListChangedBlocks never served {first_id} -> {second_id} within "
                    f"{timeout_s:.0f}s: {exc!r}"
                ) from exc
            time.sleep(interval_s)


def _block_bytes(ebs, snapshot_id, block_index, block_token):
    """The raw 512 KiB of one snapshot block, as the EBS direct API serves it."""
    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=block_index,
                                 BlockToken=block_token)
    return got["BlockData"].read(), got["DataLength"]


def _expected_block(marker):
    """The exact 512 KiB the guest writes for `marker`: (marker + newline) repeated, truncated."""
    unit = (marker + "\n").encode()
    return (unit * (_BLOCK // len(unit) + 1))[:_BLOCK]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand is refused with InvalidInstanceId until the agent registers; retrying is the wait.
    """
    deadline = time.monotonic() + _budget_s(ctx, ready_timeout_s)
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav dsnapinc block IO",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and _budget_spent(ctx):
                raise TimeoutError(f"{what}: SendCommand to {instance_id} being accepted: the run "
                                   "budget ended first; not graded") from exc
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
                timeout_s=run_timeout_s, interval_s=1.0, ctx=ctx,
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
    """The `key=value` fields of the last line starting with `marker`, as a dict."""
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


def _find_dev(size_bytes):
    """Shell lines selecting the block device by exact byte size, waiting for it to appear.

    Nitro enumerates EBS as /dev/nvme?n1 regardless of the requested device name.
    """
    return [
        'DEV=""',
        'for _ in $(seq 1 60); do',
        f'  DEV=$(lsblk -dn -b -o NAME,SIZE | awk -v w={size_bytes} '
        '\'$2==w {print "/dev/"$1; exit}\')',
        '  [ -n "$DEV" ] && break',
        '  sleep 2',
        'done',
        f'if [ -z "$DEV" ]; then echo "NO-DEVICE-OF-{size_bytes}-BYTES"; '
        'lsblk -dn -b -o NAME,SIZE,MODEL; exit 1; fi',
    ]


def _write_block_cmd(index, marker):
    """Shell lines writing exactly one 512 KiB block at `index`.

    `conv=notrunc,fsync` leaves other blocks untouched and flushes this one before dd returns.
    """
    reps = _BLOCK // (len(marker) + 1) + 2
    return [
        f'awk -v m="{marker}" \'BEGIN{{for(i=0;i<{reps};i++) print m}}\' > /tmp/dsnapinc.blk',
        f'truncate -s {_BLOCK} /tmp/dsnapinc.blk',
        f'dd if=/tmp/dsnapinc.blk of="$DEV" bs={_BLOCK} seek={index} count=1 '
        'conv=notrunc,fsync status=none',
        'sync',
        'blockdev --flushbufs "$DEV"',
    ]


def _read_blocks_cmd(line_marker):
    """Shell lines reporting the sha256 of every block, read with O_DIRECT to bypass the cache."""
    return [
        'OUT=""',
        f'for i in $(seq 0 {_N_BLOCKS - 1}); do',
        f'  S=$(dd if="$DEV" bs={_BLOCK} skip="$i" count=1 iflag=direct status=none '
        "| sha256sum | cut -d' ' -f1)",
        '  OUT="$OUT b$i=$S"',
        'done',
        f'echo "{line_marker} dev=$DEV$OUT"',
    ]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """With no write between snapshots ListChangedBlocks is empty; rewriting one guest block makes
    the next diff exactly that index, and a restore carries the new bytes there, old ones elsewhere.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html
    """
    ec2 = ctx.client("ec2")
    ebs = ctx.client("ebs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dsnapinc-incremental-snapshot"
    nonce = ctx.unique_name("dsnapinc-")

    # Known bytes: one marker per block, plus the replacement for the single block that changes.
    markers = {i: f"{nonce}-b{i}" for i in range(_N_BLOCKS)}
    changed_marker = f"{nonce}-rewritten"
    want_sha = {i: _sha(_expected_block(m)) for i, m in markers.items()}
    want_changed_sha = _sha(_expected_block(changed_marker))
    assert want_changed_sha != want_sha[_CHANGED_INDEX], (
        f"the replacement content for block {_CHANGED_INDEX} hashes to the same value as the "
        f"original ({want_changed_sha!r}); the check would assert nothing"
    )

    # --- everything decidable, before anything is created ---------------------
    az = _usable_az(ctx)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 SSM parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one instance, terminated from the moment it exists -------------------
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
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=2.0, ctx=ctx,
          what=f"instance {instance_id} reaching 'running'")

    # --- the source volume, raw: no filesystem, so the check owns every offset -
    source = ec2.create_volume(
        AvailabilityZone=az, Size=_DATA_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, source))
    _poll(lambda: _describe_volume(ec2, source)["State"], lambda s: s == "available",
          timeout_s=300, interval_s=2.0, ctx=ctx,
          what=f"source volume {source} reaching 'available'")
    ec2.attach_volume(VolumeId=source, InstanceId=instance_id, Device="/dev/sdf")
    _poll(lambda: _describe_volume(ec2, source)["Attachments"],
          lambda a: bool(a) and a[0]["State"] == "attached", timeout_s=300, interval_s=2.0,
          ctx=ctx, what=f"source volume {source} reaching 'attached' on {instance_id}")

    # --- the guest lays down eight known blocks -------------------------------
    write = ["set -eu"] + _find_dev(_DATA_BYTES)
    for i in range(_N_BLOCKS):
        write += _write_block_cmd(i, markers[i])
    write += _read_blocks_cmd("SIM2REAL-WROTE")
    wrote = _report(_run_guest(ctx, ssm, instance_id, write, "writing eight blocks in the guest"),
                    "SIM2REAL-WROTE")
    assert wrote is not None, "the guest never reported the blocks it wrote"
    for i in range(_N_BLOCKS):
        assert wrote.get(f"b{i}") == want_sha[i], (
            f"the guest read back block {i} as {wrote.get(f'b{i}')!r}, but the bytes this check "
            f"told it to write hash to {want_sha[i]!r}; the guest reported {wrote!r}"
        )

    # --- S1: the baseline, and the FULL set of blocks -------------------------
    s1 = _snapshot_volume(ctx, ec2, source, scenario, "s1-baseline")
    s1_blocks, block_size = _snapshot_blocks(ebs, s1, ctx=ctx)
    assert block_size == _BLOCK, (
        f"ListSnapshotBlocks reports BlockSize {block_size!r}; every offset in this check is "
        f"derived from {_BLOCK}"
    )
    assert set(s1_blocks) == set(range(_N_BLOCKS)), (
        f"S1 must list exactly the {_N_BLOCKS} blocks the guest wrote and nothing else (a snapshot "
        f"of a never-written volume lists none at all), but it listed "
        f"{sorted(s1_blocks)!r}"
    )
    s1_bytes, s1_len = _block_bytes(ebs, s1, _CHANGED_INDEX, s1_blocks[_CHANGED_INDEX])
    assert s1_len == _BLOCK, f"GetSnapshotBlock reported DataLength {s1_len!r}, expected {_BLOCK}"
    assert _sha(s1_bytes) == want_sha[_CHANGED_INDEX], (
        f"S1's block {_CHANGED_INDEX} hashes to {_sha(s1_bytes)!r}, but the guest wrote bytes "
        f"hashing to {want_sha[_CHANGED_INDEX]!r} — the snapshot does not hold what is on the "
        f"volume"
    )

    # --- S2: nothing written in between, so the diff must be EMPTY; this rules out a backend
    # that reports some changed block every time.
    s2 = _snapshot_volume(ctx, ec2, source, scenario, "s2-unchanged")
    quiet = _changed_blocks(ebs, s1, s2, ctx=ctx)
    assert quiet == set(), (
        f"no byte was written between S1 ({s1}) and S2 ({s2}), so ListChangedBlocks must report "
        f"nothing changed; it reported {sorted(quiet)!r}. Without this leg, a single changed block "
        f"later cannot be told apart from a backend that always names one"
    )
    s2_blocks, _ = _snapshot_blocks(ebs, s2, ctx=ctx)
    assert set(s2_blocks) == set(range(_N_BLOCKS)), (
        f"a snapshot that changed nothing must still SERVE the whole volume; S2 listed "
        f"{sorted(s2_blocks)!r}, expected {sorted(range(_N_BLOCKS))!r}"
    )

    # --- the guest rewrites exactly ONE block ---------------------------------
    change = ["set -eu"] + _find_dev(_DATA_BYTES)
    change += _write_block_cmd(_CHANGED_INDEX, changed_marker)
    change += _read_blocks_cmd("SIM2REAL-CHANGED")
    after = _report(
        _run_guest(ctx, ssm, instance_id, change,
                   f"rewriting block {_CHANGED_INDEX} in the guest"),
        "SIM2REAL-CHANGED")
    assert after is not None, "the guest never reported the volume after the rewrite"
    assert after.get(f"b{_CHANGED_INDEX}") == want_changed_sha, (
        f"the guest read block {_CHANGED_INDEX} back as {after.get(f'b{_CHANGED_INDEX}')!r} after "
        f"the rewrite, expected {want_changed_sha!r}; it reported {after!r}"
    )
    for i in range(_N_BLOCKS):
        if i == _CHANGED_INDEX:
            continue
        assert after.get(f"b{i}") == want_sha[i], (
            f"rewriting block {_CHANGED_INDEX} disturbed block {i}: the guest now reads "
            f"{after.get(f'b{i}')!r}, expected {want_sha[i]!r}"
        )

    # --- S3: incremental. One index changed; the whole set still served -------
    s3 = _snapshot_volume(ctx, ec2, source, scenario, "s3-incremental")
    changed = _changed_blocks(ebs, s2, s3, ctx=ctx)
    assert changed == {_CHANGED_INDEX}, (
        f"the guest rewrote block {_CHANGED_INDEX} and nothing else, so ListChangedBlocks(S2, S3) "
        f"must report exactly that index; it reported {sorted(changed)!r}"
    )
    assert _changed_blocks(ebs, s1, s3, ctx=ctx) == {_CHANGED_INDEX}, (
        f"the diff from the BASELINE S1 must name the same single index {_CHANGED_INDEX}, since "
        f"S2 changed nothing; it named {sorted(_changed_blocks(ebs, s1, s3, ctx=ctx))!r}"
    )
    s3_blocks, _ = _snapshot_blocks(ebs, s3, ctx=ctx)
    # The incremental relation, as an ORDERING rather than a pinned count: what CHANGED is a
    # strict subset of what the snapshot SERVES. That is the whole meaning of "incremental".
    assert changed < set(s3_blocks), (
        f"an incremental snapshot must serve strictly more blocks than it changed; S3 changed "
        f"{sorted(changed)!r} and serves {sorted(s3_blocks)!r}"
    )
    assert set(s3_blocks) == set(s1_blocks), (
        f"S3 must serve the same block set as S1 — the unchanged blocks are inherited, not lost — "
        f"but it serves {sorted(s3_blocks)!r} against S1's {sorted(s1_blocks)!r}"
    )
    s3_bytes, _ = _block_bytes(ebs, s3, _CHANGED_INDEX, s3_blocks[_CHANGED_INDEX])
    assert _sha(s3_bytes) == want_changed_sha, (
        f"S3's block {_CHANGED_INDEX} hashes to {_sha(s3_bytes)!r}, expected the rewritten bytes "
        f"{want_changed_sha!r}"
    )
    inherited = (_CHANGED_INDEX + 1) % _N_BLOCKS
    s3_inherited, _ = _block_bytes(ebs, s3, inherited, s3_blocks[inherited])
    assert _sha(s3_inherited) == want_sha[inherited], (
        f"S3 must serve the INHERITED block {inherited} unchanged, but it hashes to "
        f"{_sha(s3_inherited)!r} instead of {want_sha[inherited]!r}"
    )

    # --- restore S3 into a new volume and let the guest read it ---------------
    restored = ec2.create_volume(
        SnapshotId=s3, AvailabilityZone=az, Size=_RESTORED_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, restored))
    _poll(lambda: _describe_volume(ec2, restored)["State"], lambda s: s == "available",
          timeout_s=600, interval_s=2.0, ctx=ctx,
          what=f"restored volume {restored} reaching 'available'")
    restored_view = _describe_volume(ec2, restored)
    assert restored_view["SnapshotId"] == s3, (
        f"the restored volume names snapshot {restored_view['SnapshotId']!r}, expected {s3!r}"
    )
    ec2.attach_volume(VolumeId=restored, InstanceId=instance_id, Device="/dev/sdg")
    attached = _poll(lambda: _describe_volume(ec2, restored)["Attachments"],
                     lambda a: bool(a) and a[0]["State"] == "attached",
                     timeout_s=300, interval_s=2.0, ctx=ctx,
                     what=f"restored volume {restored} reaching 'attached' on {instance_id}")
    assert [a["InstanceId"] for a in attached] == [instance_id], (
        f"the restored volume's attachment set is {attached!r}, expected exactly {instance_id!r}"
    )

    read = ["set -eu"] + _find_dev(_RESTORED_BYTES) + _read_blocks_cmd("SIM2REAL-RESTORED")
    got = _report(_run_guest(ctx, ssm, instance_id, read,
                             "reading the restored volume in the guest"),
                  "SIM2REAL-RESTORED")
    assert got is not None, "the guest never reported the restored volume's blocks"
    assert got.get(f"b{_CHANGED_INDEX}") == want_changed_sha, (
        f"the restored volume must carry the REWRITTEN bytes at block {_CHANGED_INDEX}, but the "
        f"guest read {got.get(f'b{_CHANGED_INDEX}')!r} instead of {want_changed_sha!r}; it "
        f"reported {got!r}"
    )
    assert got.get(f"b{_CHANGED_INDEX}") != want_sha[_CHANGED_INDEX], (
        f"the restored volume carries the PRE-rewrite bytes at block {_CHANGED_INDEX} "
        f"({want_sha[_CHANGED_INDEX]!r}) — the incremental snapshot served its parent's block"
    )
    for i in range(_N_BLOCKS):
        if i == _CHANGED_INDEX:
            continue
        assert got.get(f"b{i}") == want_sha[i], (
            f"the restored volume must inherit block {i} unchanged from the parent snapshot, but "
            f"the guest read {got.get(f'b{i}')!r} instead of {want_sha[i]!r}; it reported {got!r}"
        )
    assert got["dev"] != wrote["dev"], (
        f"the guest read the restored volume on the same device it wrote the source on "
        f"({got['dev']!r}); the two are distinguished by size, so this read proves nothing"
    )

    # --- and the source volume still says what it said ------------------------
    source_after = _describe_volume(ec2, source)
    assert [a["InstanceId"] for a in source_after["Attachments"]] == [instance_id], (
        f"the restore changed the source volume's attachment set to "
        f"{source_after['Attachments']!r}, expected exactly {instance_id!r}"
    )
    assert source_after["Size"] == _DATA_GIB, (
        f"the source volume is now {source_after['Size']!r} GiB; restoring into a larger volume "
        f"must not touch it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
