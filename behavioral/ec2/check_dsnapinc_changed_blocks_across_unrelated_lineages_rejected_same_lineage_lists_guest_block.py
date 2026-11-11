"""dsnapinc-changed-blocks-across-unrelated-lineages-rejected-same-lineage-lists-guest-block."""
from __future__ import annotations

import hashlib
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dsnapinc-changed-blocks-across-unrelated-lineages-rejected-same-lineage-lists-guest-block"
GROUP = 'dsnapinc-block-storage-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"
_BLOCK = 524288
_N_BLOCKS = 4
#: Two data volumes of DIFFERENT sizes, so one guest can address each by size while both are
#: attached. Both are distinct from the AL2023 root volume (8 GiB). Nitro does not honour /dev/sdf,
#: so a device PATH is only a request and can never be selected on.
_A_GIB = 1
_A_BYTES = _A_GIB * 1024 * 1024 * 1024
_B_GIB = 2
_B_BYTES = _B_GIB * 1024 * 1024 * 1024
_CHANGED_INDEX = 2

# ===== helpers (self-contained) =====


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _expect_error(fn, what):
    """Return the AWS error (code, message) `fn` raised, and FAIL LOUDLY if it did not raise.

    Deliberately never returns a falsy sentinel on success: an implementation that ACCEPTS a call
    real AWS refuses is the strongest signal this check can produce, and reporting it as an
    empty-string "code" would read like a naming difference instead of over-permissiveness.
    """
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"{what}: real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


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


def _usable_az(ctx, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH reported available AND offers the instance type, intersected not guessed.

    describe_instance_type_offerings reports no zone state and describe_availability_zones reports
    no instance types, so either catalogue alone picks a zone that cannot run the check. AZ *names*
    are per-account aliases for different physical zones, so a literal is the same gamble wearing a
    fixed name.
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
    """A VPC of this check's own making, with a public subnet in `az`.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared
    default subnet makes the check assert a property of the account. The
    SSM agent needs egress to reach its endpoint, so the subnet gets an internet gateway, a default
    route and auto-assigned public addressing. The CIDR's second octet is random in 10/8 because
    overlapping VPC CIDRs are legal (these VPCs are never peered), so a sibling run in the same
    account cannot collide. Every piece is tagged in the call that creates it.
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
                    Description="sim2real-behav dsnapinc lineage-rejection role",
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
    """DescribeVolumes for one id, PAGINATED — the account is shared and a page is not ours alone."""
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
        time.sleep(5)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _delete_snapshot(ec2, snapshot_id, timeout_s=300):
    """Delete on a bounded retry: a snapshot still feeding a volume that is being created is
    refused with InvalidSnapshot.InUse, which converges once the restore finishes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidSnapshot.NotFound":
                return
            if _code(exc) != "InvalidSnapshot.InUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _describe_snapshot(ec2, snapshot_id):
    """DescribeSnapshots for one id, PAGINATED — same reason as the volume read."""
    for page in ec2.get_paginator("describe_snapshots").paginate(SnapshotIds=[snapshot_id]):
        for snap in page["Snapshots"]:
            if snap["SnapshotId"] == snapshot_id:
                return snap
    raise AssertionError(f"snapshot {snapshot_id} not found in any page of DescribeSnapshots")


def _snapshot_volume(ctx, ec2, volume_id, scenario, label):
    """CreateSnapshot and wait for 'completed', retrying the PER-VOLUME rate limit.

    On AWS, two CreateSnapshot calls against one volume in
    quick succession are refused with SnapshotCreationPerVolumeRateExceeded, and AWS's own message
    says to space the requests out. That code is never ASSERTED here — it is our own request rate,
    not the service's contract.
    """
    def _create():
        return ec2.create_snapshot(
            VolumeId=volume_id, Description=f"sim2real {scenario} {label}",
            TagSpecifications=[{"ResourceType": "snapshot",
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}],
        )["SnapshotId"]

    snapshot_id = _call_with_retry(
        _create, codes=_THROTTLE + ("SnapshotCreationPerVolumeRateExceeded",),
        retries=40, delay=10.0)
    ctx.on_cleanup(lambda: _delete_snapshot(ec2, snapshot_id))
    snap = _poll(lambda: _describe_snapshot(ec2, snapshot_id), lambda s: s["State"] == "completed",
                 timeout_s=1200, interval_s=5.0,
                 what=f"snapshot {label} ({snapshot_id}) of {volume_id} reaching 'completed'")
    assert snap["VolumeId"] == volume_id, (
        f"snapshot {label} names volume {snap['VolumeId']!r}, expected {volume_id!r}"
    )
    return snapshot_id


def _snapshot_blocks(ebs, snapshot_id, timeout_s=300, interval_s=5.0):
    """Every {BlockIndex: BlockToken} of a snapshot, PAGINATED and polled through the lag.

    The EBS direct-API plane can briefly trail EC2's completed-state signal with
    ResourceNotFoundException; the poll is bounded, so a snapshot the direct API never serves is a
    failure rather than a hang.
    """
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
                raise AssertionError(
                    f"ListSnapshotBlocks never served {snapshot_id} within {timeout_s}s: {exc!r}"
                ) from exc
            time.sleep(interval_s)


def _changed_blocks(ebs, first_id, second_id, timeout_s=300, interval_s=5.0):
    """Every changed BlockIndex between two snapshots, PAGINATED and polled through the same lag."""
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
                raise AssertionError(
                    f"ListChangedBlocks never served {first_id} -> {second_id} within "
                    f"{timeout_s}s: {exc!r}"
                ) from exc
            time.sleep(interval_s)


def _block_bytes(ebs, snapshot_id, block_index, block_token):
    """The raw 512 KiB of one snapshot block, as the EBS direct API serves it."""
    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=block_index,
                                 BlockToken=block_token)
    return got["BlockData"].read()


def _expected_block(marker):
    """The exact 512 KiB the guest writes for `marker`, computed HOST-side.

    The guest builds the block with `awk 'BEGIN{for(...) print m}'` and truncates, so the content
    is (marker + newline) repeated and cut at the block boundary. Deriving it here is what makes
    these KNOWN bytes rather than a digest the guest merely echoes back.
    """
    unit = (marker + "\n").encode()
    return (unit * (_BLOCK // len(unit) + 1))[:_BLOCK]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects
    SendCommand with InvalidInstanceId until its agent has registered, so retrying that call polls
    an observable condition instead of sleeping a guessed interval. A host that never accepts a
    command is a FAIL — 'the machine never came up' is a fidelity defect, not an environment limit.
    """
    deadline = time.monotonic() + ready_timeout_s
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav dsnapinc lineage rejection",
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
    """Select the block device by its exact byte SIZE, never by path, waiting for it to appear.

    Nitro presents EBS as /dev/nvme?n1 in an order that is not the attachment order, so `/dev/sdf`
    is only a request. `-d` keeps partitions out, so the root volume's children cannot match. A
    device that never appears is a FAIL, not a wait to extend.
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
    """Write exactly one 512 KiB block, with no pipe into dd and no pipefail hazard.

    awk generates (marker + newline) until the file is larger than a block and `truncate` cuts it
    to exactly one; `yes ... | head -c` would be shorter but SIGPIPEs `yes`, which under
    `set -o pipefail` aborts the whole script. `conv=notrunc,fsync` leaves every other block
    untouched and forces this one out to the volume before dd returns.
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
    """Report the sha256 of every block, read with O_DIRECT so the page cache cannot answer."""
    return [
        'OUT=""',
        f'for i in $(seq 0 {_N_BLOCKS - 1}); do',
        f'  S=$(dd if="$DEV" bs={_BLOCK} skip="$i" count=1 iflag=direct status=none '
        "| sha256sum | cut -d' ' -f1)",
        '  OUT="$OUT b$i=$S"',
        'done',
        f'echo "{line_marker} dev=$DEV$OUT"',
    ]


# ===== end helpers =====


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """ListChangedBlocks refuses a pair of snapshots from different volumes with ValidationException
    and lists no blocks, while each snapshot reads alone and a same-lineage pair names exactly the
    one block the guest rewrote: a diff across unrelated volumes would be a silently wrong answer."""
    ec2 = ctx.client("ec2")
    ebs = ctx.client("ebs")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dsnapinc-lineage-rejection"
    nonce = ctx.unique_name("dsnapinc-")

    # Known bytes: a distinct marker per volume per block, plus the one replacement.
    markers = {("a", i): f"{nonce}-a{i}" for i in range(_N_BLOCKS)}
    markers.update({("b", i): f"{nonce}-b{i}" for i in range(_N_BLOCKS)})
    changed_marker = f"{nonce}-a{_CHANGED_INDEX}-rewritten"
    want = {k: _sha(_expected_block(m)) for k, m in markers.items()}
    want_changed = _sha(_expected_block(changed_marker))
    assert len(set(want.values())) == len(want), (
        f"every block written by this check must be distinct, but the digests collide: {want!r}"
    )

    # --- everything decidable, before anything is created ---------------------
    az = _usable_az(ctx)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 SSM parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

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

    # --- two raw volumes of different sizes, attached to the one instance ------
    volumes = {}
    for label, gib, device in (("a", _A_GIB, "/dev/sdf"), ("b", _B_GIB, "/dev/sdg")):
        vid = ec2.create_volume(
            AvailabilityZone=az, Size=gib, VolumeType="gp3",
            TagSpecifications=[{"ResourceType": "volume",
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}],
        )["VolumeId"]
        ctx.on_cleanup(lambda v=vid: _detach_and_delete_volume(ec2, v))
        _poll(lambda v=vid: _describe_volume(ec2, v)["State"], lambda s: s == "available",
              timeout_s=300, interval_s=3.0, what=f"volume {label} ({vid}) reaching 'available'")
        ec2.attach_volume(VolumeId=vid, InstanceId=instance_id, Device=device)
        _poll(lambda v=vid: _describe_volume(ec2, v)["Attachments"],
              lambda a: bool(a) and a[0]["State"] == "attached", timeout_s=300, interval_s=3.0,
              what=f"volume {label} ({vid}) reaching 'attached' on {instance_id}")
        volumes[label] = vid
    assert volumes["a"] != volumes["b"], (
        f"the two volumes must be different resources, got {volumes!r}"
    )

    # --- one guest command writes known bytes to BOTH volumes -----------------
    script = ["set -eu"]
    for label, size in (("a", _A_BYTES), ("b", _B_BYTES)):
        script += _find_dev(size)
        for i in range(_N_BLOCKS):
            script += _write_block_cmd(i, markers[(label, i)])
        script += _read_blocks_cmd(f"SIM2REAL-WROTE-{label.upper()}")
    out = _run_guest(ssm, instance_id, script, "writing known bytes to both volumes")
    reports = {}
    for label in ("a", "b"):
        rep = _report(out, f"SIM2REAL-WROTE-{label.upper()}")
        assert rep is not None, (
            f"the guest never reported what it wrote to volume {label}; its stdout was {out!r}"
        )
        for i in range(_N_BLOCKS):
            assert rep.get(f"b{i}") == want[(label, i)], (
                f"the guest read block {i} of volume {label} back as {rep.get(f'b{i}')!r}, but the "
                f"bytes this check told it to write hash to {want[(label, i)]!r}; it reported "
                f"{rep!r}"
            )
        reports[label] = rep
    assert reports["a"]["dev"] != reports["b"]["dev"], (
        f"the guest wrote both volumes through the same device {reports['a']['dev']!r}; the two are "
        f"selected by size, so nothing here is about two volumes"
    )

    # --- one snapshot per volume: two UNRELATED lineages, both non-empty ------
    snap_a1 = _snapshot_volume(ctx, ec2, volumes["a"], scenario, "a1")
    snap_b1 = _snapshot_volume(ctx, ec2, volumes["b"], scenario, "b1")
    a1_blocks, block_size = _snapshot_blocks(ebs, snap_a1)
    b1_blocks, _ = _snapshot_blocks(ebs, snap_b1)
    assert block_size == _BLOCK, (
        f"ListSnapshotBlocks reports BlockSize {block_size!r}; every offset here derives from "
        f"{_BLOCK}"
    )
    # POSITIVE CONTROL 1: each snapshot is individually readable by the very API that will refuse
    # the pair, so the refusal below cannot be "these snapshots are unreadable".
    assert set(a1_blocks) == set(range(_N_BLOCKS)), (
        f"snapshot a1 must serve the {_N_BLOCKS} blocks the guest wrote to volume a, but it served "
        f"{sorted(a1_blocks)!r}"
    )
    assert set(b1_blocks) == set(range(_N_BLOCKS)), (
        f"snapshot b1 must serve the {_N_BLOCKS} blocks the guest wrote to volume b, but it served "
        f"{sorted(b1_blocks)!r}"
    )
    assert _sha(_block_bytes(ebs, snap_b1, 0, b1_blocks[0])) == want[("b", 0)], (
        f"snapshot b1's block 0 does not hold volume b's known bytes {want[('b', 0)]!r}"
    )

    # --- THE NEGATIVE: the pair is refused, in both argument orders -----------
    forward, forward_message = _expect_error(
        lambda: ebs.list_changed_blocks(FirstSnapshotId=snap_a1, SecondSnapshotId=snap_b1),
        f"ListChangedBlocks({snap_a1} -> {snap_b1}) spans two unrelated volumes")
    assert forward == "ValidationException", (
        f"two snapshots of different volumes must be refused with 'ValidationException', got "
        f"{forward!r}"
    )
    assert forward_message == f"The snapshot {snap_a1} and {snap_b1} are not related.", (
        f"unexpected forward refusal message: {forward_message!r}"
    )
    reverse, reverse_message = _expect_error(
        lambda: ebs.list_changed_blocks(FirstSnapshotId=snap_b1, SecondSnapshotId=snap_a1),
        f"ListChangedBlocks({snap_b1} -> {snap_a1}) spans the same two unrelated volumes")
    assert reverse == "ValidationException", (
        f"the refusal is about relatedness, not argument order, so the reversed pair must also be "
        f"'ValidationException'; got {reverse!r}"
    )
    assert reverse_message == f"The snapshot {snap_b1} and {snap_a1} are not related.", (
        f"unexpected reverse refusal message: {reverse_message!r}"
    )

    # --- and the effect is ABSENT: no volume, snapshot or block moved ---------
    # On AWS, two ListSnapshotBlocks calls on one unchanged snapshot
    # return the same BlockIndex set under DIFFERENT BlockToken strings — the token is a
    # short-lived handle for fetching the block, not an identity for its content. So "nothing
    # moved" is asserted over the index set and over the BYTES, and never over the token.
    fresh = {}
    for label, snapshot_id, expect in (("a1", snap_a1, a1_blocks), ("b1", snap_b1, b1_blocks)):
        after, _ = _snapshot_blocks(ebs, snapshot_id)
        fresh[label] = after
        assert set(after) == set(expect), (
            f"the refused ListChangedBlocks changed what snapshot {label} serves: it now lists "
            f"{sorted(after)!r}, previously {sorted(expect)!r}"
        )
    for (label, snapshot_id, vol) in (("a1", snap_a1, "a"), ("b1", snap_b1, "b")):
        for index in range(_N_BLOCKS):
            got = _sha(_block_bytes(ebs, snapshot_id, index, fresh[label][index]))
            assert got == want[(vol, index)], (
                f"the refused ListChangedBlocks altered block {index} of snapshot {label}: it now "
                f"hashes to {got!r}, and the bytes the guest wrote hash to {want[(vol, index)]!r}"
            )
    for label in ("a", "b"):
        snap = _describe_snapshot(ec2, {"a": snap_a1, "b": snap_b1}[label])
        assert snap["State"] == "completed", (
            f"the refused call must leave snapshot {label} 'completed', it is now "
            f"{snap['State']!r}"
        )

    # --- POSITIVE CONTROL 2: the related pair answers, and names the one block -
    change = ["set -eu"] + _find_dev(_A_BYTES) \
        + _write_block_cmd(_CHANGED_INDEX, changed_marker) \
        + _read_blocks_cmd("SIM2REAL-CHANGED")
    changed_report = _report(
        _run_guest(ssm, instance_id, change,
                   f"rewriting block {_CHANGED_INDEX} of volume a in the guest"),
        "SIM2REAL-CHANGED")
    assert changed_report is not None, "the guest never reported volume a after the rewrite"
    assert changed_report.get(f"b{_CHANGED_INDEX}") == want_changed, (
        f"the guest read block {_CHANGED_INDEX} of volume a back as "
        f"{changed_report.get(f'b{_CHANGED_INDEX}')!r} after the rewrite, expected "
        f"{want_changed!r}; it reported {changed_report!r}"
    )

    snap_a2 = _snapshot_volume(ctx, ec2, volumes["a"], scenario, "a2")
    related = _changed_blocks(ebs, snap_a1, snap_a2)
    assert related == {_CHANGED_INDEX}, (
        f"the SAME call that was refused across lineages must answer within one, naming exactly the "
        f"block the guest rewrote ({_CHANGED_INDEX}); it named {sorted(related)!r}"
    )
    a2_blocks, _ = _snapshot_blocks(ebs, snap_a2)
    assert _sha(_block_bytes(ebs, snap_a2, _CHANGED_INDEX,
                             a2_blocks[_CHANGED_INDEX])) == want_changed, (
        f"snapshot a2 must serve the rewritten bytes {want_changed!r} at block {_CHANGED_INDEX}"
    )
    # ...and volume b, whose snapshot the refused call named, still holds its own bytes untouched.
    b1_again, _ = _snapshot_blocks(ebs, snap_b1)
    assert _sha(_block_bytes(ebs, snap_b1, _CHANGED_INDEX,
                             b1_again[_CHANGED_INDEX])) == want[("b", _CHANGED_INDEX)], (
        f"volume b's block {_CHANGED_INDEX} must still hold {want[('b', _CHANGED_INDEX)]!r} — "
        f"nothing in this check writes to volume b after the first command"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
