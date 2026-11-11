"""ebsio-snapshot-restored-into-another-availability-zone-carries-the-payload."""
from __future__ import annotations

import json
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ebsio-snapshot-restored-into-another-availability-zone-carries-the-payload"
GROUP = 'ebsio-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
#: 1 GiB, which cannot be confused with the AL2023 root volume (8 GiB) by size — that is how each
#: guest finds its device without a device name Nitro does not honour.
DATA_GIB = 1
DATA_BYTES = DATA_GIB * 1024 * 1024 * 1024
#: 1 MiB of nonce-derived payload rather than one line, so a truncating implementation cannot pass.
PAYLOAD_BYTES = 1024 * 1024

# ===== helpers (self-contained) =====


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

    Nothing ambient: a fresh account may have no default VPC. The
    CIDR is random in 10/8 because overlapping VPC CIDRs are legal (these VPCs are never peered),
    so a sibling run in the same account cannot collide. Egress exists because cloud-init reaches
    the network before it runs the user-data this check's assertions come from.
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


def _delete_subnet(ctx, subnet_id):
    """`_delete_net` retries DependencyViolation; only the subnet's own not-found counts as done."""
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


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE):
    """Launch ONE instance, tagged in the same call that creates it, so an abort cannot leave an
    untagged instance behind."""
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
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _create_volume(ctx, az, scenario, *, size_gib=DATA_GIB, **kw):
    return ctx.client("ec2").create_volume(
        AvailabilityZone=az, Size=size_gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-ebsio-")}]}],
        **kw,
    )["VolumeId"]


def _describe_volume(ctx, volume_id):
    """DescribeVolumes for one id, PAGINATED — the account is shared and pages are not ours alone."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _describe_snapshot(ctx, snapshot_id):
    """DescribeSnapshots for one id, PAGINATED — same reason as the volume read."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_snapshots").paginate(SnapshotIds=[snapshot_id]):
        for snap in page["Snapshots"]:
            if snap["SnapshotId"] == snapshot_id:
                return snap
    raise AssertionError(f"snapshot {snapshot_id} not found in any page of DescribeSnapshots")


def _detach_and_wait(ctx, volume_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound"):
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if _describe_volume(ctx, volume_id)["State"] == "available":
                return
        except (ClientError, AssertionError):
            return
        time.sleep(5)


def _delete_volume_when_free(ctx, volume_id, timeout_s=300):
    """Detach, then delete on a bounded retry: a volume cannot be deleted mid-detach."""
    ec2 = ctx.client("ec2")
    _detach_and_wait(ctx, volume_id)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            # A volume still detaching is refused as in use until the detach completes.
            if _code(exc) not in ("VolumeInUse", "IncorrectState") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_snapshot(ctx, snapshot_id, timeout_s=300):
    """Delete on a bounded retry: a snapshot in use by a volume that is still being created is
    refused with InvalidSnapshot.InUse, which converges once the restore finishes."""
    ec2 = ctx.client("ec2")
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


_FIND_DEV = (
    "DEV=\n"
    "for i in $(seq 1 200); do\n"
    f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1; exit}}')\n"
    '  [ -n "$DEV" ] && break\n'
    "  sleep 3\n"
    "done\n"
    'if [ -z "$DEV" ]; then echo "SIM2REAL-NODEV" > /dev/console; exit 1; fi\n'
    "DEV=/dev/$DEV\n"
)


def _writer_script(nonce):
    """Format the data volume, write a nonce-derived payload, UNMOUNT, and report.

    The unmount is load-bearing: it is what makes the snapshot taken afterwards a clean filesystem
    image the reader can mount read-only in another zone without journal recovery.
    """
    return (
        "#!/bin/bash\n"
        + _FIND_DEV +
        'mkfs.ext4 -q -F "$DEV" > /dev/null 2>&1\n'
        "mkdir -p /mnt/data\n"
        'mount "$DEV" /mnt/data\n'
        f'yes "{nonce}" | head -c {PAYLOAD_BYTES} > /mnt/data/payload.bin\n'
        f'printf "%s\\n" "{nonce}" > /mnt/data/nonce.txt\n'
        "sync\n"
        "SHA=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        "umount /mnt/data\n"
        'UUID=$(blkid -s UUID -o value "$DEV")\n'
        f'echo "SIM2REAL-WROTE {nonce} $SHA $UUID" > /dev/console\n'
    )


def _reader_script():
    """Mount the restored volume read-only in ANOTHER zone and report what is on it."""
    return (
        "#!/bin/bash\n"
        + _FIND_DEV +
        "mkdir -p /mnt/data\n"
        'if ! mount -o ro "$DEV" /mnt/data 2>/dev/null; then\n'
        '  echo "SIM2REAL-NOMOUNT" > /dev/console; exit 1\n'
        "fi\n"
        "if [ ! -f /mnt/data/payload.bin ]; then\n"
        '  echo "SIM2REAL-NOPAYLOAD $(ls /mnt/data | tr "\\n" "," )" > /dev/console; exit 1\n'
        "fi\n"
        "SHA=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        "N=$(cat /mnt/data/nonce.txt)\n"
        "SZ=$(stat -c %s /mnt/data/payload.bin)\n"
        'UUID=$(blkid -s UUID -o value "$DEV")\n'
        'echo "SIM2REAL-READ $N $SHA $UUID $SZ" > /dev/console\n'
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A volume restored from a snapshot in another availability zone carries the source filesystem
    byte for byte, down to the ext4 UUID minted in the source zone, while the source stays attached:
    a snapshot is regional, and no guest in the second zone can reach the first zone's volume."""
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ebsio-snapshot-cross-az"

    ami = _ssm_ami(ctx)
    usable = _usable_azs(ctx)
    assert len(usable) >= 2, (
        f"this check needs two availability zones that offer {INSTANCE_TYPE}; {ctx.region} offers "
        f"{usable!r}"
    )
    az_src, az_dst = usable[0], usable[1]
    assert az_src != az_dst, f"the two zones must differ, got {az_src!r} and {az_dst!r}"
    _vpc_id, subnets = _network(ctx, scenario, [az_src, az_dst])

    # Both instances up front: B blocks on its device appearing, so the boots overlap.
    a_id = _run_instance(ctx, ami=ami, subnet_id=subnets[az_src], scenario=scenario,
                         user_data=_writer_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnets[az_dst], scenario=scenario,
                         user_data=_reader_script())["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))

    source_id = _create_volume(ctx, az_src, scenario)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, source_id))
    _poll_until(lambda: _describe_volume(ctx, source_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"source volume {source_id} reaches 'available'")

    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance A {a_id} reaches 'running'")
    ec2.attach_volume(VolumeId=source_id, InstanceId=a_id, Device="/dev/sdf")
    _poll_until(lambda: _describe_volume(ctx, source_id)["Attachments"],
                lambda at: bool(at) and at[0]["State"] == "attached",
                timeout_s=300, interval_s=5,
                description=f"source volume {source_id} attaches to A {a_id}")

    # --- A writes the payload and unmounts, so the snapshot is a clean filesystem image ---
    a_text = _poll_until(lambda: _console(ctx, a_id),
                         lambda t: "SIM2REAL-WROTE" in t or "SIM2REAL-NODEV" in t,
                         timeout_s=900, interval_s=15,
                         description=f"guest A {a_id} reports what it wrote to {source_id}")
    a_fields = _console_fields(a_text, "SIM2REAL-WROTE")
    assert a_fields is not None, (
        f"guest A never reported a write — it said {_console_fields(a_text, 'SIM2REAL-')!r}; last "
        f"2KB of console was {a_text[-2048:]!r}"
    )
    assert len(a_fields) >= 4, (
        f"A's report must carry a nonce, a sha256 and a filesystem UUID, got {a_fields!r}"
    )
    a_nonce, a_sha, a_uuid = a_fields[1], a_fields[2], a_fields[3]
    assert a_nonce == nonce, f"guest A echoed nonce {a_nonce!r}, expected {nonce!r}"
    assert len(a_sha) == 64, f"guest A reported a malformed sha256 {a_sha!r}"
    assert len(a_uuid) == 36, f"guest A reported a malformed filesystem UUID {a_uuid!r}"

    # --- snapshot the volume in the source zone ---
    snapshot_id = ec2.create_snapshot(
        VolumeId=source_id, Description=f"sim2real {scenario} {nonce}",
        TagSpecifications=[{"ResourceType": "snapshot",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))
    snap = _poll_until(lambda: _describe_snapshot(ctx, snapshot_id),
                       lambda s: s["State"] == "completed",
                       timeout_s=1200, interval_s=10,
                       description=f"snapshot {snapshot_id} reaches 'completed'")
    assert snap["VolumeId"] == source_id, (
        f"the snapshot names volume {snap['VolumeId']!r}, expected {source_id!r}"
    )
    assert snap["VolumeSize"] == DATA_GIB, (
        f"the snapshot reports VolumeSize {snap['VolumeSize']!r}, expected {DATA_GIB!r}"
    )
    assert snap["Progress"] == "100%", (
        f"a completed snapshot reports Progress {snap['Progress']!r}, expected '100%'"
    )

    # --- restore it into the OTHER zone ---
    restored_id = ec2.create_volume(
        SnapshotId=snapshot_id, AvailabilityZone=az_dst, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-ebsio-")}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, restored_id))
    _poll_until(lambda: _describe_volume(ctx, restored_id)["State"], lambda s: s == "available",
                timeout_s=600, interval_s=5,
                description=f"restored volume {restored_id} reaches 'available'")
    restored = _describe_volume(ctx, restored_id)
    assert restored["SnapshotId"] == snapshot_id, (
        f"the restored volume names snapshot {restored['SnapshotId']!r}, expected {snapshot_id!r}"
    )
    assert restored["AvailabilityZone"] == az_dst, (
        f"the restored volume landed in {restored['AvailabilityZone']!r}, expected the OTHER zone "
        f"{az_dst!r}"
    )
    assert restored["Size"] == snap["VolumeSize"], (
        f"the restored volume is {restored['Size']!r} GiB but the snapshot was taken of "
        f"{snap['VolumeSize']!r} GiB"
    )

    # --- and the guest in that zone reads exactly what the guest in the first zone wrote ---
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance B {b_id} reaches 'running'")
    ec2.attach_volume(VolumeId=restored_id, InstanceId=b_id, Device="/dev/sdf")
    attached_b = _poll_until(
        lambda: _describe_volume(ctx, restored_id)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached",
        timeout_s=300, interval_s=5,
        description=f"restored volume {restored_id} attaches to B {b_id}")
    assert [a["InstanceId"] for a in attached_b] == [b_id], (
        f"the restored volume's attachment set is {attached_b!r}, expected exactly B {b_id!r}"
    )

    b_text = _poll_until(lambda: _console(ctx, b_id),
                         lambda t: "SIM2REAL-READ" in t or "SIM2REAL-NOMOUNT" in t
                         or "SIM2REAL-NOPAYLOAD" in t or "SIM2REAL-NODEV" in t,
                         timeout_s=900, interval_s=15,
                         description=f"guest B {b_id} reports what it read from {restored_id}")
    b_fields = _console_fields(b_text, "SIM2REAL-READ")
    assert b_fields is not None, (
        f"guest B never read the restored filesystem — it said "
        f"{_console_fields(b_text, 'SIM2REAL-NOMOUNT') or _console_fields(b_text, 'SIM2REAL-')!r}; "
        f"last 2KB of console was {b_text[-2048:]!r}"
    )
    assert len(b_fields) >= 5, (
        f"B's report must carry a nonce, a sha256, a filesystem UUID and the payload size, got "
        f"{b_fields!r}"
    )
    b_nonce, b_sha, b_uuid, b_size = b_fields[1], b_fields[2], b_fields[3], int(b_fields[4])
    assert b_nonce == nonce, (
        f"guest B read nonce {b_nonce!r} out of the restored volume, but guest A wrote {nonce!r}"
    )
    assert b_sha == a_sha, (
        f"the payload on the restored volume hashes to {b_sha!r} but was written as {a_sha!r} — the "
        f"snapshot did not carry the bytes across the zone boundary"
    )
    assert b_uuid == a_uuid, (
        f"the filesystem on the restored volume has UUID {b_uuid!r} but guest A minted {a_uuid!r} — "
        f"the restore provisioned a new filesystem instead of copying the snapshot"
    )
    assert b_size == PAYLOAD_BYTES, (
        f"the payload on the restored volume is {b_size} bytes, expected {PAYLOAD_BYTES}"
    )

    # --- the source volume is untouched in its own zone ---
    source_after = _describe_volume(ctx, source_id)
    assert source_after["AvailabilityZone"] == az_src, (
        f"the source volume moved to {source_after['AvailabilityZone']!r}, expected {az_src!r}"
    )
    assert [a["InstanceId"] for a in source_after["Attachments"]] == [a_id], (
        f"the restore changed the source volume's attachment set to "
        f"{source_after['Attachments']!r}, expected exactly A {a_id!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A resource in this
# VPC deletes asynchronously, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation while its ENIs remain: retry that code inside one window shared by the
# check's network deletes, then raise naming the ENIs still attached. Teardown-only.
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
