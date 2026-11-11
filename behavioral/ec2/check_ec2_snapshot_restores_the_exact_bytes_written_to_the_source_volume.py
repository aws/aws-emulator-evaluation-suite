"""ec2-snapshot-restores-the-exact-bytes-written-to-the-source-volume."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-snapshot-restores-the-exact-bytes-written-to-the-source-volume"
GROUP = 'ebs-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
DATA_GIB = 1
DATA_BYTES = DATA_GIB * 1024 * 1024 * 1024
PAYLOAD_BYTES = 1024 * 1024
PAYLOAD_1 = 'payload-1.bin'
PAYLOAD_2 = 'payload-2.bin'

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
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable


def _create_subnet(ctx, az, scenario):
    """A dedicated VPC and subnet in `az`, deleted after the instances in it terminate."""
    ec2 = ctx.client("ec2")
    tags = lambda rt: [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.207.0.0/16", TagSpecifications=tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_unblocked(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.207.1.0/24", AvailabilityZone=az, TagSpecifications=tags("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_when_unblocked(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _delete_when_unblocked(fn, timeout_s=300, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
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


def _create_volume(ctx, az, scenario, **kw):
    ec2 = ctx.client("ec2")
    params = dict(
        AvailabilityZone=az, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    params.update(kw)
    if "SnapshotId" not in params:
        params.setdefault("Size", DATA_GIB)
    return ec2.create_volume(**params)


def _describe_volume(ctx, volume_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_and_wait(ctx, volume_id, timeout_s=300):
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_volume(VolumeId=volume_id)
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


def _delete_volume_when_free(ctx, volume_id, timeout_s=420):
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound"):
            raise
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


def _delete_snapshot_bounded(ctx, snapshot_id, timeout_s=300):
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


def _describe_snapshot(ctx, snapshot_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_snapshots").paginate(SnapshotIds=[snapshot_id]):
        for snap in page["Snapshots"]:
            if snap["SnapshotId"] == snapshot_id:
                return snap
    raise AssertionError(f"snapshot {snapshot_id} not found in any page of DescribeSnapshots")


def _console(ctx, instance_id):
    """The instance's serial console text, AS RETURNED by GetConsoleOutput(Latest=True).

    Latest=True is required on Nitro instance types. Output is not decoded here: botocore's
    ``decode_console_output`` handler already base64-decodes it in place (and leaves it untouched
    when it is not valid base64), so decoding again turns the guest's own words into binary noise.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _console_fields(text, marker):
    """The whitespace fields of the last console line containing marker, starting AT the marker.

    Sliced at the marker rather than split over the whole line, because /dev/console is shared with
    the login getty. On AWS a guest report arrives as
    ``'ip-172-31-36-148 login: SIM2REAL-DISK nvme1n1 1073741824'``, so any parser that indexes from
    either end of the line reads the getty's words instead of the guest's.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


#: Both guest scripts find the data volume BY SIZE via lsblk and never by device path: nitro exposes
#: /dev/nvme1n1 where xen exposes /dev/xvdf, so a hardcoded name is the most likely false failure.
_FIND_DEV = (
    "find_dev() {\n"
    "  for i in $(seq 1 $((${1}/3))); do\n"
    f"    D=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1; exit}}')\n"
    '    if [ -n "$D" ]; then echo "/dev/$D"; return 0; fi\n'
    "    sleep 3\n"
    "  done\n"
    "  return 1\n"
    "}\n"
    "wait_gone() {\n"
    "  for i in $(seq 1 $((${1}/3))); do\n"
    f"    D=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1; exit}}')\n"
    '    if [ -z "$D" ]; then return 0; fi\n'
    "    sleep 3\n"
    "  done\n"
    "  return 1\n"
    "}\n"
)


def _writer_reader_script(nonce):
    """Instance A: write payload-1 to the source volume, report its sha256, then WAIT for the device
    to go away and for a NEW one of the same size to arrive — the restored volume — and report what
    it finds there.

    The device disappearing and reappearing IS the signal. Nothing here needs SSM, an instance
    profile or IMDS instance tags, so the check has no dependency outside EC2 itself.
    """
    return (
        "#!/bin/bash\n"
        + _FIND_DEV +
        'DEV=$(find_dev 600) || { echo "SIM2REAL-NODEV-1" > /dev/console; exit 1; }\n'
        'mkfs.ext4 -q -F "$DEV" > /dev/null 2>&1\n'
        "mkdir -p /mnt/src\n"
        'mount "$DEV" /mnt/src\n'
        f'yes "{nonce}" | head -c {PAYLOAD_BYTES} > /mnt/src/{PAYLOAD_1}\n'
        "sync\n"
        f"SHA=$(sha256sum /mnt/src/{PAYLOAD_1} | cut -d' ' -f1)\n"
        "umount /mnt/src\n"
        f'echo "SIM2REAL-WROTE {nonce} $SHA" > /dev/console\n'
        'wait_gone 600 || { echo "SIM2REAL-STILLTHERE" > /dev/console; exit 1; }\n'
        'RDEV=$(find_dev 900) || { echo "SIM2REAL-NODEV-2" > /dev/console; exit 1; }\n'
        "mkdir -p /mnt/restored\n"
        'mount -o ro "$RDEV" /mnt/restored\n'
        f"RSHA=$(sha256sum /mnt/restored/{PAYLOAD_1} | cut -d' ' -f1)\n"
        f'if [ -e /mnt/restored/{PAYLOAD_2} ]; then P2=present; else P2=absent; fi\n'
        "LS=$(ls -A /mnt/restored | tr '\\n' ',')\n"
        f'echo "SIM2REAL-READ {nonce} $RSHA $P2 $LS" > /dev/console\n'
    )


def _appender_script(nonce):
    """Instance B: write payload-2 to the SOURCE volume, strictly after the snapshot completed.

    A second machine does this rather than instance A, because A must stay free to receive the
    restored volume — and because the restored volume carries the same filesystem UUID as the
    source, so the two can never be mounted on one host.
    """
    return (
        "#!/bin/bash\n"
        + _FIND_DEV +
        'DEV=$(find_dev 900) || { echo "SIM2REAL-NODEV-B" > /dev/console; exit 1; }\n'
        "mkdir -p /mnt/src\n"
        'mount "$DEV" /mnt/src\n'
        f'yes "{nonce}-after" | head -c {PAYLOAD_BYTES} > /mnt/src/{PAYLOAD_2}\n'
        "sync\n"
        f"SHA=$(sha256sum /mnt/src/{PAYLOAD_2} | cut -d' ' -f1)\n"
        f"LS=$(ls -A /mnt/src | tr '\\n' ',')\n"
        "umount /mnt/src\n"
        f'echo "SIM2REAL-APPENDED {nonce} $SHA $LS" > /dev/console\n'
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A volume created from a snapshot holds the source's bytes as of snapshot time, and data
    written to the source after the snapshot completed is absent from it: a point-in-time copy,
    read inside a guest over real bytes."""
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-snapshot-point-in-time"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    subnet_id = _create_subnet(ctx, az, scenario)

    source = _create_volume(ctx, az, scenario)["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, source))
    _poll_until(lambda: _describe_volume(ctx, source)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"source volume {source} reaches 'available'")

    a_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                         user_data=_writer_reader_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                         user_data=_appender_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))

    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=420, interval_s=5, description=f"instance A {a_id} reaches 'running'")
    ec2.attach_volume(VolumeId=source, InstanceId=a_id, Device="/dev/sdf")
    _poll_until(lambda: _describe_volume(ctx, source)["Attachments"],
                lambda at: bool(at) and at[0]["State"] == "attached", timeout_s=240, interval_s=5,
                description=f"source volume {source} attaches to instance A {a_id}")

    # --- A writes payload-1 and reports its digest ---
    a_wrote = _poll_until(lambda: _console_fields(_console(ctx, a_id), "SIM2REAL-WROTE"),
                          lambda f: f is not None, timeout_s=420, interval_s=15,
                          description=f"instance A {a_id} reports writing {PAYLOAD_1}")
    assert len(a_wrote) == 3 and a_wrote[1] == nonce, (
        f"instance A's write report must be 'SIM2REAL-WROTE <nonce> <sha256>', got {a_wrote!r}"
    )
    sha_1 = a_wrote[2]
    assert len(sha_1) == 64, f"instance A reported a malformed sha256 {sha_1!r}"

    # --- the snapshot is the point in time ---
    snapshot_id = ec2.create_snapshot(
        VolumeId=source, Description=f"sim2real {scenario} {nonce}",
        TagSpecifications=[{"ResourceType": "snapshot",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot_bounded(ctx, snapshot_id))
    snap = _poll_until(lambda: _describe_snapshot(ctx, snapshot_id),
                       lambda s: s["State"] in ("completed", "error"),
                       timeout_s=900, interval_s=15,
                       description=f"snapshot {snapshot_id} of {source} completes")
    assert snap["State"] == "completed", (
        f"snapshot {snapshot_id} reached State {snap['State']!r}, expected 'completed'"
    )
    assert snap["Progress"] == "100%", (
        f"a completed snapshot must report Progress '100%', got {snap['Progress']!r}"
    )
    assert snap["VolumeId"] == source, (
        f"snapshot {snapshot_id} names source volume {snap['VolumeId']!r}, expected {source!r}"
    )
    source_size = _describe_volume(ctx, source)["Size"]
    assert snap["VolumeSize"] == source_size, (
        f"the snapshot declares VolumeSize {snap['VolumeSize']!r} but the source volume is "
        f"{source_size!r} GiB"
    )

    # --- payload-2 is written to the SOURCE strictly after that point, by a second machine ---
    _detach_and_wait(ctx, source)
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=420, interval_s=5, description=f"instance B {b_id} reaches 'running'")
    ec2.attach_volume(VolumeId=source, InstanceId=b_id, Device="/dev/sdf")
    _poll_until(lambda: _describe_volume(ctx, source)["Attachments"],
                lambda at: bool(at) and at[0]["State"] == "attached", timeout_s=240, interval_s=5,
                description=f"source volume {source} attaches to instance B {b_id}")
    b_appended = _poll_until(lambda: _console_fields(_console(ctx, b_id), "SIM2REAL-APPENDED"),
                             lambda f: f is not None, timeout_s=420, interval_s=15,
                             description=f"instance B {b_id} reports writing {PAYLOAD_2}")
    assert len(b_appended) >= 4 and b_appended[1] == nonce, (
        f"instance B's report must be 'SIM2REAL-APPENDED <nonce> <sha256> <listing>', got "
        f"{b_appended!r}"
    )
    assert PAYLOAD_2 in b_appended[3], (
        f"instance B's own listing of the SOURCE volume must contain {PAYLOAD_2!r} — otherwise the "
        f"absence assertion below is vacuous. It listed {b_appended[3]!r}"
    )

    # --- restore the snapshot into a new volume and hand it to instance A ---
    restored_v = _create_volume(ctx, az, scenario, SnapshotId=snapshot_id)
    restored = restored_v["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, restored))
    assert restored_v["Size"] == snap["VolumeSize"], (
        f"a volume restored without an explicit Size must take the snapshot's VolumeSize "
        f"{snap['VolumeSize']!r}, got {restored_v['Size']!r}"
    )
    assert restored_v["SnapshotId"] == snapshot_id, (
        f"the restored volume names SnapshotId {restored_v.get('SnapshotId')!r}, expected "
        f"{snapshot_id!r}"
    )
    _poll_until(lambda: _describe_volume(ctx, restored)["State"], lambda s: s == "available",
                timeout_s=420, interval_s=5,
                description=f"restored volume {restored} reaches 'available'")
    ec2.attach_volume(VolumeId=restored, InstanceId=a_id, Device="/dev/sdg")
    _poll_until(lambda: _describe_volume(ctx, restored)["Attachments"],
                lambda at: bool(at) and at[0]["State"] == "attached", timeout_s=240, interval_s=5,
                description=f"restored volume {restored} attaches to instance A {a_id}")

    a_read = _poll_until(lambda: _console_fields(_console(ctx, a_id), "SIM2REAL-READ"),
                         lambda f: f is not None, timeout_s=600, interval_s=15,
                         description=f"instance A {a_id} reports what the restored volume holds")
    assert len(a_read) >= 5 and a_read[1] == nonce, (
        f"instance A's read report must be 'SIM2REAL-READ <nonce> <sha256> <present|absent> "
        f"<listing>', got {a_read!r}"
    )
    restored_sha, payload2_state, listing = a_read[2], a_read[3], a_read[4]

    # --- what the snapshot captured ---
    assert restored_sha == sha_1, (
        f"{PAYLOAD_1} on the restored volume hashes to {restored_sha!r} but instance A wrote "
        f"{sha_1!r} to the source before the snapshot — the restore is not byte-identical"
    )
    # --- and what it did NOT capture ---
    assert payload2_state == "absent", (
        f"{PAYLOAD_2} was written to the source AFTER snapshot {snapshot_id} completed, so it must "
        f"be absent from the restored volume; instance A reported {payload2_state!r} and listed "
        f"{listing!r}"
    )
    assert PAYLOAD_2 not in listing, (
        f"instance A's directory listing of the restored volume mentions {PAYLOAD_2!r}: {listing!r}"
    )
    assert PAYLOAD_1 in listing, (
        f"instance A's directory listing of the restored volume does not mention {PAYLOAD_1!r}: "
        f"{listing!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
