"""ec2-ebs-volume-bytes-survive-detach-and-reattach-to-a-different-instance."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-ebs-volume-bytes-survive-detach-and-reattach-to-a-different-instance"
GROUP = 'ebs-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
#: 1 GiB, chosen so it cannot be confused with the AL2023 root volume (8 GiB) by size, which is
#: how the guest finds the device without hardcoding a name.
DATA_GIB = 1
DATA_BYTES = DATA_GIB * 1024 * 1024 * 1024
#: 1 MiB of deterministic payload rather than one line, so a truncating implementation cannot pass.
PAYLOAD_MIB = 1

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
    vpc_id = ec2.create_vpc(CidrBlock="10.206.0.0/16", TagSpecifications=tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_when_unblocked(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.206.1.0/24", AvailabilityZone=az, TagSpecifications=tags("subnet")
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


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE, **kw):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
        **kw,
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


def _create_volume(ctx, az, scenario, size_gib=DATA_GIB, **kw):
    ec2 = ctx.client("ec2")
    vol = ec2.create_volume(
        AvailabilityZone=az, Size=size_gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
        **kw,
    )
    return vol["VolumeId"]


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


def _delete_volume_when_free(ctx, volume_id, timeout_s=300):
    """Detach if needed, then delete on a bounded retry loop — a volume cannot be deleted while
    an attachment is still detaching."""
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


def _guest_script(*, role, nonce, wait_s):
    """A user-data script that finds the data volume BY SIZE and never by device name.

    Nitro exposes /dev/nvme1n1 where xen exposes /dev/xvdf, so a hardcoded path is the single most
    likely cause of a false failure in an EBS check. lsblk's byte size is the portable handle: the
    data volume is 1 GiB and the AL2023 root volume is 8 GiB, so the match is unambiguous.
    """
    find_dev = (
        "DEV=\n"
        f"for i in $(seq 1 {wait_s // 3}); do\n"
        f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1; exit}}')\n"
        '  [ -n "$DEV" ] && break\n'
        "  sleep 3\n"
        "done\n"
        'if [ -z "$DEV" ]; then echo "SIM2REAL-NODEV" > /dev/console; exit 1; fi\n'
        'DEV=/dev/$DEV\n'
    )
    if role == "writer":
        return (
            "#!/bin/bash\n"
            + find_dev +
            'mkfs.ext4 -q -F "$DEV" > /dev/null 2>&1\n'
            "mkdir -p /mnt/data\n"
            'mount "$DEV" /mnt/data\n'
            # 1 MiB whose CONTENT is derived from the per-run nonce, so neither a truncating
            # implementation nor a canned blob can reproduce the digest.
            f'yes "{nonce}" | head -c {PAYLOAD_MIB * 1024 * 1024} > /mnt/data/payload.bin\n'
            f'printf "%s\\n" "{nonce}" > /mnt/data/nonce.txt\n'
            "sync\n"
            "SHA=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
            "umount /mnt/data\n"
            'UUID=$(blkid -s UUID -o value "$DEV")\n'
            f'echo "SIM2REAL-WROTE {nonce} $SHA $UUID" > /dev/console\n'
        )
    return (
        "#!/bin/bash\n"
        + find_dev +
        "mkdir -p /mnt/data\n"
        'mount -o ro "$DEV" /mnt/data\n'
        "SHA=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        "N=$(cat /mnt/data/nonce.txt)\n"
        'UUID=$(blkid -s UUID -o value "$DEV")\n'
        'echo "SIM2REAL-READ $N $SHA $UUID" > /dev/console\n'
    )


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Bytes one instance writes to an EBS volume read back byte-identical on a different instance
    after detach and reattach, and the ext4 UUID minted by the first guest proves the volume moved
    rather than being recreated blank."""
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ec2-ebs-bytes-move"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    subnet_id = _create_subnet(ctx, az, scenario)

    volume_id = _create_volume(ctx, az, scenario)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, volume_id))
    _poll_until(lambda: _describe_volume(ctx, volume_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"volume {volume_id} reaches 'available'")
    created = _describe_volume(ctx, volume_id)
    assert created["Attachments"] == [], (
        f"a freshly created volume must have no attachments, got {created['Attachments']!r}"
    )

    # Both instances up front: B's guest blocks on its device appearing, so the boots overlap.
    a_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                         user_data=_guest_script(role="writer", nonce=nonce,
                                                 wait_s=600))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, a_id))
    b_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                         user_data=_guest_script(role="reader", nonce=nonce,
                                                 wait_s=1200))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, b_id))

    _poll_until(lambda: _instance_state(ctx, a_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance A {a_id} reaches 'running'")
    ec2.attach_volume(VolumeId=volume_id, InstanceId=a_id, Device="/dev/sdf")
    attached_a = _poll_until(
        lambda: _describe_volume(ctx, volume_id)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached",
        timeout_s=300, interval_s=5,
        description=f"volume {volume_id} reaches 'attached' on instance A {a_id}")
    assert attached_a[0]["InstanceId"] == a_id, (
        f"the attachment names {attached_a[0]['InstanceId']!r}, expected instance A {a_id!r}"
    )

    # --- A writes 1 MiB and reports the sha256 plus the filesystem UUID it minted ---
    a_text = _poll_until(lambda: _console(ctx, a_id),
                         lambda t: "SIM2REAL-WROTE" in t or "SIM2REAL-NODEV" in t,
                         timeout_s=1200, interval_s=15,
                         description=f"instance A {a_id} reports what it wrote to {volume_id}")
    a_fields = _console_fields(a_text, "SIM2REAL-WROTE")
    assert a_fields is not None, (
        f"instance A never reported a write — it said {_console_fields(a_text, 'SIM2REAL-')!r}; "
        f"last 2KB of console was {a_text[-2048:]!r}"
    )
    assert len(a_fields) >= 4, (
        f"instance A's report must carry a nonce, a sha256 and a filesystem UUID, got {a_fields!r}"
    )
    a_nonce, a_sha, a_uuid = a_fields[1], a_fields[2], a_fields[3]
    assert a_nonce == nonce, f"instance A echoed nonce {a_nonce!r}, expected {nonce!r}"
    assert len(a_sha) == 64, f"instance A reported a malformed sha256 {a_sha!r}"
    assert len(a_uuid) == 36, f"instance A reported a malformed filesystem UUID {a_uuid!r}"

    # --- the volume really leaves A ---
    _detach_and_wait(ctx, volume_id)
    detached = _describe_volume(ctx, volume_id)
    assert detached["State"] == "available", (
        f"after the detach the volume state is {detached['State']!r}, expected 'available'"
    )
    assert detached["Attachments"] == [], (
        f"a detached volume must report no attachments, got {detached['Attachments']!r}"
    )

    # --- and arrives at B, which reads back what A wrote ---
    _poll_until(lambda: _instance_state(ctx, b_id), lambda s: s == "running",
                timeout_s=600, interval_s=5, description=f"instance B {b_id} reaches 'running'")
    ec2.attach_volume(VolumeId=volume_id, InstanceId=b_id, Device="/dev/sdf")
    attached_b = _poll_until(
        lambda: _describe_volume(ctx, volume_id)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached",
        timeout_s=300, interval_s=5,
        description=f"volume {volume_id} reaches 'attached' on instance B {b_id}")
    assert len(attached_b) == 1 and attached_b[0]["InstanceId"] == b_id, (
        f"after the move the volume must be attached to exactly instance B {b_id!r}, got "
        f"{attached_b!r}"
    )

    b_text = _poll_until(lambda: _console(ctx, b_id),
                         lambda t: "SIM2REAL-READ" in t or "SIM2REAL-NODEV" in t,
                         timeout_s=1200, interval_s=15,
                         description=f"instance B {b_id} reports what it read from {volume_id}")
    b_fields = _console_fields(b_text, "SIM2REAL-READ")
    assert b_fields is not None, (
        f"instance B never reported a read — it said {_console_fields(b_text, 'SIM2REAL-')!r}; "
        f"last 2KB of console was {b_text[-2048:]!r}"
    )
    assert len(b_fields) >= 4, (
        f"instance B's report must carry a nonce, a sha256 and a filesystem UUID, got {b_fields!r}"
    )
    b_nonce, b_sha, b_uuid = b_fields[1], b_fields[2], b_fields[3]

    assert b_sha == a_sha, (
        f"the {PAYLOAD_MIB} MiB instance B read back hashes to {b_sha!r} but instance A wrote "
        f"{a_sha!r} — the bytes did not survive the move"
    )
    assert b_nonce == nonce and a_nonce == nonce, (
        f"instance B read nonce {b_nonce!r} where instance A wrote {a_nonce!r} (expected {nonce!r})"
    )
    assert b_uuid == a_uuid, (
        f"the filesystem UUID instance B sees is {b_uuid!r} but instance A minted {a_uuid!r} — the "
        f"volume was recreated, not moved"
    )

    moved = _describe_volume(ctx, volume_id)
    assert moved["Size"] == created["Size"] == DATA_GIB, (
        f"the volume's Size changed across the move: {created['Size']!r} -> {moved['Size']!r}"
    )
    assert moved["AvailabilityZone"] == created["AvailabilityZone"] == az, (
        f"the volume's AvailabilityZone changed across the move: "
        f"{created['AvailabilityZone']!r} -> {moved['AvailabilityZone']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
