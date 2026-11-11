"""ebsio-online-volume-grow-preserves-the-bytes-and-the-guest-sees-the-new-capacity."""
from __future__ import annotations

import json
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ebsio-online-volume-grow-preserves-the-bytes-and-the-guest-sees-the-new-capacity"
GROUP = 'ebsio-data-plane'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
#: 1 GiB start, 3 GiB target. Both differ from the AL2023 root volume (8 GiB), which is how the
#: guest finds the device by size instead of by a device name Nitro does not honour.
START_GIB = 1
TARGET_GIB = 3
START_BYTES = START_GIB * 1024 * 1024 * 1024
TARGET_BYTES = TARGET_GIB * 1024 * 1024 * 1024
#: 1 MiB of nonce-derived payload: a truncating or canned implementation cannot reproduce the digest.
PAYLOAD_BYTES = 1024 * 1024
#: The write that can only land on capacity the grow actually added: 1200 MiB does not fit in a
#: 1 GiB volume, so its success is not a number the API reported but storage the guest used.
BEYOND_MIB = 1200
BEYOND_BYTES = BEYOND_MIB * 1024 * 1024


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


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

    An account may have no default VPC. The CIDR is random in 10/8 (overlap is legal, nothing is
    peered); egress exists because cloud-init reaches the network before it runs the user-data.
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
    """Launch one instance, tagged in the same call that creates it so an abort cannot skip it."""
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
        AvailabilityZone=az, Size=size_gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-ebsio-")}]}],
        **kw,
    )["VolumeId"]


def _describe_volume(ctx, volume_id):
    """DescribeVolumes for one id, paginated."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


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
        time.sleep(2)


def _delete_volume_when_free(ctx, volume_id, timeout_s=300):
    """Detach, then delete on a bounded retry: a volume cannot be deleted mid-detach."""
    ec2 = ctx.client("ec2")
    _detach_and_wait(ctx, volume_id)
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


def _guest_script(nonce):
    """User-data that writes a payload, waits for the volume to GROW UNDER IT, and re-reads.

    The device is found by byte size, never by name: Nitro exposes /dev/nvme1n1 where the API was
    told /dev/sdf, so a hardcoded path is the likeliest cause of a false failure in an EBS check.
    Each phase reports to /dev/console, which is the only channel out of a guest this check does
    not give a shell, and every failure path reports a distinguishable marker rather than hanging.
    """
    return (
        "#!/bin/bash\n"
        "DEV=\n"
        "for i in $(seq 1 120); do\n"
        f"  DEV=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {START_BYTES} {{print $1; exit}}')\n"
        '  [ -n "$DEV" ] && break\n'
        "  sleep 3\n"
        "done\n"
        'if [ -z "$DEV" ]; then echo "SIM2REAL-NODEV" > /dev/console; exit 1; fi\n'
        "DEV=/dev/$DEV\n"
        'mkfs.ext4 -q -F "$DEV" > /dev/null 2>&1\n'
        "mkdir -p /mnt/data\n"
        'mount "$DEV" /mnt/data\n'
        f'yes "{nonce}" | head -c {PAYLOAD_BYTES} > /mnt/data/payload.bin\n'
        "sync\n"
        "SHA=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        "FS1=$(df -B1 --output=size /mnt/data | tail -1 | tr -d ' ')\n"
        f'echo "SIM2REAL-BASE {nonce} $SHA $FS1" > /dev/console\n'
        # The grow happens from outside, while the filesystem stays mounted and in use.
        "GREW=\n"
        "for i in $(seq 1 200); do\n"
        f'  SZ=$(blockdev --getsize64 "$DEV")\n'
        f'  if [ "$SZ" = "{TARGET_BYTES}" ]; then GREW=$SZ; break; fi\n'
        "  sleep 3\n"
        "done\n"
        'if [ -z "$GREW" ]; then\n'
        '  echo "SIM2REAL-NOGROW $(blockdev --getsize64 "$DEV")" > /dev/console; exit 1\n'
        "fi\n"
        'resize2fs "$DEV" > /dev/null 2>&1\n'
        "FS2=$(df -B1 --output=size /mnt/data | tail -1 | tr -d ' ')\n"
        "SHA2=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        'echo "SIM2REAL-GROWN $GREW $SHA2 $FS2" > /dev/console\n'
        # A write larger than the ORIGINAL volume: it can only land on capacity the grow added.
        f"dd if=/dev/zero of=/mnt/data/beyond.bin bs=1M count={BEYOND_MIB} status=none\n"
        "sync\n"
        "WROTE=$(stat -c %s /mnt/data/beyond.bin)\n"
        "SHA3=$(sha256sum /mnt/data/payload.bin | cut -d' ' -f1)\n"
        'echo "SIM2REAL-BEYOND $WROTE $SHA3" > /dev/console\n'
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Growing an attached EBS volume under a mounted filesystem preserves the payload's sha256, the
    guest's block device and resized filesystem report the new capacity, and a write too large
    for the original volume then succeeds.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/recognize-expanded-volume-linux.html
    """
    ec2 = ctx.client("ec2")
    nonce = "sim2real-nonce-" + uuid.uuid4().hex
    scenario = "ebsio-online-grow"

    ami = _ssm_ami(ctx)
    az = _usable_azs(ctx)[0]
    _vpc_id, subnets = _network(ctx, scenario, [az])

    volume_id = _create_volume(ctx, az, scenario, size_gib=START_GIB)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, volume_id))
    _poll_until(lambda: _describe_volume(ctx, volume_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=2, ctx=ctx,
                description=f"volume {volume_id} reaches 'available'")
    created = _describe_volume(ctx, volume_id)
    assert created["Size"] == START_GIB, (
        f"the volume was created at Size {created['Size']!r}, expected {START_GIB!r}"
    )

    instance_id = _run_instance(ctx, ami=ami, subnet_id=subnets[az], scenario=scenario,
                                user_data=_guest_script(nonce))["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=2, ctx=ctx,
                description=f"instance {instance_id} reaches 'running'")

    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    attached = _poll_until(
        lambda: _describe_volume(ctx, volume_id)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached",
        timeout_s=300, interval_s=2, ctx=ctx,
        description=f"volume {volume_id} reaches 'attached' on {instance_id}")
    assert attached[0]["InstanceId"] == instance_id, (
        f"the attachment names {attached[0]['InstanceId']!r}, expected {instance_id!r}"
    )

    # --- the guest formats the device, writes 1 MiB of nonce-derived payload and reports ---
    base_text = _poll_until(lambda: _console(ctx, instance_id),
                            lambda t: "SIM2REAL-BASE" in t or "SIM2REAL-NODEV" in t,
                            timeout_s=900, interval_s=2, ctx=ctx,
                            description=f"guest {instance_id} reports the payload it wrote")
    base = _console_fields(base_text, "SIM2REAL-BASE")
    assert base is not None, (
        f"the guest never reported a write — it said "
        f"{_console_fields(base_text, 'SIM2REAL-')!r}; last 2KB of console was "
        f"{base_text[-2048:]!r}"
    )
    assert len(base) >= 4, (
        f"the base report must carry a nonce, a sha256 and a filesystem size, got {base!r}"
    )
    base_nonce, sha_before, fs_before = base[1], base[2], int(base[3])
    assert base_nonce == nonce, f"the guest echoed nonce {base_nonce!r}, expected {nonce!r}"
    assert len(sha_before) == 64, f"the guest reported a malformed sha256 {sha_before!r}"
    assert fs_before <= START_BYTES, (
        f"the filesystem reports {fs_before} bytes on a {START_BYTES}-byte device, which is "
        f"impossible — the guest is not looking at the volume this check attached"
    )

    # --- grow the volume while that filesystem stays mounted ---
    ec2.modify_volume(VolumeId=volume_id, Size=TARGET_GIB)
    mod = _poll_until(
        lambda: ec2.describe_volumes_modifications(
            VolumeIds=[volume_id])["VolumesModifications"][0],
        lambda m: m["ModificationState"] == "completed",
        timeout_s=900, interval_s=2, ctx=ctx,
        description=f"the modification of {volume_id} reaches 'completed'")
    assert mod["OriginalSize"] == START_GIB, (
        f"the modification record says the volume started at {mod['OriginalSize']!r}, expected "
        f"{START_GIB!r}"
    )
    assert mod["TargetSize"] == TARGET_GIB, (
        f"the modification record targets {mod['TargetSize']!r}, expected {TARGET_GIB!r}"
    )
    grown_api = _describe_volume(ctx, volume_id)
    assert grown_api["Size"] == TARGET_GIB, (
        f"after the modification completed DescribeVolumes still reports Size "
        f"{grown_api['Size']!r}, expected {TARGET_GIB!r}"
    )
    assert grown_api["State"] == "in-use", (
        f"the volume left 'in-use' during an ONLINE grow: {grown_api['State']!r}"
    )

    # --- the guest sees the new capacity and the old bytes are still there ---
    grown_text = _poll_until(lambda: _console(ctx, instance_id),
                             lambda t: "SIM2REAL-GROWN" in t or "SIM2REAL-NOGROW" in t,
                             timeout_s=900, interval_s=2, ctx=ctx,
                             description=f"guest {instance_id} reports the grown device")
    grown = _console_fields(grown_text, "SIM2REAL-GROWN")
    assert grown is not None, (
        f"the guest never saw the device grow — it said "
        f"{_console_fields(grown_text, 'SIM2REAL-NOGROW')!r}; last 2KB of console was "
        f"{grown_text[-2048:]!r}"
    )
    assert len(grown) >= 4, (
        f"the grown report must carry the device size, a sha256 and a filesystem size, got "
        f"{grown!r}"
    )
    dev_bytes, sha_after, fs_after = int(grown[1]), grown[2], int(grown[3])
    assert dev_bytes == TARGET_BYTES, (
        f"the guest's block device reports {dev_bytes} bytes, expected {TARGET_BYTES} — the API "
        f"reported the new size but the device the guest writes to did not grow"
    )
    assert sha_after == sha_before, (
        f"the payload hashes to {sha_after!r} after the grow but was written as {sha_before!r} — "
        f"the bytes did not survive the resize"
    )
    assert fs_after > fs_before * 2, (
        f"the mounted filesystem is {fs_after} bytes after resize2fs and was {fs_before} before; "
        f"a {START_GIB} -> {TARGET_GIB} GiB grow must more than double it"
    )

    # --- and a write that could not have fitted in the original volume succeeds ---
    beyond_text = _poll_until(lambda: _console(ctx, instance_id),
                              lambda t: "SIM2REAL-BEYOND" in t,
                              timeout_s=900, interval_s=2, ctx=ctx,
                              description=f"guest {instance_id} reports the post-grow write")
    beyond = _console_fields(beyond_text, "SIM2REAL-BEYOND")
    assert beyond is not None and len(beyond) >= 3, (
        f"the guest never reported the post-grow write, got {beyond!r}; last 2KB of console was "
        f"{beyond_text[-2048:]!r}"
    )
    wrote, sha_final = int(beyond[1]), beyond[2]
    assert wrote == BEYOND_BYTES, (
        f"the post-grow write landed {wrote} bytes, expected {BEYOND_BYTES} — the capacity the "
        f"grow added is reported but not usable"
    )
    assert wrote > START_BYTES, (
        f"the post-grow write of {wrote} bytes would have fitted in the original {START_BYTES}-byte "
        f"volume, so it proves nothing about the added capacity"
    )
    assert sha_final == sha_before, (
        f"after filling the grown volume the payload hashes to {sha_final!r}, but it was written "
        f"as {sha_before!r} — the pre-grow bytes were overwritten by the added capacity"
    )

    final = _describe_volume(ctx, volume_id)
    assert final["Size"] == TARGET_GIB, (
        f"the volume's final Size is {final['Size']!r}, expected {TARGET_GIB!r}"
    )
    assert [a["InstanceId"] for a in final["Attachments"]] == [instance_id], (
        f"the grow changed the attachment set to {final['Attachments']!r}, expected exactly "
        f"{instance_id!r}"
    )


# Network deletes wait (bounded) for AWS-managed ENIs to leave, since dependent resources delete
# asynchronously and an immediate delete fails with DependencyViolation. Teardown only.
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
