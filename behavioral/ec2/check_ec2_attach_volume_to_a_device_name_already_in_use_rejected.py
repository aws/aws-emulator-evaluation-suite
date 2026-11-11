"""ec2-attach-volume-to-a-device-name-already-in-use-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-attach-volume-to-a-device-name-already-in-use-rejected"
GROUP = 'ebs-attachment-rejected'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"
#: Distinct sizes let the guest tell the volumes apart: Nitro does not honour the device path.
#: Both differ from the AL2023 root volume (8 GiB).
_FIRST_GIB = 1
_SECOND_GIB = 2
_DEVICE = "/dev/sdf"
_FREE_DEVICE = "/dev/sdg"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The ClientError (code, message) raised by fn; raises if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(
        f"the call was expected to be refused by real AWS but it SUCCEEDED, returning {result!r}"
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="", ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is 'available' and offers the instance type.

    Offerings do not report zone state, and AZ names are per-account aliases, so none is hard-coded.
    """
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ in this region offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _retry_delete(fn, retries=60, delay=2.0):
    """Delete, tolerating the bounded dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                             "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                             "InvalidAssociationID.NotFound", "InvalidVolume.NotFound",
                             "Gateway.NotAttached"):
                return None
            raise


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    Not the default VPC: an account need not have one. The SSM agent needs egress to its endpoint.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
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
    role = ctx.unique_name("sim2real-att-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav ebs attachment role",
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
    """Terminate and wait for 'terminated': the ENI only clears then, which VPC teardown needs."""
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
        time.sleep(2)


def _detach_and_delete_volume(ec2, volume_id, timeout_s=300):
    """Detach if attached, wait for 'available', then delete; an in-use volume cannot be deleted."""
    def _vol():
        try:
            return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
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


def _make_volume(ctx, ec2, az, gib, scenario):
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
          lambda s: s == "available", ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2.0,
          what=f"volume {volume_id} reaching 'available'")
    return volume_id


def _attachments(ec2, volume_id):
    return ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0].get("Attachments") or []


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=420, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand is retried on InvalidInstanceId: a fresh host rejects it until its agent registers.
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
                Comment="sim2real-behav ebs attachment",
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
                ctx=ctx, timeout_s=_budget_s(ctx, run_timeout_s), interval_s=2.0,
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


def _guest_disk_sizes(ctx, ssm, instance_id, what):
    """The set of whole-disk byte sizes the guest can see.

    Nitro presents EBS volumes as /dev/nvme?n1 in no fixed order, so disks are told apart by size.
    """
    out = _run_guest(ctx, ssm, instance_id, [
        "set -uo pipefail",
        'echo "SIM2REAL-DISKS sizes=$(lsblk -dn -b -o SIZE | sort -n | tr \'\\n\' \',\')"',
    ], what)
    rep = _report(out, "SIM2REAL-DISKS")
    assert rep and rep.get("sizes"), f"{what}: the guest reported no disks at all; stdout {out!r}"
    return {int(s) for s in rep["sizes"].split(",") if s.strip()}


def _guest_roundtrip(ctx, ssm, instance_id, gib, nonce, what):
    """Make a filesystem on the disk of exactly `gib` GiB, write `nonce`, read it back."""
    want = gib * 1024 * 1024 * 1024
    out = _run_guest(ctx, ssm, instance_id, [
        "set -euo pipefail",
        # The API reports 'attached' before the guest's NVMe hot-plug lands; wait for the disk.
        "for _ in $(seq 1 30); do "
        f'D=$(lsblk -dn -b -o NAME,SIZE | awk -v w={want} \'$2==w {{print $1; exit}}\'); '
        '[ -n "$D" ] && break; sleep 1; done',
        'if [ -z "$D" ]; then echo "NO-SUCH-DISK"; lsblk -dn -b -o NAME,SIZE; exit 1; fi',
        'mkfs.ext4 -qF "/dev/$D"',
        f"mkdir -p /mnt/v{gib}",
        f'mount "/dev/$D" /mnt/v{gib}',
        f'echo "{nonce}" > /mnt/v{gib}/nonce',
        "sync",
        f"umount /mnt/v{gib}",
        f'mount -o ro "/dev/$D" /mnt/v{gib}',
        f'echo "SIM2REAL-RT dev=$D value=$(cat /mnt/v{gib}/nonce)"',
        f"umount /mnt/v{gib}",
    ], what)
    rep = _report(out, "SIM2REAL-RT")
    assert rep and rep.get("value") == nonce, (
        f"{what}: the {gib} GiB volume did not round-trip the nonce {nonce!r} inside the guest; "
        f"the guest reported {rep!r} (stdout {out!r})"
    )
    return rep["dev"]


def _guest_read(ctx, ssm, instance_id, gib, what):
    """Read back whatever nonce the disk of exactly `gib` GiB already carries."""
    want = gib * 1024 * 1024 * 1024
    out = _run_guest(ctx, ssm, instance_id, [
        "set -uo pipefail",
        f'D=$(lsblk -dn -b -o NAME,SIZE | awk -v w={want} \'$2==w {{print $1; exit}}\')',
        'V=absent',
        f"mkdir -p /mnt/r{gib}",
        f'if [ -n "$D" ]; then if mount -o ro "/dev/$D" /mnt/r{gib} 2>/dev/null; then '
        f'V=$(cat /mnt/r{gib}/nonce 2>/dev/null || echo no-file); umount /mnt/r{gib}; '
        'else V=unmountable; fi; else D=no-device; fi',
        'echo "SIM2REAL-READ dev=$D value=$V"',
    ], what)
    rep = _report(out, "SIM2REAL-READ")
    assert rep, f"{what}: the guest emitted no read report; stdout {out!r}"
    return rep


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """Attaching a volume at a device name already in use is refused with InvalidParameterValue.

    The volume stays 'available', the guest sees no new disk and the first volume is undisturbed;
    the same volume then attaches at a free device name and round-trips a nonce in the guest.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "ec2-attach-device-name-in-use"
    nonce_first = ctx.unique_name("sim2real-first-")
    nonce_second = ctx.unique_name("sim2real-second-")

    az = _usable_az(ec2)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

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
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2.0,
          what=f"instance {instance_id} reaching 'running'")

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
          ctx=ctx, timeout_s=_budget_s(ctx, 420), interval_s=2.0,
          what=f"the SSM agent on {instance_id} coming Online")

    baseline = _guest_disk_sizes(ctx, ssm, instance_id, "the guest's disks before any attachment")

    # The attachment that legitimately occupies the device name.
    first = _make_volume(ctx, ec2, az, _FIRST_GIB, scenario)
    ec2.attach_volume(VolumeId=first, InstanceId=instance_id, Device=_DEVICE)
    _poll(lambda: _attachments(ec2, first),
          lambda a: bool(a) and a[0]["State"] == "attached",
          ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2.0,
          what=f"volume {first} reaching 'attached' at {_DEVICE}")
    assert _attachments(ec2, first)[0]["Device"] == _DEVICE, (
        f"the attachment reports device {_attachments(ec2, first)[0]!r}, expected {_DEVICE!r}"
    )
    first_dev = _guest_roundtrip(ctx, ssm, instance_id, _FIRST_GIB, nonce_first,
                                 f"round-tripping a nonce through {first}")
    with_first = _guest_disk_sizes(ctx, ssm, instance_id, "the guest's disks with one volume attached")
    assert _FIRST_GIB * 1024 ** 3 in with_first, (
        f"the {_FIRST_GIB} GiB volume {first} is attached but the guest cannot see a disk of that "
        f"size; it sees {sorted(with_first)!r}"
    )

    second = _make_volume(ctx, ec2, az, _SECOND_GIB, scenario)
    code, message = _error(
        lambda: ec2.attach_volume(VolumeId=second, InstanceId=instance_id, Device=_DEVICE)
    )
    assert code == "InvalidParameterValue", (
        f"attaching {second} at {_DEVICE!r}, which {first} already occupies on {instance_id}, must "
        f"be refused with InvalidParameterValue; real AWS returned {code!r}"
    )
    assert message == (f"Invalid value '{_DEVICE}' for unixDevice. Attachment point {_DEVICE} is "
                       "already in use"), message

    assert _attachments(ec2, second) == [], (
        f"the refused volume {second} must still be unattached, but it reports "
        f"{_attachments(ec2, second)!r}"
    )
    assert ec2.describe_volumes(VolumeIds=[second])["Volumes"][0]["State"] == "available", (
        f"the refused volume {second} must stay 'available', but it is "
        f"{ec2.describe_volumes(VolumeIds=[second])['Volumes'][0]['State']!r}"
    )
    after_refusal = _guest_disk_sizes(ctx, ssm, instance_id, "the guest's disks after the refused attach")
    assert _SECOND_GIB * 1024 ** 3 not in after_refusal, (
        f"the attach of {second} was refused, so no {_SECOND_GIB} GiB disk may appear inside the "
        f"guest — but it sees {sorted(after_refusal)!r}"
    )
    assert after_refusal == with_first, (
        f"a refused attach must not change the guest's block devices at all; they went from "
        f"{sorted(with_first)!r} to {sorted(after_refusal)!r}"
    )
    still = _guest_read(ctx, ssm, instance_id, _FIRST_GIB, "re-reading the first volume after the refusal")
    assert still.get("value") == nonce_first, (
        f"the refused attach disturbed the volume that legitimately held {_DEVICE!r}: its nonce "
        f"read back as {still!r}, expected {nonce_first!r}"
    )

    # Positive control: the same volume at a free device name.
    ec2.attach_volume(VolumeId=second, InstanceId=instance_id, Device=_FREE_DEVICE)
    _poll(lambda: _attachments(ec2, second),
          lambda a: bool(a) and a[0]["State"] == "attached",
          ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2.0,
          what=f"volume {second} reaching 'attached' at {_FREE_DEVICE}")
    second_dev = _guest_roundtrip(ctx, ssm, instance_id, _SECOND_GIB, nonce_second,
                                  f"round-tripping a nonce through {second}")
    assert second_dev != first_dev, (
        f"the two volumes must be two distinct block devices inside the guest, but both resolved to "
        f"{second_dev!r}"
    )
    with_both = _guest_disk_sizes(ctx, ssm, instance_id, "the guest's disks with both volumes attached")
    assert {_FIRST_GIB * 1024 ** 3, _SECOND_GIB * 1024 ** 3} <= with_both, (
        f"with both volumes attached the guest must see both sizes; it sees {sorted(with_both)!r} "
        f"(it started from {sorted(baseline)!r})"
    )
    final = _guest_read(ctx, ssm, instance_id, _FIRST_GIB, "re-reading the first volume at the end")
    assert final.get("value") == nonce_first, (
        f"attaching a second volume must not disturb the first's contents; its nonce read back as "
        f"{final!r}, expected {nonce_first!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
