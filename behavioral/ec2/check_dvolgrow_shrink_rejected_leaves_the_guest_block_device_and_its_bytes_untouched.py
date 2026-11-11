"""dvolgrow-shrink-rejected-leaves-the-guest-block-device-and-its-bytes-untouched."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dvolgrow-shrink-rejected-leaves-the-guest-block-device-and-its-bytes-untouched"
GROUP = 'dvolgrow-rejected'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_INSTANCE_TYPE = "t3.micro"
_GIB = 1024 * 1024 * 1024

# The shrink target is still a legal gp3 size, so the rejection can only be about shrinking. All
# sizes differ from the 8 GiB AL2023 root volume, so the guest can find the data disk by size.
_START_GIB = 4
_SHRINK_GIB = 2
_GROW_GIB = 6
_PAYLOAD_BYTES = 1024 * 1024

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The (code, message) of the AWS error `fn` raised; raises on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"the call was expected to be rejected but it SUCCEEDED, returning {result!r}"
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
    """Delete, retrying (bounded) through the dependency window a just-terminated ENI leaves."""
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
    """An AZ that is both available and offers the instance type; neither API reports both."""
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
    """A new VPC with a public subnet in `az`, since an account need not have a default VPC.

    The SSM agent needs egress, hence the internet gateway, default route and public addressing.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario},
                                              {"Key": "Name",
                                               "Value": ctx.unique_name("sim2real-dvolgrow-")}]}]

    # Randomised so concurrent runs in one account do not collide; the VPCs are never peered.
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
                    Description="sim2real-behav rejected volume shrink role",
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
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(2)


def _describe_volume(ec2, volume_id):
    """DescribeVolumes for one id, paginated."""
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _detach_and_delete_volume(ec2, volume_id, timeout_s=300):
    """Detach if attached, wait for 'available', then delete; LIFO runs this before the instance
    is terminated, and an in-use volume cannot be deleted."""
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
        time.sleep(2)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=600):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand fails with InvalidInstanceId until the agent registers, so retrying it is the wait.
    """
    deadline = time.monotonic() + _budget_s(ctx, ready_timeout_s)
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav rejected volume shrink",
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


def _measure(marker):
    """A guest script that re-measures the mounted data volume and writes one canary file; the
    canary catches a device that went read-only, which would also report an unchanged size."""
    return [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        'DEV=$(findmnt -no SOURCE /mnt/grow)',
        'if [ -z "$DEV" ]; then echo "NOT-MOUNTED"; findmnt -no SOURCE,TARGET; exit 1; fi',
        f'echo "{marker}-canary" > /mnt/grow/canary-{marker}.txt',
        "sync",
        f'echo "{marker} dev=$DEV bytes=$(blockdev --getsize64 $DEV)'
        ' fs=$(df -B1 --output=size /mnt/grow | tail -1 | tr -d \' \')'
        ' sha=$(sha256sum /mnt/grow/payload.bin | cut -d\' \' -f1)'
        f' canary=$(cat /mnt/grow/canary-{marker}.txt)"',
    ]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """A rejected shrink of an attached, mounted EBS volume leaves the guest's block device size,
    filesystem size and payload digest unchanged, while a legal grow of the same volume is seen
    by the same in-guest reader.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/modify-volume-requirements.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "dvolgrow-shrink-rejected"
    nonce = ctx.unique_name("sim2real-nonce-")

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
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=2.0, ctx=ctx,
          what=f"instance {instance_id} reaching 'running'")

    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_START_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-dvolgrow-")}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: _describe_volume(ec2, volume_id)["State"], lambda s: s == "available",
          timeout_s=300, interval_s=2.0, ctx=ctx,
          what=f"volume {volume_id} reaching 'available'")
    created = _describe_volume(ec2, volume_id)
    assert created["Size"] == _START_GIB, (
        f"the volume was created at Size {created['Size']!r}, expected {_START_GIB!r}"
    )
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    attachments = _poll(lambda: _describe_volume(ec2, volume_id)["Attachments"],
                        lambda a: bool(a) and a[0]["State"] == "attached",
                        timeout_s=300, interval_s=2.0, ctx=ctx,
                        what=f"volume {volume_id} reaching 'attached' on {instance_id}")
    assert attachments[0]["InstanceId"] == instance_id, (
        f"the attachment names {attachments[0]['InstanceId']!r}, expected {instance_id!r}"
    )

    # The device is found by exact byte size, never by path: Nitro presents EBS as /dev/nvme?n1 in
    # an order that is not the attachment order, so '/dev/sdf' is only a request.
    provision = [
        "set -eu",   # no pipefail: awk/head close their pipes early, and SIGPIPE is not a failure
        "DEV=",
        "for i in $(seq 1 60); do",
        f"  DEV=$(lsblk -dn -b -o NAME,SIZE | awk -v w={_START_GIB * _GIB} "
        "'$2==w {print $1; exit}')",
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
    base = _report(_run_guest(ctx, ssm, instance_id, provision,
                              "provisioning the filesystem and writing the payload"),
                   "SIM2REAL-BASE")
    assert base is not None and {"dev", "bytes", "fs", "sha", "payload"} <= set(base), (
        f"the guest did not report a provisioned filesystem, it reported {base!r}"
    )
    assert int(base["payload"]) == _PAYLOAD_BYTES, (
        f"the guest wrote {base['payload']!r} bytes of payload, expected {_PAYLOAD_BYTES!r}"
    )
    assert len(base["sha"]) == 64, f"the guest reported a malformed sha256 {base['sha']!r}"
    assert int(base["bytes"]) == _START_GIB * _GIB, (
        f"the guest's block device is {base['bytes']!r} bytes, expected {_START_GIB * _GIB} — it is "
        f"not looking at the volume this check attached"
    )
    sha, fs_before = base["sha"], int(base["fs"])
    assert 0 < fs_before <= _START_GIB * _GIB, (
        f"the filesystem reports {fs_before} bytes on a {_START_GIB * _GIB}-byte device, which is "
        f"impossible"
    )

    code, message = _error(lambda: ec2.modify_volume(VolumeId=volume_id, Size=_SHRINK_GIB))
    assert code == "InvalidParameterValue", (
        f"shrinking a {_START_GIB} GiB volume to {_SHRINK_GIB} GiB was rejected with {code!r}, "
        f"expected 'InvalidParameterValue'"
    )
    assert message == "New size cannot be smaller than existing size", (
        f"unexpected shrink refusal message: {message!r}"
    )

    # A never-modified volume makes this lookup a NotFound rather than an empty list.
    mods_code, mods_message = _error(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"]
    )
    assert mods_code == "InvalidVolumeModification.NotFound", (
        f"the rejected shrink left a modification record: DescribeVolumesModifications answered "
        f"{mods_code!r}, expected 'InvalidVolumeModification.NotFound'"
    )
    assert mods_message == f"Modification for volume '{volume_id}' does not exist.", (
        f"unexpected modification NotFound message: {mods_message!r}"
    )

    after_api = _describe_volume(ec2, volume_id)
    assert after_api["Size"] == _START_GIB, (
        f"the volume's Size is {after_api['Size']!r} after a REJECTED shrink, expected "
        f"{_START_GIB!r}"
    )
    assert after_api["State"] == "in-use", (
        f"the volume is {after_api['State']!r} after a rejected shrink, expected 'in-use' — a "
        f"rejection must not disturb the attachment"
    )

    refused = _report(_run_guest(ctx, ssm, instance_id, _measure("SIM2REAL-REFUSED"),
                                 "re-measuring the device after the rejected shrink"),
                      "SIM2REAL-REFUSED")
    assert refused is not None and {"bytes", "fs", "sha", "canary"} <= set(refused), (
        f"the guest did not report the post-rejection state, it reported {refused!r}"
    )
    assert int(refused["bytes"]) == _START_GIB * _GIB, (
        f"the guest's block device is {refused['bytes']!r} bytes after the shrink was REJECTED, "
        f"expected {_START_GIB * _GIB} — the API refused the request and the device shrank anyway"
    )
    assert int(refused["fs"]) == fs_before, (
        f"the mounted filesystem is {refused['fs']!r} bytes after the rejected shrink but was "
        f"{fs_before!r} before"
    )
    assert refused["sha"] == sha, (
        f"the payload hashes to {refused['sha']!r} after the rejected shrink, but it was written "
        f"as {sha!r} — a rejected request must not touch a single byte"
    )
    assert refused["canary"] == "SIM2REAL-REFUSED-canary", (
        f"the guest could not write to the volume after the rejected shrink (canary read back as "
        f"{refused['canary']!r}), so 'unchanged size' is not evidence that nothing happened"
    )
    assert refused["dev"] == base["dev"], (
        f"the guest is now measuring {refused['dev']!r} but provisioned {base['dev']!r}"
    )

    # Positive control: the same call with a larger size is visible in the guest.
    ec2.modify_volume(VolumeId=volume_id, Size=_GROW_GIB)
    mod = _poll(lambda: ec2.describe_volumes_modifications(
                    VolumeIds=[volume_id])["VolumesModifications"][0],
                lambda m: m["ModificationState"] == "completed",
                timeout_s=900, interval_s=1.0, ctx=ctx,
                what=f"the legal grow of {volume_id} reaching 'completed'")
    assert mod["OriginalSize"] == _START_GIB, (
        f"the modification record says the volume started at {mod['OriginalSize']!r}, expected "
        f"{_START_GIB!r} — the rejected shrink must not appear in its history"
    )
    assert mod["TargetSize"] == _GROW_GIB, (
        f"the modification record targets {mod['TargetSize']!r}, expected {_GROW_GIB!r}"
    )
    grown_api = _describe_volume(ec2, volume_id)
    assert grown_api["Size"] == _GROW_GIB, (
        f"the legal grow completed but DescribeVolumes reports Size {grown_api['Size']!r}, "
        f"expected {_GROW_GIB!r}"
    )

    grown = _report(_run_guest(ctx, ssm, instance_id, _measure("SIM2REAL-GROWN"),
                               "re-measuring the device after the legal grow"),
                    "SIM2REAL-GROWN")
    assert grown is not None and {"bytes", "sha", "canary"} <= set(grown), (
        f"the guest did not report the post-grow state, it reported {grown!r}"
    )
    assert int(grown["bytes"]) == _GROW_GIB * _GIB, (
        f"the guest's block device is {grown['bytes']!r} bytes after a LEGAL grow to {_GROW_GIB} "
        f"GiB, expected {_GROW_GIB * _GIB} — the same reader that saw no change from the rejected "
        f"shrink must see this one, or the absence above proves nothing"
    )
    assert grown["sha"] == sha, (
        f"the payload hashes to {grown['sha']!r} after the legal grow, but it was written as "
        f"{sha!r}"
    )
    assert grown["canary"] == "SIM2REAL-GROWN-canary", (
        f"the guest could not write to the grown volume (canary read back as {grown['canary']!r})"
    )
    assert [a["InstanceId"] for a in grown_api["Attachments"]] == [instance_id], (
        f"the grow changed the attachment set to {grown_api['Attachments']!r}, expected exactly "
        f"{instance_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
