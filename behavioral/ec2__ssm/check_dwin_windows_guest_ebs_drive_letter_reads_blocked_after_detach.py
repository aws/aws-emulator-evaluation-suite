"""dwin-windows-guest-ebs-drive-letter-reads-blocked-after-detach."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dwin-windows-guest-ebs-drive-letter-reads-blocked-after-detach"
GROUP = 'windows-guest'
SERVICES = ['ec2', 'ssm']

_WINDOWS_AMI_PARAM = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.large"
_VOLUME_GIB = 1
_DEVICE = "xvdf"
_DRIVE = "D"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


@tags(
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "axis:rejection",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An EBS volume attached to a Windows guest becomes an NTFS drive letter whose file hashes back
    byte-identically; after offline and detach the drive, file and disk are gone in the guest while
    C: stays readable, and the volume is `available` with no attachments.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    # --- everything decidable, before the first create ------------------------
    az = _usable_az(ec2, _INSTANCE_TYPE)
    ami = ssm.get_parameter(Name=_WINDOWS_AMI_PARAM)["Parameter"]["Value"]
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    assert image["Platform"] == "windows", (
        f"{_WINDOWS_AMI_PARAM} must resolve to a Windows image; {ami} reports "
        f"Platform={image.get('Platform')!r} Name={image.get('Name')!r}"
    )
    nonce = ctx.unique_name("sim2real-dwin-bytes-")
    expected_digest = hashlib.sha256(nonce.encode("ascii")).hexdigest().upper()

    net = _public_network(ctx, ec2, az)
    profile = _ssm_instance_profile(ctx, iam)

    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami,
            InstanceType=_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=net["subnet_id"],
            SecurityGroupIds=[net["group_id"]],
            IamInstanceProfile={"Name": profile},
            TagSpecifications=_tag_spec(ctx, ("instance", "volume")),
        ),
        # A brand-new instance profile is not immediately resolvable by RunInstances.
        codes=_THROTTLE + ("InvalidParameterValue",),
        retries=60,
        delay=2.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )

    # --- the data volume, attached to that instance ---------------------------
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_VOLUME_GIB, VolumeType="gp3",
        TagSpecifications=_tag_spec(ctx, ("volume",)),
    )["VolumeId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id),
                                        codes=("VolumeInUse", "IncorrectState")))
    ec2.get_waiter("volume_available").wait(
        VolumeIds=[volume_id], WaiterConfig={"Delay": 1, "MaxAttempts": 300})
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 1, "MaxAttempts": 600})

    attachment = ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=_DEVICE)
    ctx.on_cleanup(lambda: _detach_if_attached(ec2, volume_id))
    assert attachment["InstanceId"] == instance_id, attachment
    assert attachment["Device"] == _DEVICE, (
        f"the attachment must echo the device name it was given, reported "
        f"{attachment['Device']!r}, expected {_DEVICE!r}"
    )
    attached = _poll(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "in-use"
        and any(a["State"] == "attached" for a in v.get("Attachments", [])),
        timeout_s=300, interval_s=1.0, what=f"volume {volume_id} reaching in-use/attached", ctx=ctx,
    )
    assert attached["Attachments"][0]["InstanceId"] == instance_id, attached

    # --- the agent has to come up: a Windows host that never registers is a FAIL
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(
        _agent_view,
        lambda i: i is not None and i.get("PingStatus") == "Online",
        timeout_s=1200,
        interval_s=2.0,
        what=f"the SSM agent on Windows instance {instance_id} reaching PingStatus Online", ctx=ctx,
    )
    assert info["PlatformType"] == "Windows", (
        f"a Windows Server host must register as PlatformType Windows, got "
        f"{info.get('PlatformType')!r} for {instance_id!r}"
    )

    # --- the guest turns the attached disk into a drive letter and writes -----
    out = _powershell(ssm, instance_id, [
        "$ErrorActionPreference='Stop'",
        "'DISKS=' + (@(Get-Disk).Count)",
        "$d=Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'} | Select-Object -First 1",
        "if (-not $d) { throw 'no RAW disk appeared in the guest for the attached volume' }",
        "'RAWSIZE=' + $d.Size",
        "Initialize-Disk -Number $d.Number -PartitionStyle GPT | Out-Null",
        f"New-Partition -DiskNumber $d.Number -DriveLetter {_DRIVE} -UseMaximumSize | Out-Null",
        f"Format-Volume -DriveLetter {_DRIVE} -FileSystem NTFS "
        "-NewFileSystemLabel 'sim2real' -Confirm:$false | Out-Null",
        f"'LETTER=' + (Get-Volume -DriveLetter {_DRIVE}).DriveLetter",
        f"'FS=' + (Get-Volume -DriveLetter {_DRIVE}).FileSystemType",
        f"Set-Content -Path {_DRIVE}:\\sim2real.txt -Value '{nonce}' -Encoding Ascii -NoNewline",
        f"'HASH=' + (Get-FileHash -Path {_DRIVE}:\\sim2real.txt -Algorithm SHA256).Hash",
        f"'LEN=' + (Get-Item {_DRIVE}:\\sim2real.txt).Length",
        f"'BACK=' + (Get-Content -Path {_DRIVE}:\\sim2real.txt -Raw)",
    ], timeout_s=900, ctx=ctx)
    guest = _kv(out["StandardOutputContent"])

    assert out["StandardErrorContent"] == "", (
        f"the storage script wrote to stderr: {out['StandardErrorContent']!r}"
    )
    assert int(guest["DISKS"]) == 2, (
        f"the guest must see two disks (the 30 GiB root and the attached {_VOLUME_GIB} GiB "
        f"volume), Get-Disk counted {guest.get('DISKS')!r}"
    )
    assert int(guest["RAWSIZE"]) == _VOLUME_GIB * 1024 ** 3, (
        f"the RAW disk the guest found is {guest.get('RAWSIZE')!r} bytes, but the volume was "
        f"created as {_VOLUME_GIB} GiB = {_VOLUME_GIB * 1024 ** 3} bytes"
    )
    assert guest["LETTER"] == _DRIVE, (
        f"the attached volume must be mountable as drive letter {_DRIVE!r}; the guest reports "
        f"{guest.get('LETTER')!r}"
    )
    assert guest["FS"] == "NTFS", (
        f"the formatted volume must report NTFS in the guest, got {guest.get('FS')!r}"
    )
    assert guest["LEN"] == str(len(nonce)), (
        f"the file on {_DRIVE}: is {guest.get('LEN')!r} bytes, but {len(nonce)} bytes were written"
    )
    assert guest["BACK"] == nonce, (
        f"the bytes read back from {_DRIVE}: were {guest.get('BACK')!r}, not the {nonce!r} written"
    )
    assert guest["HASH"] == expected_digest, (
        f"the guest's SHA-256 over {_DRIVE}:\\sim2real.txt is {guest.get('HASH')!r}, but the "
        f"digest of the bytes this check wrote is {expected_digest!r}"
    )

    # --- break exactly one thing: offline in the guest, then detach -----------
    offline = _powershell(ssm, instance_id, [
        "$ErrorActionPreference='Stop'",
        f"$dn=(Get-Partition -DriveLetter {_DRIVE}).DiskNumber",
        "Set-Disk -Number $dn -IsOffline $true",
        "'OFFLINED=' + $dn",
    ], ctx=ctx)
    assert _kv(offline["StandardOutputContent"]).get("OFFLINED"), (
        f"the guest did not report the disk it offlined: {offline['StandardOutputContent']!r}"
    )

    ec2.detach_volume(VolumeId=volume_id)
    detached = _poll(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=300, interval_s=1.0, what=f"volume {volume_id} returning to available", ctx=ctx,
    )
    assert detached["Attachments"] == [], (
        f"a detached volume must report no attachments, got {detached['Attachments']!r}"
    )

    # --- the absence, read from inside the same guest, with a positive control -
    # The guest drops the disk on its own clock after the control plane reports `available`, so
    # the probe is repeated until the guest view settles or the bound runs out.
    def _guest_after():
        return _kv(_powershell(ssm, instance_id, [
            "'CDRIVE=' + (Test-Path C:\\Windows\\System32\\cmd.exe)",
            f"'DFILE=' + (Test-Path {_DRIVE}:\\sim2real.txt)",
            f"'DVOLS=' + (@(Get-Volume | Where-Object {{$_.DriveLetter -eq '{_DRIVE}'}}).Count)",
            "'DISKS=' + (@(Get-Disk).Count)",
        ], ctx=ctx)["StandardOutputContent"])

    gone = _settle(
        _guest_after,
        lambda g: g.get("DFILE") == "False" and g.get("DVOLS") == "0" and g.get("DISKS") == "1",
        timeout_s=300, interval_s=1.0, ctx=ctx,
    )
    assert gone["CDRIVE"] == "True", (
        "the positive control must still hold: the same guest must still be able to read its "
        f"system drive, Test-Path C:\\Windows\\System32\\cmd.exe returned {gone.get('CDRIVE')!r}"
    )
    assert gone["DFILE"] == "False", (
        f"the file on the detached volume must no longer be readable in the guest, Test-Path "
        f"{_DRIVE}:\\sim2real.txt returned {gone.get('DFILE')!r}"
    )
    assert gone["DVOLS"] == "0", (
        f"no volume may carry the letter {_DRIVE!r} once the EBS volume is detached, the guest "
        f"counted {gone.get('DVOLS')!r}"
    )
    assert int(gone["DISKS"]) == 1, (
        f"the guest must see only its root disk after the detach, Get-Disk counted "
        f"{gone.get('DISKS')!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(probe, predicate, timeout_s, interval_s=1.0, *, ctx):
    """The first observation that satisfies `predicate`, else the last one once the bound runs
    out, so the caller's own assertions name what was seen."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the settled observation: the run budget ended first; not graded")
            return last
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="", *, ctx):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})"
            )
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _retry_delete(fn, codes=("DependencyViolation", "InvalidParameterValue", "DeleteConflict"),
                  attempts=100, delay=2.0):
    """Deletes that can only succeed once a reference is released. ctx.on_cleanup swallows
    exceptions, so a leak here would be silent — retry, then let the final raise surface."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound") or code in ("NoSuchEntity", "InvalidGroup.NotFound"):
                return None
            if code in codes and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise
    raise last


def _detach_if_attached(ec2, volume_id):
    """Force the volume off whatever holds it, so `delete_volume` can succeed even if the check
    failed before its own detach."""
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    if volume["State"] == "available":
        return
    _retry_delete(lambda: ec2.detach_volume(VolumeId=volume_id, Force=True),
                  codes=("IncorrectState", "VolumeInUse"))
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"] == "available":
            return
        time.sleep(2)


def _tag_spec(ctx, resource_types):
    """Name and sim2real tags for a TagSpecifications entry per resource type."""
    return [
        {"ResourceType": rt,
         "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dwin-")},
                  {"Key": "sim2real", "Value": CHECK}]}
        for rt in resource_types
    ]


def _usable_az(ec2, instance_type):
    """An AZ that both is available and offers the instance type. Neither catalogue answers
    both questions, and a hardcoded AZ name is a different physical zone in another account."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers {instance_type}; offered {sorted(offered)!r}, "
        f"available {sorted(available)!r}"
    )
    return usable[0]


def _public_network(ctx, ec2, az):
    """A VPC, public subnet, route to an internet gateway and a security group, all created
    here: the SSM agent must reach the SSM endpoints to register, and an ambient default VPC is
    account configuration this check must not depend on."""
    vpc = ec2.create_vpc(
        CidrBlock="10.89.0.0/16", TagSpecifications=_tag_spec(ctx, ("vpc",)),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})

    igw = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec(ctx, ("internet-gateway",)),
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_internet_gateway(
        InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.detach_internet_gateway(
        InternetGatewayId=igw, VpcId=vpc)))

    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.89.1.0/24", AvailabilityZone=az,
        TagSpecifications=_tag_spec(ctx, ("subnet",)),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})

    table = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=_tag_spec(ctx, ("route-table",)),
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=table)))
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.disassociate_route_table(
        AssociationId=assoc)))

    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-dwin-sg-"), Description="sim2real dwin windows guest",
        VpcId=vpc, TagSpecifications=_tag_spec(ctx, ("security-group",)),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_security_group(GroupId=group)))
    return {"vpc_id": vpc, "subnet_id": subnet, "group_id": group}


def _ssm_instance_profile(ctx, iam):
    """An instance profile granting only AmazonSSMManagedInstanceCore, created here and torn
    down in the order IAM requires (a role still held by a profile cannot be deleted)."""
    name = ctx.unique_name("sim2real-dwin-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real dwin windows guest storage role",
                    Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _drop_role():
        _retry_delete(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY))
        _retry_delete(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _drop_profile():
        _retry_delete(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name))
        _retry_delete(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait until the instance has left `running`, so the network and the instance
    profile it references can then be deleted."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = [
            i["State"]["Name"]
            for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            for i in r["Instances"]
        ]
        if all(s == "terminated" for s in states):
            return
        time.sleep(2)


def _powershell(ssm, instance_id, lines, timeout_s=600, *, ctx):
    """Send one AWS-RunPowerShellScript command and return its completed invocation."""
    sent = _call_with_retry(
        lambda: ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": lines},
            TimeoutSeconds=600,
            Comment="sim2real dwin windows guest",
        )
    )
    command_id = sent["Command"]["CommandId"]
    assert sent["Command"]["Status"] == "Pending", (
        f"a freshly accepted command must be Pending, got {sent['Command']['Status']!r}"
    )

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(
        _invocation,
        lambda i: i is not None and i.get("Status") in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=1.0,
        what=f"invocation {command_id} on {instance_id} reaching a terminal status", ctx=ctx,
    )
    assert inv["Status"] == "Success", (
        f"the PowerShell invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["InstanceId"] == instance_id, (
        f"the invocation reports instance {inv['InstanceId']!r}, expected {instance_id!r}"
    )
    return inv


def _kv(stdout):
    """`KEY=value` lines from a PowerShell invocation's stdout (CRLF-terminated)."""
    out = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            out[key] = value
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
