"""nvme-instance-store-guest-device-path-rejected-as-an-ebs-attachment-point."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nvme-instance-store-guest-device-path-rejected-as-an-ebs-attachment-point"
GROUP = "instance-store-device-naming-rejected"
SERVICES = ["ec2"]

#: Named rather than searched for; its properties are asserted against DescribeInstanceTypes
#: before anything is created.
INSTANCE_TYPE = "m5d.large"

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

# The guest inventory uses `lsblk --pairs`: the `nvme` CLI is not installed on the AL2023 AMI.

#: `lsblk -P` emits `NAME="x" SIZE="123" MODEL="Amazon EC2 NVMe Instance Storage" ...` -- one
#: quoted value per column, which is why MODEL's embedded spaces are not a parsing problem.
_PAIR = re.compile(r'(\w+)="([^"]*)"')

#: The guest's block-device report: whole disks with NVMe model and serial, the root device, where
#: each /dev/xvd* and /dev/sd* resolves (udev symlinks on Nitro), and the per-boot boot_id.
_PROBE = [
    "set -euo pipefail",
    "lsblk -d -b -P -o NAME,SIZE,MODEL,SERIAL,TYPE | sed 's/^/SIM2REAL-DISK /'",
    "R=$(findmnt -n -o SOURCE /)",
    "PK=$(lsblk -no PKNAME \"$R\" | head -n1 | tr -d ' ')",
    "echo \"SIM2REAL-ROOT src=$R real=$(readlink -f \"$R\") pk=$PK\"",
    "for L in /dev/xvd* /dev/sd*; do [ -e \"$L\" ] || continue; "
    "echo \"SIM2REAL-COMPAT path=$L real=$(readlink -f \"$L\")\"; done",
    "echo \"SIM2REAL-BOOT id=$(cat /proc/sys/kernel/random/boot_id)\"",
]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error_of(fn):
    """The (code, message) the call raised, or an AssertionError if it was accepted."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc), exc.response["Error"]["Message"]
    raise AssertionError(
        "the call real AWS rejects was ACCEPTED -- over-permissiveness, not an error-code mismatch"
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
    """Delete, retrying a bounded number of times while a just-terminated ENI holds a dependency."""
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


def _instance_type_facts(ec2, itype):
    got = ec2.describe_instance_types(InstanceTypes=[itype])["InstanceTypes"]
    assert got, f"{itype!r} is not described by this region's instance-type catalogue"
    return got[0]


def _declared_disk_bytes(store):
    """Every instance-store disk the family declares, as a sorted list of byte sizes.

    The kernel reports exactly SizeInGB * 10**9 bytes per disk, so the comparison is an equality.
    """
    out = []
    for group in store["Disks"]:
        out += [group["SizeInGB"] * 10 ** 9] * group["Count"]
    return sorted(out)


def _derive_az(ec2, itype):
    """The first AZ that both offers `itype` and is reporting itself available.

    Offerings do not report zone state and zones do not report instance types, so both are read.
    """
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
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
        f"no available AZ in this region offers {itype!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _ami(ssm, arch):
    ami = ssm.get_parameter(
        Name=f"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-{arch}"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 {arch} parameter did not resolve to an AMI: {ami!r}"
    return ami


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    The SSM agent needs egress, so the subnet gets an internet gateway and public addressing.
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
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-nvme-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav instance-store nvme device identity",
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


def _describe_instance(ec2, instance_id):
    """DescribeInstances, polling through the read-after-write window after RunInstances.

    A DescribeInstances right after RunInstances can return InvalidInstanceID.NotFound for the new id.
    """
    def _once():
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                return None
            raise
        return resv[0]["Instances"][0] if resv and resv[0].get("Instances") else None

    return _poll(_once, lambda i: i is not None, timeout_s=120, interval_s=3.0,
                 what=f"DescribeInstances resolving {instance_id}")


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


def _detach_and_delete_volume(ec2, volume_id, timeout_s=300):
    """Detach if attached, wait for 'available', then delete.

    Self-sufficient rather than order-dependent: the volume is created after the instance, so LIFO
    runs this BEFORE the terminate, and a delete of an in-use volume is refused.
    """
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
        time.sleep(5)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand returns InvalidInstanceId until the agent registers, so retrying it is the wait.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav instance-store nvme device identity",
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


def _fields(rest):
    out = {}
    for field in rest.split():
        if "=" in field:
            key, _, value = field.partition("=")
            out[key] = value
    return out


def _guest_view(ssm, instance_id, what):
    """The guest's own account of its block devices: (disks, root, compat, boot_id)."""
    out = _run_guest(ssm, instance_id, _PROBE, what)
    disks, compat, root, boot = [], {}, {}, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SIM2REAL-DISK "):
            disks.append(dict(_PAIR.findall(line)))
        elif line.startswith("SIM2REAL-ROOT "):
            root = _fields(line[len("SIM2REAL-ROOT "):])
        elif line.startswith("SIM2REAL-COMPAT "):
            got = _fields(line[len("SIM2REAL-COMPAT "):])
            if got.get("path"):
                compat[got["path"]] = got.get("real")
        elif line.startswith("SIM2REAL-BOOT "):
            boot = _fields(line[len("SIM2REAL-BOOT "):]).get("id")
    assert disks and root.get("pk") and boot, (
        f"{what}: the guest did not report a usable block-device inventory; its stdout was {out!r}"
    )
    return disks, root, compat, boot


def _instance_store_disks(disks):
    """The whole disks whose NVMe model string identifies them as EC2 instance storage.

    Selected by MODEL rather than device path, because the path is the thing under test.
    """
    return [d for d in disks if "Instance Storage" in d.get("MODEL", "")]


def _ebs_disks(disks):
    return [d for d in disks if "Elastic Block Store" in d.get("MODEL", "")]


def _serial_to_name(disks):
    return {d["SERIAL"]: d["NAME"] for d in disks if d.get("SERIAL")}


def _launch(ctx, ec2, ssm, iam, scenario, az, ami):
    """One tagged instance of INSTANCE_TYPE in a public subnet of this check's own VPC, running,
    with its SSM agent Online. Termination is registered immediately after RunInstances, before
    any wait, so a host that never registers is terminated rather than left billing."""
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
            ImageId=ami, InstanceType=INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
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

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=600, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )
    return instance_id


#: An EBS device name AWS accepts, used as the positive control.
_GOOD_DEVICE = "/dev/xvdb"
_DATA_GIB = 1


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachVolume at the guest's instance-store NVMe path is refused with InvalidParameterValue and
    changes nothing, while the same volume attaches at a real EBS device name as a new namespace.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "nvme-instance-store-path-not-an-ebs-attachment-point"

    # --- everything decidable, before anything is created ---------------------
    facts = _instance_type_facts(ec2, INSTANCE_TYPE)
    store = facts.get("InstanceStorageInfo") or {}
    assert facts.get("Hypervisor") == "nitro", (
        f"{INSTANCE_TYPE} must be a Nitro family so that both storage classes are NVMe and the "
        f"attachment point is a real NVMe path; got Hypervisor={facts.get('Hypervisor')!r}"
    )
    assert store.get("NvmeSupport") == "required", (
        f"{INSTANCE_TYPE} must declare InstanceStorageInfo.NvmeSupport 'required'; got {store!r}"
    )
    declared = _declared_disk_bytes(store)
    assert len(declared) >= 1 and sum(declared) == store["TotalSizeInGB"] * 10 ** 9, (
        f"{INSTANCE_TYPE}'s per-disk instance-store declaration {declared!r} must be non-empty and "
        f"must add up to the declared TotalSizeInGB {store.get('TotalSizeInGB')!r}: {store!r}"
    )
    arches = facts["ProcessorInfo"]["SupportedArchitectures"]
    arch = "arm64" if "arm64" in arches else "x86_64"

    az = _derive_az(ec2, INSTANCE_TYPE)
    instance_id = _launch(ctx, ec2, ssm, iam, scenario, az, _ami(ssm, arch))

    disks, _root, _compat, _boot = _guest_view(ssm, instance_id, "inventory before the attachment")
    ephemeral = _instance_store_disks(disks)
    assert len(ephemeral) == len(declared), (
        f"{INSTANCE_TYPE} declares {len(declared)} instance-store disk(s) but the guest presents "
        f"{len(ephemeral)}: {ephemeral!r} (whole inventory {disks!r})"
    )
    ess = ephemeral[0]
    ess_dev = "/dev/" + ess["NAME"]
    assert ess["NAME"].startswith("nvme"), (
        f"this check attaches at the instance store's NVMe path, so the guest must report one: "
        f"{ess!r}"
    )
    mapping_before = _serial_to_name(disks)

    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_DATA_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
          lambda s: s == "available", timeout_s=300, interval_s=3.0,
          what=f"volume {volume_id} reaching 'available'")

    # --- the negative: one varied input, the guest's own NVMe path -------------
    code, message = _error_of(lambda: ec2.attach_volume(
        VolumeId=volume_id, InstanceId=instance_id, Device=ess_dev))
    assert code == "InvalidParameterValue", (
        f"attaching {volume_id} at the instance store's guest path {ess_dev!r} must be rejected "
        f"with InvalidParameterValue ('{ess_dev} is not a valid EBS device name'), got {code!r}"
    )
    assert message == (
        f"Value ({ess_dev}) for parameter device is invalid. {ess_dev} is not a valid EBS device name."
    ), f"AttachVolume at {ess_dev!r} refusal message: {message!r}"

    # (a) the volume did not attach at all.
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert volume["State"] == "available" and not volume.get("Attachments"), (
        f"the rejected AttachVolume must leave {volume_id} untouched, but it is now {volume!r}"
    )
    # (b) and it is not among the instance's volumes, read through the paginator.
    attached = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]):
        attached += page["Volumes"]
    assert volume_id not in {v["VolumeId"] for v in attached}, (
        f"{volume_id} must not be attached to {instance_id} after the rejection, but "
        f"DescribeVolumes lists it: {attached!r}"
    )
    # (c) the strongest form of absent: the guest's device set did not change.
    disks_after, _r, _c, _b = _guest_view(ssm, instance_id, "inventory after the rejection")
    assert _serial_to_name(disks_after) == mapping_before, (
        f"a rejected attachment must not alter the guest's block devices; the serial-to-device map "
        f"was {mapping_before!r} and is now {_serial_to_name(disks_after)!r}"
    )

    # --- the positive control, in the same file, on the same volume ------------
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=_GOOD_DEVICE)
    _poll(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"],
          lambda a: bool(a) and a[0]["State"] == "attached", timeout_s=300, interval_s=3.0,
          what=f"volume {volume_id} reaching 'attached' on {instance_id} at {_GOOD_DEVICE}")
    # Nitro exposes an EBS volume's id, without the hyphen, as its NVMe serial.
    expected_serial = volume_id.replace("-", "")
    grown = _poll(
        lambda: _guest_view(ssm, instance_id, "inventory after the accepted attachment")[0],
        lambda ds: expected_serial in _serial_to_name(ds),
        timeout_s=300, interval_s=10.0,
        what=f"the guest presenting a namespace with serial {expected_serial!r}",
    )
    mapping_grown = _serial_to_name(grown)
    assert set(mapping_before) | {expected_serial} == set(mapping_grown), (
        f"attaching {volume_id} at {_GOOD_DEVICE} must add exactly one namespace and remove none; "
        f"the guest had serials {sorted(mapping_before)!r} and now has {sorted(mapping_grown)!r}"
    )
    new = [d for d in grown if d.get("SERIAL") == expected_serial][0]
    assert new["NAME"].startswith("nvme"), (
        f"on {INSTANCE_TYPE} an EBS volume attached at {_GOOD_DEVICE} still arrives as an NVMe "
        f"namespace; the guest named it {new['NAME']!r}: {new!r}"
    )
    assert int(new["SIZE"]) == _DATA_GIB * 1024 ** 3, (
        f"a {_DATA_GIB} GiB volume must present {_DATA_GIB * 1024 ** 3} bytes to the guest, got "
        f"{new['SIZE']!r}: {new!r}"
    )
    assert mapping_grown[ess["SERIAL"]] == ess["NAME"], (
        f"attaching an EBS volume must not move the instance store: serial {ess['SERIAL']!r} was "
        f"{ess['NAME']!r} and is now {mapping_grown[ess['SERIAL']]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
