"""nvme-instance-store-serial-to-device-mapping-and-data-survive-a-reboot."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nvme-instance-store-serial-to-device-mapping-and-data-survive-a-reboot"
GROUP = "instance-store-device-identity"
SERVICES = ["ec2"]

#: Named rather than searched for: the behaviour is a property of this Nitro family, and its
#: properties are asserted against describe_instance_types before anything is created.
INSTANCE_TYPE = "m5d.large"

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

# The AL2023 AMI has no `nvme` CLI, so the guest inventory comes from `lsblk --pairs`.

#: `lsblk -P` emits `NAME="x" SIZE="123" MODEL="Amazon EC2 NVMe Instance Storage" ...` -- one
#: quoted value per column, which is why MODEL's embedded spaces are not a parsing problem.
_PAIR = re.compile(r'(\w+)="([^"]*)"')

#: The guest's report on its block devices: disks with NVMe model and serial, the root device,
#: where each /dev/xvd* and /dev/sd* resolves (udev symlinks on Nitro), and the per-boot boot_id.
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


def _error_code(fn):
    """The error code the call raised; fails if it did not raise at all."""
    try:
        fn()
    except ClientError as exc:
        return _code(exc)
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


def _bounded(ctx, cap_s, reserve_s=10.0):
    """`cap_s`, shortened so the wait ends `reserve_s` before the runner stops the check."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


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
"""
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

    Groups of {SizeInGB, Count} are expanded per device. SizeInGB is decimal GB and the kernel
    reports exactly SizeInGB * 10**9 bytes, so the comparison is an equality.
    """
    out = []
    for group in store["Disks"]:
        out += [group["SizeInGB"] * 10 ** 9] * group["Count"]
    return sorted(out)


def _derive_az(ec2, itype):
    """The first AZ that both offers `itype` and is reporting itself available.

    Offerings report no zone state and DescribeAvailabilityZones reports no instance types, so
    both are intersected.
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

    An account need not have a default VPC. The SSM agent needs egress to reach its endpoint, so
    the subnet gets an internet gateway, a default route and public addressing.
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


def _describe_instance(ctx, ec2, instance_id):
    """DescribeInstances, tolerating the read-after-write window RunInstances leaves.

    DescribeInstances right after RunInstances can return InvalidInstanceID.NotFound for the new id.
    """
    def _once():
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                return None
            raise
        return resv[0]["Instances"][0] if resv and resv[0].get("Instances") else None

    return _poll(_once, lambda i: i is not None, timeout_s=_bounded(ctx, 120), interval_s=2.0,
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


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry is the wait for the agent: a freshly booted host rejects SendCommand with
    InvalidInstanceId until its agent registers. A host that never accepts a command fails.
    """
    deadline = time.monotonic() + _bounded(ctx, ready_timeout_s)
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
                time.sleep(2)
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
                timeout_s=_bounded(ctx, run_timeout_s), interval_s=2.0,
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


def _guest_view(ctx, ssm, instance_id, what, *, run_timeout_s=300):
    """The guest's own account of its block devices: (disks, root, compat, boot_id).

    `disks` is one dict per whole disk from `lsblk --pairs`; `root` is the root source and parent
    disk; `compat` maps each /dev/xvd*|/dev/sd* path to its target; `boot_id` is per boot.
    """
    out = _run_guest(ctx, ssm, instance_id, _PROBE, what, run_timeout_s=run_timeout_s)
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

    Selected by MODEL rather than by device path, because the path is the thing under test.
    """
    return [d for d in disks if "Instance Storage" in d.get("MODEL", "")]


def _ebs_disks(disks):
    return [d for d in disks if "Elastic Block Store" in d.get("MODEL", "")]


def _serial_to_name(disks):
    return {d["SERIAL"]: d["NAME"] for d in disks if d.get("SERIAL")}


def _view_after_reboot(ctx, ssm, instance_id):
    """The guest view, or the failure text while the rebooting guest cannot yet run the probe."""
    try:
        return _guest_view(ctx, ssm, instance_id, "inventory after the reboot", run_timeout_s=60)
    except AssertionError as exc:
        return str(exc)


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
          timeout_s=_bounded(ctx, 600), interval_s=2.0,
          what=f"instance {instance_id} reaching 'running'")

    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=_bounded(ctx, 600), interval_s=2.0,
                 what=f"the SSM agent on {instance_id} coming Online")
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )
    return instance_id


#: Mount point for the per-run nonce filesystem on the ephemeral disk.
_MOUNT = "/mnt/sim2real-ess"


def _write_nonce(dev, nonce):
    return [
        "set -euo pipefail",
        f'mkfs.ext4 -qF "{dev}"',
        f'mkdir -p "{_MOUNT}"',
        f'mount "{dev}" "{_MOUNT}"',
        f'echo "{nonce}" > "{_MOUNT}/nonce"',
        "sync",
        f'umount "{_MOUNT}"',
        f'echo "SIM2REAL-WROTE dev={dev}"',
    ]


def _read_nonce(dev):
    """Read the nonce back from `dev`, reporting a missing device or file as a nameable value."""
    return [
        "set -uo pipefail",
        f'mkdir -p "{_MOUNT}"',
        "V=absent",
        f'if [ -b "{dev}" ]; then',
        f'  if mount -o ro "{dev}" "{_MOUNT}" 2>/dev/null; then',
        f'    V=$(cat "{_MOUNT}/nonce" 2>/dev/null || echo no-file); umount "{_MOUNT}";',
        "  else V=unmountable; fi",
        "else V=no-device; fi",
        'echo "SIM2REAL-READ value=$V boot=$(cat /proc/sys/kernel/random/boot_id)"',
    ]


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A reboot keeps the instance store disk (same NVMe serial and size) and its bytes.

    The EBS root's NVMe serial keeps naming the root volume id, graded inside the guest; disks are
    matched by serial, since AWS documents that NVMe kernel names can change across boots.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "nvme-instance-store-reboot-device-identity"
    nonce = ctx.unique_name("sim2real-nonce-")

    # --- everything decidable, before anything is created ---------------------
    facts = _instance_type_facts(ec2, INSTANCE_TYPE)
    store = facts.get("InstanceStorageInfo") or {}
    assert facts.get("Hypervisor") == "nitro", (
        f"{INSTANCE_TYPE} must be a Nitro family for the EBS-serial half of this check; the "
        f"catalogue reports Hypervisor={facts.get('Hypervisor')!r}"
    )
    assert facts["EbsInfo"].get("NvmeSupport") == "required", (
        f"{INSTANCE_TYPE} must present EBS over NVMe for the serial binding to exist; got "
        f"{facts['EbsInfo']!r}"
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
    api = _describe_instance(ctx, ec2, instance_id)
    root_volume = {m["DeviceName"]: m["Ebs"]["VolumeId"]
                   for m in api["BlockDeviceMappings"]}.get(api["RootDeviceName"])
    assert root_volume, (
        f"DescribeInstances reports RootDeviceName {api['RootDeviceName']!r} with no matching "
        f"BlockDeviceMappings entry: {api['BlockDeviceMappings']!r}"
    )

    # --- the guest's view, before the transition ------------------------------
    disks, root, compat, boot0 = _guest_view(ctx, ssm, instance_id, "inventory before the reboot")
    ephemeral = _instance_store_disks(disks)
    assert len(ephemeral) == len(declared), (
        f"{INSTANCE_TYPE} declares {len(declared)} instance-store disk(s) but the guest presents "
        f"{len(ephemeral)}: {ephemeral!r} (whole inventory {disks!r})"
    )
    assert sorted(int(d["SIZE"]) for d in ephemeral) == declared, (
        f"the guest's instance-store disks are {sorted(int(d['SIZE']) for d in ephemeral)!r} bytes "
        f"but {INSTANCE_TYPE} declares {declared!r}: {ephemeral!r}"
    )
    ess = ephemeral[0]
    ess_dev = "/dev/" + ess["NAME"]
    assert ess["NAME"].startswith("nvme"), (
        f"the instance store must be an NVMe namespace, not {ess['NAME']!r}: {ess!r}"
    )

    # The Nitro naming fact, asserted in both directions: xvda is a SYMLINK onto the EBS root, and
    # nothing under xvd/sd reaches the ephemeral disk.
    ebs = _ebs_disks(disks)
    assert len(ebs) == 1 and ebs[0]["NAME"] == root["pk"], (
        f"exactly one disk should identify as 'Amazon Elastic Block Store' and it should be the "
        f"root's whole disk {root['pk']!r}; the guest reported {ebs!r}"
    )
    assert ebs[0]["SERIAL"] == root_volume.replace("-", ""), (
        f"on Nitro an EBS volume's NVMe serial is its volume id without the hyphen, so the root "
        f"volume {root_volume!r} must appear as serial {root_volume.replace('-', '')!r}; the guest "
        f"reported {ebs[0]['SERIAL']!r}"
    )
    assert compat.get("/dev/xvda") == "/dev/" + ebs[0]["NAME"], (
        f"on Nitro /dev/xvda is a udev compatibility symlink onto the EBS root's NVMe namespace "
        f"/dev/{ebs[0]['NAME']}, but it resolves to {compat.get('/dev/xvda')!r}; all compat paths "
        f"were {compat!r}"
    )
    aliased = {p: t for p, t in compat.items() if t == ess_dev}
    assert not aliased, (
        f"no xvd/sd compatibility path may reach the instance store {ess_dev!r}, but these do: "
        f"{aliased!r}"
    )
    mapping_before = _serial_to_name(disks)
    assert ess["SERIAL"] in mapping_before, (
        f"the instance store reported no NVMe serial, so there is no identity to hold stable: "
        f"{ess!r}"
    )

    # --- write the nonce, and prove it landed on THIS boot ---------------------
    _run_guest(ctx, ssm, instance_id, _write_nonce(ess_dev, nonce),
               f"making a filesystem on {ess_dev} and writing the nonce")
    same = _fields(_run_guest(ctx, ssm, instance_id, _read_nonce(ess_dev),
                              "reading the nonce back on the boot that wrote it")
                   .split("SIM2REAL-READ ", 1)[-1])
    assert same.get("value") == nonce, (
        f"the nonce {nonce!r} was not readable from {ess_dev!r} on the boot that wrote it, so "
        f"nothing later can be attributed to the reboot; the guest reported {same!r}"
    )
    assert same.get("boot") == boot0, (
        f"the machine rebooted between the write and the read (boot {boot0!r} -> "
        f"{same.get('boot')!r}), so this read proves nothing about the write"
    )

    # --- the transition: same host, so nothing may move ------------------------
    ec2.reboot_instances(InstanceIds=[instance_id])
    after = _poll(
        lambda: _view_after_reboot(ctx, ssm, instance_id),
        lambda view: isinstance(view, tuple) and view[3] != boot0,
        timeout_s=_bounded(ctx, 900), interval_s=2.0,
        what=f"instance {instance_id} reporting a new boot id after RebootInstances",
    )
    disks_after, root_after, compat_after, boot1 = after
    assert boot1 != boot0, f"the guest never rebooted: boot id stayed {boot0!r}"

    # (1) the same NVMe serials come back: a reboot keeps the physical host and the device set.
    mapping_after = _serial_to_name(disks_after)
    assert sorted(mapping_after) == sorted(mapping_before), (
        f"a reboot keeps the physical host and the attached device set, so the same NVMe serials "
        f"must come back; they were {sorted(mapping_before)!r} and are now "
        f"{sorted(mapping_after)!r}"
    )

    # (2) the ephemeral disk is the same serial, same size, still NVMe, still not aliased as xvd.
    ess_after = _instance_store_disks(disks_after)
    same_serial = [d for d in ess_after if d.get("SERIAL") == ess["SERIAL"]]
    assert len(ess_after) == len(declared) and len(same_serial) == 1, (
        f"the instance store came back as {ess_after!r}; before the reboot it was {ess!r}"
    )
    ess_dev_after = "/dev/" + same_serial[0]["NAME"]
    assert same_serial[0]["NAME"].startswith("nvme"), (
        f"the instance store must still be an NVMe namespace, not {same_serial[0]['NAME']!r}"
    )
    assert int(same_serial[0]["SIZE"]) == int(ess["SIZE"]), (
        f"the instance store changed size across the reboot: {ess['SIZE']!r} -> "
        f"{same_serial[0]['SIZE']!r}"
    )
    assert {p: t for p, t in compat_after.items() if t == ess_dev_after} == {}, (
        f"after the reboot an xvd/sd path resolves onto the instance store {ess_dev_after!r}: "
        f"{compat_after!r}"
    )

    # (3) the bytes survived on the disk that carries the same serial.
    post = _fields(_run_guest(ctx, ssm, instance_id, _read_nonce(ess_dev_after),
                              "reading the nonce back after the reboot")
                   .split("SIM2REAL-READ ", 1)[-1])
    assert post.get("boot") == boot1, (
        f"the read landed on boot {post.get('boot')!r}, not the post-reboot boot {boot1!r}"
    )
    assert post.get("value") == nonce, (
        f"a REBOOT keeps the physical host, so the instance store must still hold {nonce!r}, but "
        f"{ess_dev_after!r} read back as {post.get('value')!r}; guest reported {post!r}"
    )

    # (4) the EBS root's serial still names the same volume, and the root still boots from it.
    ebs_after = _ebs_disks(disks_after)
    assert len(ebs_after) == 1 and ebs_after[0]["SERIAL"] == root_volume.replace("-", ""), (
        f"after the reboot the EBS root must still carry serial {root_volume.replace('-', '')!r}; "
        f"the guest reported {ebs_after!r}"
    )
    assert ebs_after[0]["NAME"] == root_after["pk"], (
        f"the root filesystem must still be mounted from the EBS root {ebs_after[0]['NAME']!r}, "
        f"but its whole disk is {root_after['pk']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
