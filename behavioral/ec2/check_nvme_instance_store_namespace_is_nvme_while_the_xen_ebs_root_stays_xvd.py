"""nvme-instance-store-namespace-is-nvme-while-the-xen-ebs-root-stays-xvd."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nvme-instance-store-namespace-is-nvme-while-the-xen-ebs-root-stays-xvd"
GROUP = "instance-store-device-naming"
SERVICES = ["ec2"]

# Named rather than searched for: the behaviour is a property of this specific Xen family, and
# every property relied on is asserted against describe_instance_types before launch.
INSTANCE_TYPE = "i3.large"

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

# The AL2023 AMI ships no `nvme` CLI, so the guest inventory comes from `lsblk -P`, which quotes
# each column value and so keeps MODEL's embedded spaces parseable.
_PAIR = re.compile(r'(\w+)="([^"]*)"')

# xvd*/sd* paths are reported with their resolved target because on Nitro they are udev
# compatibility symlinks rather than devices.
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
    """The error code the call raised; an unexpected success fails as over-permissiveness."""
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


def _instance_type_facts(ec2, itype):
    got = ec2.describe_instance_types(InstanceTypes=[itype])["InstanceTypes"]
    assert got, f"{itype!r} is not described by this region's instance-type catalogue"
    return got[0]


def _declared_disk_bytes(store):
    """Every declared instance-store disk as a sorted list of byte sizes, expanded by Count.

    Instance-store capacity is decimal GB and the kernel reports exactly SizeInGB * 10**9 bytes.
    """
    out = []
    for group in store["Disks"]:
        out += [group["SizeInGB"] * 10 ** 9] * group["Count"]
    return sorted(out)


def _derive_az(ec2, itype):
    """The first AZ that both offers `itype` and reports itself available.

    Offerings do not report zone state, and zone state says nothing about instance types.
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
    """A VPC of this check's own making with a public subnet in `az`.

    Not the default VPC, which an account need not have; the SSM agent needs internet egress.
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
    """DescribeInstances, tolerating the eventual-consistency window after RunInstances.

    An immediate describe can return InvalidInstanceID.NotFound for the id just minted.
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
    """Terminate and wait for 'terminated': the ENI only clears then, and VPC teardown needs it."""
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
        time.sleep(5)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand fails with InvalidInstanceId until the agent registers, so retrying it is the wait.
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
    """Whole disks whose MODEL says instance storage; not by path, which is under test."""
    return [d for d in disks if "Instance Storage" in d.get("MODEL", "")]


def _ebs_disks(disks):
    return [d for d in disks if "Elastic Block Store" in d.get("MODEL", "")]


def _serial_to_name(disks):
    return {d["SERIAL"]: d["NAME"] for d in disks if d.get("SERIAL")}


def _launch(ctx, ec2, ssm, iam, scenario, az, ami):
    """A running INSTANCE_TYPE instance in its own VPC with its SSM agent Online."""
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


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On Xen i3.large the instance store is an NVMe namespace while the EBS root is a real /dev/xvd
    device, and the guest's local disks match the declared count and byte size exactly.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "nvme-instance-store-xen-family-device-naming"

    # On i3.large EbsInfo.NvmeSupport is 'supported' but instance storage NVMe is 'required', so
    # the two storage classes are presented differently; on Nitro everything is NVMe.
    facts = _instance_type_facts(ec2, INSTANCE_TYPE)
    store = facts.get("InstanceStorageInfo") or {}
    assert facts.get("Hypervisor") == "xen", (
        f"{INSTANCE_TYPE} is the subject BECAUSE it is a Xen family -- the whole point is that its "
        f"EBS root is not NVMe -- but the catalogue now reports "
        f"Hypervisor={facts.get('Hypervisor')!r}"
    )
    assert facts["EbsInfo"].get("NvmeSupport") == "supported", (
        f"{INSTANCE_TYPE} must declare EbsInfo.NvmeSupport 'supported' (optional), not required, "
        f"or its EBS root would be NVMe too and the contrast this check rests on is gone; got "
        f"{facts['EbsInfo']!r}"
    )
    assert store.get("NvmeSupport") == "required", (
        f"{INSTANCE_TYPE} must declare InstanceStorageInfo.NvmeSupport 'required' -- that "
        f"requirement IS the claim under test -- but the catalogue reports {store!r}"
    )
    declared = _declared_disk_bytes(store)
    assert len(declared) >= 1 and sum(declared) == store["TotalSizeInGB"] * 10 ** 9, (
        f"{INSTANCE_TYPE}'s per-disk instance-store declaration {declared!r} must be non-empty and "
        f"must add up to the declared TotalSizeInGB {store.get('TotalSizeInGB')!r}: {store!r}"
    )
    arches = facts["ProcessorInfo"]["SupportedArchitectures"]
    arch = "arm64" if "arm64" in arches else "x86_64"
    assert arch in arches, f"{INSTANCE_TYPE} supports neither x86_64 nor arm64: {arches!r}"

    az = _derive_az(ec2, INSTANCE_TYPE)
    instance_id = _launch(ctx, ec2, ssm, iam, scenario, az, _ami(ssm, arch))
    api = _describe_instance(ec2, instance_id)

    disks, root, compat, _boot = _guest_view(ssm, instance_id, "reading the block-device inventory")
    ephemeral = _instance_store_disks(disks)

    # (1) exactly as many local disks as the family declares, at exactly the declared sizes.
    assert len(ephemeral) == len(declared), (
        f"{INSTANCE_TYPE} declares {len(declared)} instance-store disk(s) "
        f"({_declared_disk_bytes(store)!r} bytes) but the guest presents {len(ephemeral)}: "
        f"{ephemeral!r} (whole inventory {disks!r})"
    )
    observed = sorted(int(d["SIZE"]) for d in ephemeral)
    assert observed == declared, (
        f"the guest's instance-store disks are {observed!r} bytes but {INSTANCE_TYPE} declares "
        f"{declared!r}; DescribeInstanceTypes and the block device must agree byte for byte "
        f"(guest inventory {ephemeral!r})"
    )

    # (2) every one of them is an NVMe namespace, by kernel name.
    for disk in ephemeral:
        assert disk["NAME"].startswith("nvme"), (
            f"the instance store must be presented as an NVMe namespace even on a Xen family "
            f"({INSTANCE_TYPE} declares InstanceStorageInfo.NvmeSupport 'required'), but the guest "
            f"named it {disk['NAME']!r}: {disk!r}"
        )
        assert disk["TYPE"] == "disk", (
            f"the instance store must appear as a whole disk, not {disk['TYPE']!r}: {disk!r}"
        )

    # (3) the EBS root, on this family, is a REAL /dev/xvd device -- not NVMe, and not a symlink.
    assert root["pk"].startswith("xvd"), (
        f"on {INSTANCE_TYPE} (Xen, EbsInfo.NvmeSupport 'supported') the EBS root must come up as a "
        f"blkfront /dev/xvd device, but the guest boots from {root['src']!r} whose whole disk is "
        f"{root['pk']!r}; inventory {disks!r}"
    )
    assert root["real"] == root["src"], (
        f"the root filesystem's device {root['src']!r} resolved to {root['real']!r}: on this family "
        f"it must BE the xvd device rather than a compatibility symlink onto something else"
    )
    assert not _ebs_disks(disks), (
        f"a Xen-presented EBS root carries no NVMe model string, so no disk here may identify "
        f"itself as 'Amazon Elastic Block Store'; the guest reported {_ebs_disks(disks)!r}"
    )

    # (4) no /dev/xvd* or /dev/sd* path reaches the instance store. This is the NOT-xvd half, and
    #     it is asserted over resolved targets because those paths are udev symlinks.
    local_paths = {"/dev/" + d["NAME"] for d in ephemeral}
    aliased = {p: t for p, t in compat.items() if t in local_paths}
    assert not aliased, (
        f"the instance store must never be reachable as an xvd/sd device, but these compatibility "
        f"paths resolve onto it: {aliased!r} (instance-store devices {sorted(local_paths)!r})"
    )
    assert compat, (
        "the guest reported no /dev/xvd* or /dev/sd* path at all, so assertion (4) had nothing to "
        "rule out -- on a Xen family the root device itself must appear there"
    )

    # (5) record versus execution: the device name the API reports for the root is the xvd disk the
    #     guest really boots from, and the local disk has no EBS identity at all.
    assert api["RootDeviceName"] == "/dev/" + root["pk"], (
        f"DescribeInstances reports RootDeviceName {api['RootDeviceName']!r} but the guest boots "
        f"from {root['src']!r} on whole disk {root['pk']!r}"
    )
    attached = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]):
        attached += page["Volumes"]
    assert not [v for v in attached if v["Size"] * 1024 ** 3 in declared or
                v["Size"] * 10 ** 9 in declared], (
        f"an instance-store disk has no volume id and must never appear in DescribeVolumes, but a "
        f"volume of instance-store size is attached to {instance_id}: {attached!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
