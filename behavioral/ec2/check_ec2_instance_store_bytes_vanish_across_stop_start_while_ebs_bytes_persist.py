"""ec2-instance-store-bytes-vanish-across-stop-start-while-ebs-bytes-persist."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-instance-store-bytes-vanish-across-stop-start-while-ebs-bytes-persist"
GROUP = 'instance-store-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: 1 GiB, deliberately distinct from the AL2023 root volume (8 GiB) so the GUEST can identify the
#: data volume by size without the check hardcoding a device path.
_DATA_GIB = 1
_DATA_BYTES = _DATA_GIB * 1024 * 1024 * 1024

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


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


def _pick_instance_store_type(ec2):
    """The smallest current-generation type with local NVMe storage offered in an available AZ.

    Instance-store capacity is a property of the type, and AZ names are per-account aliases.
    """
    cands = []
    for page in ec2.get_paginator("describe_instance_types").paginate(
        Filters=[
            {"Name": "instance-storage-supported", "Values": ["true"]},
            {"Name": "current-generation", "Values": ["true"]},
        ]
    ):
        for t in page["InstanceTypes"]:
            arches = t["ProcessorInfo"]["SupportedArchitectures"]
            arch = "arm64" if "arm64" in arches else ("x86_64" if "x86_64" in arches else None)
            store = t.get("InstanceStorageInfo") or {}
            if arch is None or not store.get("TotalSizeInGB"):
                continue
            cands.append(
                (t["VCpuInfo"]["DefaultVCpus"], t["MemoryInfo"]["SizeInMiB"],
                 t["InstanceType"], arch, store["TotalSizeInGB"])
            )
    assert cands, "this region offers no current-generation instance type with local NVMe storage"
    cands.sort()
    shortlist = cands[:20]
    offered = {}
    for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [c[2] for c in shortlist]}],
    )["InstanceTypeOfferings"]:
        offered.setdefault(o["InstanceType"], set()).add(o["Location"])
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    for _vcpu, _mib, name, arch, gb in shortlist:
        azs = sorted(offered.get(name, set()) & available)
        if azs:
            return name, arch, gb, azs[0]
    raise AssertionError(
        "no instance type with local NVMe storage is offered in an available AZ here; "
        f"shortlist was {[c[2] for c in shortlist]!r}, offerings {offered!r}, available {available!r}"
    )


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded: a DependencyViolation that never clears is a leak to declare, not a loop to sit in.
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
    role = ctx.unique_name("sim2real-ess-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav instance-store data-plane role",
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


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=420, run_timeout_s=300):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand returns InvalidInstanceId until the agent registers, so its retry is the wait.
    """
    deadline = time.monotonic() + ready_timeout_s
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav instance-store data plane",
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


def _report(stdout, marker):
    """The `key=value` fields of the last line starting with `marker`, as a dict.

    The guest emits one machine-readable line per phase, so nothing here depends on the order or
    the wording of the rest of its output.
    """
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


#: Find the two devices by PROPERTY, never by path. Nitro presents EBS as /dev/nvme?n1 in an order
#: that is not the attachment order, so `/dev/sdf` is only a request; the local SSD is identified by
#: its NVMe model string and the data volume by its exact byte size.
_FIND_DEVICES = (
    'ESS=$(lsblk -dn -o NAME,MODEL | awk \'/Instance Storage/ {print $1; exit}\')\n'
    'EBS=$(lsblk -dn -b -o NAME,SIZE,MODEL | awk -v w=%d \'$2==w {print $1; exit}\')\n'
) % _DATA_BYTES


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Instance-store bytes written in the guest are lost across a stop/start (new host) while EBS
    bytes persist, and a reboot (same host) preserves both; the local disk is never an EBS volume.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "ec2-instance-store-ephemerality"
    nonce = ctx.unique_name("sim2real-nonce-")

    # --- everything decidable, before anything is created ---------------------
    itype, arch, store_gb, az = _pick_instance_store_type(ec2)
    ami = ssm.get_parameter(
        Name=f"/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-{arch}"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 {arch} parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one instance that has a local NVMe disk ------------------------------
    tag_spec = [
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": profile},
                                      {"Key": "sim2real", "Value": scenario}]}
        for rt in ("instance", "volume")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=itype, MinCount=1, MaxCount=1, SubnetId=subnet,
            IamInstanceProfile={"Name": profile}, TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    # Registered before any wait so a host that never registers with SSM is not left billing.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert reservation["Instances"][0]["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {reservation['Instances'][0]['Placement']!r}, not {az!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # --- a 1 GiB EBS volume, attached to the same machine ---------------------
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_DATA_GIB, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
          lambda s: s == "available", timeout_s=300, interval_s=3.0,
          what=f"volume {volume_id} reaching 'available'")
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    _poll(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"],
          lambda a: bool(a) and a[0]["State"] == "attached", timeout_s=300, interval_s=3.0,
          what=f"volume {volume_id} reaching 'attached' on {instance_id}")

    # --- the control plane must NOT represent the local disk as a volume ------
    attached = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]):
        attached += page["Volumes"]
    assert volume_id in {v["VolumeId"] for v in attached}, (
        f"the volume just attached is not among this instance's volumes: {attached!r}"
    )
    assert not [v for v in attached if v["Size"] == store_gb], (
        f"an instance-store disk of {store_gb} GB must never appear as an EBS volume, but "
        f"DescribeVolumes reported one attached to {instance_id}: {attached!r}"
    )

    # --- the agent must register: a host that never registers is a FAIL -------
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=420, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- phase 1: make a filesystem on each disk and write the nonce ----------
    provision = [
        "set -euo pipefail",
        _FIND_DEVICES,
        'if [ -z "$ESS" ]; then echo "NO-LOCAL-NVME"; lsblk -dn -o NAME,SIZE,MODEL; exit 1; fi',
        'if [ -z "$EBS" ]; then echo "NO-EBS-DATA-DISK"; lsblk -dn -b -o NAME,SIZE,MODEL; exit 1; fi',
        'mkfs.ext4 -qF "/dev/$ESS"',
        'mkfs.ext4 -qF "/dev/$EBS"',
        "mkdir -p /mnt/ess /mnt/ebs",
        'mount "/dev/$ESS" /mnt/ess',
        'mount "/dev/$EBS" /mnt/ebs',
        f'echo "{nonce}" > /mnt/ess/nonce',
        f'echo "{nonce}" > /mnt/ebs/nonce',
        "sync",
        "umount /mnt/ess /mnt/ebs",
        'echo "SIM2REAL-PROVISIONED boot=$(cat /proc/sys/kernel/random/boot_id)'
        ' ess_dev=$ESS ebs_dev=$EBS"',
    ]
    out = _run_guest(ssm, instance_id, provision, "provisioning the two filesystems")
    first = _report(out, "SIM2REAL-PROVISIONED")
    assert first and first.get("boot") and first.get("ess_dev") and first.get("ebs_dev"), (
        f"the guest did not report a provisioned pair of disks; its stdout was {out!r}"
    )
    boot0 = first["boot"]

    # Read the nonce back on the SAME boot first, so a later absence cannot be blamed on a write
    # that never landed.
    read_back = [
        "set -uo pipefail",
        _FIND_DEVICES,
        "mkdir -p /mnt/ess /mnt/ebs",
        'ESSV=absent; EBSV=absent',
        'if [ -n "$ESS" ]; then',
        '  if mount -o ro "/dev/$ESS" /mnt/ess 2>/dev/null; then',
        '    ESSV=$(cat /mnt/ess/nonce 2>/dev/null || echo no-file); umount /mnt/ess;',
        '  else ESSV=unmountable; fi',
        'else ESS=no-device; fi',
        'if [ -n "$EBS" ]; then',
        '  if mount -o ro "/dev/$EBS" /mnt/ebs 2>/dev/null; then',
        '    EBSV=$(cat /mnt/ebs/nonce 2>/dev/null || echo no-file); umount /mnt/ebs;',
        '  else EBSV=unmountable; fi',
        'else EBS=no-device; fi',
        'echo "SIM2REAL-READ boot=$(cat /proc/sys/kernel/random/boot_id)'
        ' ess_dev=$ESS ess=$ESSV ebs_dev=$EBS ebs=$EBSV"',
        'echo "SIM2REAL-DISKS $(lsblk -dn -b -o NAME,SIZE,MODEL | tr \'\\n\' \';\')"',
    ]
    same_boot = _report(_run_guest(ssm, instance_id, read_back, "reading back on the same boot"),
                        "SIM2REAL-READ")
    assert same_boot and same_boot.get("ess") == nonce and same_boot.get("ebs") == nonce, (
        f"the nonce {nonce!r} was not readable from BOTH disks on the boot that wrote it, so "
        f"nothing later can be attributed to a power transition; the guest reported {same_boot!r}"
    )
    assert same_boot["boot"] == boot0, (
        f"the machine rebooted between the write and the read (boot {boot0!r} -> "
        f"{same_boot['boot']!r}), so this read proves nothing about the write"
    )

    # --- transition 1: REBOOT keeps the physical host, so both disks survive ---
    ec2.reboot_instances(InstanceIds=[instance_id])
    # boot_id is regenerated per boot, so a new value proves the transition happened.
    after_reboot = _report(
        _poll(lambda: _run_guest(ssm, instance_id, read_back, "reading back after the reboot"),
              lambda o: (_report(o, "SIM2REAL-READ") or {}).get("boot") not in (None, boot0),
              timeout_s=600, interval_s=10.0,
              what=f"instance {instance_id} reporting a new boot id after RebootInstances"),
        "SIM2REAL-READ")
    boot1 = after_reboot["boot"]
    assert boot1 != boot0, f"the guest never rebooted: boot id stayed {boot0!r}"
    assert after_reboot["ess"] == nonce, (
        f"a REBOOT must preserve instance-store contents — the physical host does not change — but "
        f"the local disk read back as {after_reboot['ess']!r} instead of {nonce!r}; the guest "
        f"reported {after_reboot!r}"
    )
    assert after_reboot["ebs"] == nonce, (
        f"the EBS volume must survive a reboot, but it read back as {after_reboot['ebs']!r} "
        f"instead of {nonce!r}; the guest reported {after_reboot!r}"
    )

    # --- transition 2: STOP/START moves hosts, so the ephemeral disk is wiped --
    ec2.stop_instances(InstanceIds=[instance_id])
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "stopped",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'stopped'")
    # The EBS volume must still be attached across the power cycle; the local disk cannot be asked.
    stopped_attachments = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"]
    assert stopped_attachments and stopped_attachments[0]["InstanceId"] == instance_id, (
        f"a stopped instance must keep its EBS attachment, got {stopped_attachments!r}"
    )
    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]))
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} returning to 'running'")

    after_cycle = _report(
        _poll(lambda: _run_guest(ssm, instance_id, read_back, "reading back after the stop/start"),
              lambda o: (_report(o, "SIM2REAL-READ") or {}).get("boot") not in (None, boot0, boot1),
              timeout_s=900, interval_s=10.0,
              what=f"instance {instance_id} reporting a new boot id after the stop/start"),
        "SIM2REAL-READ")
    assert after_cycle["boot"] not in (boot0, boot1), (
        f"the machine did not boot afresh after the stop/start: boot id is "
        f"{after_cycle['boot']!r}, previously {boot0!r} then {boot1!r}"
    )
    # The invariant pair, on one machine, across one transition.
    assert after_cycle["ebs"] == nonce, (
        f"an EBS volume is network-attached and MUST carry its bytes across a stop/start, but the "
        f"nonce read back as {after_cycle['ebs']!r} instead of {nonce!r}; guest reported "
        f"{after_cycle!r}"
    )
    assert after_cycle["ess"] != nonce, (
        f"instance-store contents MUST NOT survive a stop/start — the instance moves to a new "
        f"physical host — but the local disk still carried the nonce {nonce!r}; guest reported "
        f"{after_cycle!r}"
    )
    # ...and the disk is still THERE, merely blank: a type with local storage keeps presenting it,
    # so 'the device disappeared' would be a different (and also wrong) behaviour.
    assert after_cycle["ess_dev"] != "no-device", (
        f"the instance type {itype!r} has {store_gb} GB of local NVMe storage, so the device must "
        f"still be present after a stop/start — merely blank. The guest reported {after_cycle!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
