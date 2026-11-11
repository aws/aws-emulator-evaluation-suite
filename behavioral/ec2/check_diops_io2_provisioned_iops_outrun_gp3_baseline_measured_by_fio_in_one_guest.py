"""diops-io2-provisioned-iops-outrun-gp3-baseline-measured-by-fio-in-one-guest."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "diops-io2-provisioned-iops-outrun-gp3-baseline-measured-by-fio-in-one-guest"
GROUP = 'diops-provisioned-iops'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_AL2023_SSM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

#: The smallest instance that can exhibit the ordering. t3.micro's EbsOptimizedInfo reports
#: BaselineIops 500 behind a burst-credit bucket, so a gp3 volume at its 3000 IOPS floor is
#: already above what the HOST will sustain and the two volumes would measure the same. m5.large
#: reports BaselineIops 3600 / MaximumIops 18750 — the first size in the family whose ceiling is
#: several times the gp3 floor, which is what makes a difference in the volumes visible at all.
#: Read, never assumed: the ceiling is taken from DescribeInstanceTypes below and asserted.
_INSTANCE_TYPE = "m5.large"
#: gp3's IOPS floor. A fixed API constant, not a quota: every gp3 volume gets 3000 IOPS and AWS
#: does not raise it for an account, so it is legitimate to name here (unlike the host ceiling).
_GP3_BASELINE_IOPS = 3000
#: The io2 provisioning, expressed as a MULTIPLE of the gp3 floor and then clamped by whatever
#: the instance says it can drive. Nothing absolute is asserted about the outcome; the multiple
#: only has to be large enough that the ordering is measurable rather than noise.
_IO2_MULTIPLE = 4
#: Both volumes are the same size, so volume type and provisioned IOPS are the only difference
#: between them. 50 GiB keeps the io2 target inside io2's 1000:1 IOPS-per-GiB ceiling and gp3's
#: 500:1 with room to spare, so the size is never the thing under test.
_VOLUME_GIB = 50
#: 4 KiB random writes at queue depth 64 over four jobs: the standard shape for saturating a
#: provisioned-IOPS ceiling. 20 s of measurement after a 5 s ramp is long enough to average out
#: the first-touch jitter and far shorter than the instance's burst allowance.
_FIO_RUNTIME_S = 20
_FIO_RAMP_S = 5

# ===== helpers =====


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


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that both is 'available' and offers the instance type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. A literal AZ name would be the
    same capacity gamble wearing a fixed name, since AZ names are per-account aliases for
    different physical zones.
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
        f"no available AZ in this region offers {instance_type!r}; the intersection of the "
        f"offerings {sorted(offered)!r} with the available zones was empty"
    )
    return usable[0]


def _host_ebs_ceiling(ec2, instance_type=_INSTANCE_TYPE):
    """The instance type's own EBS IOPS ceiling and floor, as AWS reports them.

    Read from DescribeInstanceTypes rather than written down, because the numbers a host can
    drive are the target's to state: pinning them here would make this check grade a constant.
    """
    info = ec2.describe_instance_types(InstanceTypes=[instance_type])["InstanceTypes"][0]
    ebs = info["EbsInfo"]["EbsOptimizedInfo"]
    return int(ebs["MaximumIops"]), int(ebs["BaselineIops"])


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind. Bounded: a
    DependencyViolation that never clears is a leak to declare, not a loop to sit in."""
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


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared
    default subnet makes the check assert a property of the account. The
    SSM agent needs egress to reach its endpoint, and the guest needs it to install fio. The CIDR
    picks a random second octet so two concurrent runs in one account read differently in a
    console; overlapping VPC CIDRs are legal because these VPCs are never peered. Every object is
    tagged in the call that creates it.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

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
    role = ctx.unique_name("sim2real-diops-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav provisioned-iops role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    # Propagation is waited out by RunInstances' bounded InvalidParameterValue retry below.
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


def _terminate_and_wait(ec2, instance_id, timeout_s=900):
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


def _describe_volume(ec2, volume_id):
    """DescribeVolumes for one id, paginated."""
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} appears in no page of DescribeVolumes")


def _detach_and_delete_volume(ec2, volume_id, timeout_s=420):
    """Detach if attached, wait for 'available', then delete. Self-sufficient rather than
    order-dependent: a delete of an in-use volume is refused."""
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
        time.sleep(5)
    _retry_delete(lambda: ec2.delete_volume(VolumeId=volume_id))


def _make_volume(ctx, ec2, az, scenario, **kw):
    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=_VOLUME_GIB,
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario},
                                     {"Key": "Name",
                                      "Value": ctx.unique_name("sim2real-diops-")}]}],
        **kw,
    )["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, volume_id))
    _poll(lambda: _describe_volume(ec2, volume_id)["State"], lambda s: s == "available",
          timeout_s=420, interval_s=3.0, what=f"volume {volume_id} reaching 'available'")
    return volume_id


def _attach(ec2, volume_id, instance_id, device):
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=device)
    _poll(lambda: _describe_volume(ec2, volume_id).get("Attachments") or [],
          lambda a: bool(a) and a[0]["State"] == "attached",
          timeout_s=420, interval_s=3.0,
          what=f"volume {volume_id} reaching 'attached' on {instance_id}")


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a freshly booted host rejects SendCommand
    with InvalidInstanceId until its agent has registered, so retrying that call polls an
    observable condition instead of sleeping a guessed interval. A host that never accepts a
    command is a FAIL, not a reason to stop grading.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav provisioned iops",
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
        f"stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _fields(line):
    return {k: v for k, _, v in (f.partition("=") for f in line.split()) if k and v}


def _report(stdout, marker):
    """The `key=value` fields of the last line starting with `marker`, as a dict."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith(marker):
            return _fields(line[len(marker):])
    return None


def _wait_agent_online(ssm, instance_id):
    """Wait for the SSM agent to register; the listing is account-wide, so it is paginated."""
    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
          timeout_s=600, interval_s=5.0, what=f"the SSM agent on {instance_id} coming Online")


def _guest_device_for(ssm, instance_id, volume_id, what):
    """The guest's block device for `volume_id`, resolved by the NVMe serial AWS puts on it.

    Read inside the machine, and by serial rather than by path: Nitro presents EBS volumes as
    /dev/nvme?n1 in an order that is not the attachment order, so the Device name handed to
    AttachVolume is a request and never a promise. The serial IS the volume id with the hyphen
    removed, which is the only handle that survives that reordering.
    """
    wanted = volume_id.replace("-", "")
    out = _run_guest(ssm, instance_id, [
        "set -uo pipefail",
        'lsblk -dn -o NAME,SERIAL | awk \'{print "SIM2REAL-DISK name="$1" serial="$2}\'',
    ], what)
    disks = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SIM2REAL-DISK"):
            f = _fields(line[len("SIM2REAL-DISK"):])
            if f.get("serial") and f.get("name"):
                disks[f["serial"]] = f["name"]
    assert wanted in disks, (
        f"{what}: the guest sees no block device carrying the serial {wanted!r} of volume "
        f"{volume_id}; it reports serial->device {disks!r}"
    )
    return "/dev/" + disks[wanted]


def _install_fio(ssm, instance_id, what):
    """Install fio in the guest. Its absence is a FAILURE that names it, never a skip."""
    out = _run_guest(ssm, instance_id, [
        "set -uo pipefail",
        "dnf install -y -q fio > /tmp/diops-dnf.log 2>&1 || "
        '{ echo "required tool not available in this environment: fio"; '
        "tail -20 /tmp/diops-dnf.log; exit 1; }",
        'echo "SIM2REAL-FIO-INSTALL version=$(fio --version)"',
    ], what, run_timeout_s=600)
    rep = _report(out, "SIM2REAL-FIO-INSTALL")
    assert rep and rep.get("version"), (
        f"{what}: fio did not report a version after installation; stdout {out!r}"
    )
    return rep["version"]


def _guest_fio_iops(ssm, instance_id, device, what):
    """Achieved 4 KiB random-write IOPS on `device`, MEASURED BY FIO INSIDE THE GUEST.

    The number is read out of fio's own JSON report and nothing else: it is what the guest
    observed the block device sustaining, not what any DescribeVolumes said about it. The
    mount-point guard is a safety belt — a script that reached the root disk would destroy the
    instance it is measuring — and its trip is a distinguishable failure rather than a hang.
    """
    out = _run_guest(ssm, instance_id, [
        "set -uo pipefail",
        f"D={device}",
        'M=$(lsblk -no MOUNTPOINT "$D" | tr -d "[:space:]")',
        'if [ -n "$M" ]; then echo "SIM2REAL-FIO-REFUSED mounts=$M"; exit 1; fi',
        'fio --name=diops --filename="$D" --rw=randwrite --bs=4k --direct=1 --ioengine=libaio '
        f"--iodepth=64 --numjobs=4 --group_reporting --time_based --runtime={_FIO_RUNTIME_S} "
        f"--ramp_time={_FIO_RAMP_S} --norandommap --randrepeat=0 --output-format=json "
        "--output=/tmp/diops-fio.json > /dev/null",
        # Summed over every job fio reports, so the number is the same whether fio collapses
        # --group_reporting into one entry or lists all four.
        'python3 -c "'
        "import json;d=json.load(open('/tmp/diops-fio.json'));"
        "print('SIM2REAL-FIO iops=%d bytes=%d' % "
        "(round(sum(j['write']['iops'] for j in d['jobs'])), "
        "sum(j['write']['io_bytes'] for j in d['jobs'])))"
        '"',
    ], what, run_timeout_s=600)
    rep = _report(out, "SIM2REAL-FIO")
    assert rep and rep.get("iops") and rep.get("bytes"), (
        f"{what}: fio produced no parseable IOPS report inside the guest; stdout {out!r}"
    )
    iops, moved = int(rep["iops"]), int(rep["bytes"])
    assert moved > 0, (
        f"{what}: fio reports {iops} IOPS on {device} but {moved} bytes written — no data moved, "
        f"so the rate is not a measurement of anything"
    )
    return iops


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """An io2 volume with high provisioned IOPS sustains strictly more 4 KiB random writes than a gp3
    volume at its baseline, measured by fio in one guest with both attached, and DescribeVolumes
    reports each volume's provisioning; only the ordering is asserted, never a rate."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "diops-io2-outruns-gp3"

    max_iops, baseline_iops = _host_ebs_ceiling(ec2)
    assert max_iops >= 2 * _GP3_BASELINE_IOPS, (
        f"{_INSTANCE_TYPE} reports MaximumIops {max_iops} against a gp3 floor of "
        f"{_GP3_BASELINE_IOPS}, so no io2 provisioning could measurably outrun gp3 on this host "
        f"and the ordering would be noise; BaselineIops is {baseline_iops}"
    )
    io2_iops = min(max_iops, _IO2_MULTIPLE * _GP3_BASELINE_IOPS)

    az = _usable_az(ec2)
    ami = ssm.get_parameter(Name=_AL2023_SSM)["Parameter"]["Value"]
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
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=900, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    _wait_agent_online(ssm, instance_id)

    # --- the two volumes: identical but for the provisioning under test -------
    gp3 = _make_volume(ctx, ec2, az, scenario, VolumeType="gp3")
    io2 = _make_volume(ctx, ec2, az, scenario, VolumeType="io2", Iops=io2_iops)

    gp3_record = _describe_volume(ec2, gp3)
    assert gp3_record.get("Iops") == _GP3_BASELINE_IOPS, (
        f"a gp3 volume created without an Iops argument must report the {_GP3_BASELINE_IOPS} "
        f"baseline; DescribeVolumes reports {gp3_record.get('Iops')!r} for {gp3}"
    )
    io2_record = _describe_volume(ec2, io2)
    assert io2_record.get("Iops") == io2_iops, (
        f"io2 volume {io2} was created with Iops {io2_iops}; DescribeVolumes reports "
        f"{io2_record.get('Iops')!r}"
    )
    assert io2_record.get("Size") == gp3_record.get("Size"), (
        f"the two volumes must differ only in provisioning, but they are "
        f"{io2_record.get('Size')!r} GiB and {gp3_record.get('Size')!r} GiB"
    )

    _attach(ec2, gp3, instance_id, "/dev/sdf")
    _attach(ec2, io2, instance_id, "/dev/sdg")

    gp3_dev = _guest_device_for(ssm, instance_id, gp3, "locating the gp3 volume in the guest")
    io2_dev = _guest_device_for(ssm, instance_id, io2, "locating the io2 volume in the guest")
    assert gp3_dev != io2_dev, (
        f"the two volumes must be two distinct block devices inside the guest, but both resolved "
        f"to {gp3_dev!r}"
    )

    _install_fio(ssm, instance_id, "installing fio in the guest")

    # gp3 first, deliberately: its 3000 IOPS floor is below the host's own BaselineIops, so this
    # leg cannot spend the burst allowance the io2 leg then needs.
    gp3_measured = _guest_fio_iops(ssm, instance_id, gp3_dev,
                                   f"measuring the gp3 baseline volume {gp3} in the guest")
    io2_measured = _guest_fio_iops(ssm, instance_id, io2_dev,
                                   f"measuring the io2 volume {io2} in the guest")

    assert io2_measured > gp3_measured, (
        f"the io2 volume {io2}, provisioned at {io2_iops} IOPS, must sustain strictly more 4 KiB "
        f"random writes than the gp3 volume {gp3} at its {_GP3_BASELINE_IOPS} baseline — the two "
        f"are the same size, in the same AZ, on the same instance, under the same fio job, so "
        f"provisioning is the only difference. fio measured io2 at {io2_measured} IOPS and gp3 at "
        f"{gp3_measured} IOPS inside the guest ({_INSTANCE_TYPE} reports MaximumIops {max_iops}, "
        f"BaselineIops {baseline_iops})"
    )
    # The absence half, and a DIFFERENT statement from the ordering above: the host is able to
    # drive io2_iops — it just did — so the gp3 volume staying under that level is the volume's
    # own provisioning capping it, not the host running out of allowance. An implementation that
    # lets host headroom leak into an unprovisioned volume passes the ordering and fails this.
    assert gp3_measured < io2_iops, (
        f"the gp3 volume {gp3} measured {gp3_measured} IOPS inside the guest, at or above the "
        f"{io2_iops} IOPS provisioned for the io2 volume — on a host that had just been shown to "
        f"sustain that rate. A gp3 volume's ceiling is its own provisioning "
        f"({_GP3_BASELINE_IOPS}), not the host's ({max_iops})"
    )
    # ...and the provisioning DescribeVolumes reports did not drift while the data plane ran.
    assert _describe_volume(ec2, io2).get("Iops") == io2_iops, (
        f"io2 volume {io2} reports Iops "
        f"{_describe_volume(ec2, io2).get('Iops')!r} after the measurement, expected {io2_iops}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
