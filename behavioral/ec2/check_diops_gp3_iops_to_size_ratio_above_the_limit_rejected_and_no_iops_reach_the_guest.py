"""diops-gp3-iops-to-size-ratio-above-the-limit-rejected-and-no-iops-reach-the-guest."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "diops-gp3-iops-to-size-ratio-above-the-limit-rejected-and-no-iops-reach-the-guest"
GROUP = 'diops-provisioned-iops-rejected'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_AL2023_SSM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

#: A small instance whose EBS IOPS ceiling is several times the gp3 floor, so an increase is
#: measurable; t3.micro's BaselineIops of 500 sits below gp3's own floor.
_INSTANCE_TYPE = "m5.large"
#: gp3's defaults for a volume created without Iops or Throughput.
_GP3_BASELINE_IOPS = 3000
_GP3_BASELINE_THROUGHPUT = 125
#: gp3's IOPS-per-GiB ceiling and the throughput for the raised IOPS. The illegal value is
#: size * 500 + 1, so the refusal is attributable to the ratio alone.
_GP3_MAX_IOPS_PER_GIB = 500
_GP3_RAISED_THROUGHPUT = 750
#: Large enough that size * 500 is far above the host ceiling, so the legal target below is
#: decided by the host rather than by the ratio, and small enough to stay cheap.
_VOLUME_GIB = 50
_FIO_RUNTIME_S = 20
_FIO_RAMP_S = 5

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """The (code, message) of the ClientError raised by fn.

    Raises when fn succeeds, so an unexpected acceptance is never read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
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

    Offerings do not report zone state and zones do not report instance types, so both are read.
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

    Read from DescribeInstanceTypes rather than pinned.
    """
    info = ec2.describe_instance_types(InstanceTypes=[instance_type])["InstanceTypes"][0]
    ebs = info["EbsInfo"]["EbsOptimizedInfo"]
    return int(ebs["MaximumIops"]), int(ebs["BaselineIops"])


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, retrying a bounded DependencyViolation window left by a just-terminated ENI."""
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

    The SSM agent needs egress to reach its endpoint, and the guest needs it to install fio.
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
    # Propagation is retried at first use: RunInstances retries InvalidParameterValue.
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
    """Terminate and wait for 'terminated', when the ENI clears and network teardown can proceed."""
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


def _modifications(ec2, volume_id):
    """Every VolumeModification record for one volume, PAGINATED and filtered to it.

    The filter form returns an empty list for a never-modified volume, where VolumeIds=[...]
    raises InvalidVolumeModification.NotFound.
    """
    found = []
    for page in ec2.get_paginator("describe_volumes_modifications").paginate(
            Filters=[{"Name": "volume-id", "Values": [volume_id]}]):
        found.extend(page["VolumesModifications"])
    return found


def _detach_and_delete_volume(ec2, volume_id, timeout_s=420):
    """Detach if attached, wait for 'available', then delete; an in-use volume cannot be deleted."""
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

    SendCommand fails with InvalidInstanceId until the agent registers, so that is retried.
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
    """Wait for the SSM agent to come Online; the listing is account-wide, so it is paginated."""
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

    Nitro does not keep the AttachVolume device name; the NVMe serial is the volume id without
    its hyphen.
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
    """Install fio in the guest; failure to install fails the check, naming fio."""
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
    """Achieved 4 KiB random-write IOPS on `device`, from fio's JSON report inside the guest.

    The mount-point guard refuses to write to a mounted disk such as the root volume.
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
        # Summed over every job, whether or not fio collapses --group_reporting into one entry.
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


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """ModifyVolume refuses gp3 IOPS one above the 500:1 IOPS-per-GiB ratio with no record and no
    guest-visible gain, while a legal target is applied and raises the IOPS fio measures inside the
    guest. Only the ordering of fio measurements is asserted, since provisioned IOPS is a ceiling.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/general-purpose.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "diops-gp3-ratio-rejected"

    max_iops, baseline_iops = _host_ebs_ceiling(ec2)
    assert max_iops >= 2 * _GP3_BASELINE_IOPS, (
        f"{_INSTANCE_TYPE} reports MaximumIops {max_iops} against a gp3 floor of "
        f"{_GP3_BASELINE_IOPS}, so no legal increase could measurably beat the baseline on this "
        f"host and the positive control would be noise; BaselineIops is {baseline_iops}"
    )
    legal_iops = min(max_iops, _GP3_MAX_IOPS_PER_GIB * _VOLUME_GIB)
    illegal_iops = _GP3_MAX_IOPS_PER_GIB * _VOLUME_GIB + 1

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

    volume = _make_volume(ctx, ec2, az, scenario, VolumeType="gp3")
    created = _describe_volume(ec2, volume)
    assert created.get("Iops") == _GP3_BASELINE_IOPS, (
        f"a gp3 volume created without an Iops argument must report the {_GP3_BASELINE_IOPS} "
        f"baseline; DescribeVolumes reports {created.get('Iops')!r} for {volume}"
    )
    assert created.get("Throughput") == _GP3_BASELINE_THROUGHPUT, (
        f"a gp3 volume created without a Throughput argument must report "
        f"{_GP3_BASELINE_THROUGHPUT} MiB/s; DescribeVolumes reports "
        f"{created.get('Throughput')!r} for {volume}"
    )
    _attach(ec2, volume, instance_id, "/dev/sdf")
    device = _guest_device_for(ssm, instance_id, volume, "locating the gp3 volume in the guest")
    _install_fio(ssm, instance_id, "installing fio in the guest")
    baseline_measured = _guest_fio_iops(
        ssm, instance_id, device, f"measuring {volume} at its gp3 defaults in the guest")

    code, message = _error(lambda: ec2.modify_volume(VolumeId=volume, Iops=illegal_iops))
    assert code == "InvalidParameterValue", (
        f"ModifyVolume must refuse {illegal_iops} IOPS on a {_VOLUME_GIB} GiB gp3 volume — one "
        f"IOP above the {_GP3_MAX_IOPS_PER_GIB}:1 IOPS-per-GiB ratio — with InvalidParameterValue; "
        f"real AWS returned {code!r}"
    )
    expected_message = (
        f"Iops to volume size ratio of {illegal_iops / _VOLUME_GIB:.6f} is too high; "
        f"maximum is {_GP3_MAX_IOPS_PER_GIB}"
    )
    assert message == expected_message, f"unexpected ratio refusal message: {message!r}"

    after_refusal_record = _describe_volume(ec2, volume)
    assert after_refusal_record.get("Iops") == _GP3_BASELINE_IOPS, (
        f"the refused modification must leave {volume} at {_GP3_BASELINE_IOPS} IOPS; "
        f"DescribeVolumes now reports {after_refusal_record.get('Iops')!r}"
    )
    assert after_refusal_record.get("Throughput") == _GP3_BASELINE_THROUGHPUT, (
        f"the refused modification touched nothing but Iops, so {volume}'s Throughput must still "
        f"be {_GP3_BASELINE_THROUGHPUT} MiB/s; DescribeVolumes reports "
        f"{after_refusal_record.get('Throughput')!r}"
    )
    assert _modifications(ec2, volume) == [], (
        f"a refused ModifyVolume must create no VolumeModification at all, but "
        f"DescribeVolumesModifications reports {_modifications(ec2, volume)!r} for {volume}"
    )
    refused_measured = _guest_fio_iops(
        ssm, instance_id, device, f"measuring {volume} after the refused modification")

    accepted = ec2.modify_volume(VolumeId=volume, Iops=legal_iops,
                                 Throughput=_GP3_RAISED_THROUGHPUT)["VolumeModification"]
    assert accepted["TargetIops"] == legal_iops, (
        f"ModifyVolume accepted the legal target but reports TargetIops "
        f"{accepted['TargetIops']!r}, expected {legal_iops}"
    )
    # A briefly empty filter result is one more poll rather than an IndexError.
    _poll(lambda: [m["ModificationState"] for m in _modifications(ec2, volume)],
          lambda s: s == ["completed"], timeout_s=1200, interval_s=10.0,
          what=f"the modification of {volume} reaching 'completed'")

    modified = _describe_volume(ec2, volume)
    assert modified.get("Iops") == legal_iops, (
        f"the accepted modification must be reflected in DescribeVolumes: {volume} should report "
        f"{legal_iops} IOPS, it reports {modified.get('Iops')!r}"
    )
    assert modified.get("Throughput") == _GP3_RAISED_THROUGHPUT, (
        f"the accepted modification must be reflected in DescribeVolumes: {volume} should report "
        f"{_GP3_RAISED_THROUGHPUT} MiB/s, it reports {modified.get('Throughput')!r}"
    )
    accepted_measured = _guest_fio_iops(
        ssm, instance_id, device, f"measuring {volume} after the accepted modification")

    assert accepted_measured > baseline_measured, (
        f"raising {volume} from {_GP3_BASELINE_IOPS} to {legal_iops} provisioned IOPS must raise "
        f"what the guest can actually sustain; fio measured {accepted_measured} IOPS after the "
        f"modification against {baseline_measured} IOPS before it, on the same device, the same "
        f"host and the same job ({_INSTANCE_TYPE} reports MaximumIops {max_iops})"
    )
    assert refused_measured < accepted_measured, (
        f"the refused modification must deliver none of the performance the accepted one did, but "
        f"fio measured {refused_measured} IOPS after the refusal and {accepted_measured} IOPS "
        f"after the acceptance — so the refusal either applied silently, or the acceptance did "
        f"nothing and the two are indistinguishable"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
