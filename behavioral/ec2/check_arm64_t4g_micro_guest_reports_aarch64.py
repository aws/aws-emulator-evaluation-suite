"""arm64-t4g-micro-guest-reports-aarch64."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arm64-t4g-micro-guest-reports-aarch64"
GROUP = 'arm64-architecture'
SERVICES = ['ec2']

_ARM64_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
_INSTANCE_TYPE = "t4g.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: ELF `e_machine` for AArch64, from the ELF ABI (`EM_AARCH64`). The guest reads this out of the
#: header of its OWN shell, so the value is the kernel's view of what it can execute.
_EM_AARCH64 = "183"
#: ELF `e_ident[EI_CLASS]` for a 64-bit object (`ELFCLASS64`).
_ELFCLASS64 = "2"
#: `CPU implementer` for Arm Ltd in /proc/cpuinfo — Graviton cores are Arm Neoverse.
_ARM_IMPLEMENTER = "0x41"




def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
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
    """Poll probe() until predicate(result); AssertionError on timeout."""
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


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=40, delay=5.0):
    """Delete, tolerating 'already gone' and retrying 'still referenced'."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_type):
    """An AZ that is BOTH 'available' and offers instance_type.

    Offerings do not report zone state and zones say nothing about instance types; AZ names are
    per-account aliases, so none is hardcoded."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in this region offers {instance_type!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario, instance_type):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed, as the account may have no default VPC. Every resource is tagged in
    the call that creates it."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2, instance_type)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.176.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _delete_with_retry(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound",
                  "InvalidVpcID.NotFound"))
        _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
                           gone=("InvalidInternetGatewayID.NotFound",))

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # The VPC's own main route table, which is created with the VPC and destroyed with it.
    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.176.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-arm64-"), VpcId=vpc_id,
        Description="sim2real arm64 architecture egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-arm64-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real arm64 architecture managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_profile():
        _delete_with_retry(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name), gone=("NoSuchEntity",),
            busy=("DeleteConflict",))
        _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                           gone=("NoSuchEntity",), busy=("DeleteConflict",))

    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


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
    """Terminate and wait for 'terminated' — not merely 'shutting-down'.

    The ENI and the root volume only go away at 'terminated', and the subnet, security group and
    VPC deletions registered EARLIER (and therefore running later, LIFO) all depend on that.
    """
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


def _launch(ctx, *, ami, instance_type, profile_name, subnet_id, sg_id, scenario):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    return resv["Instances"][0]


def _wait_online(ctx, instance_id, timeout_s=600):
    """Wait for the SSM agent on this host to report Online. Never registering is a FAIL."""
    ssm = ctx.client("ssm")

    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    return _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=timeout_s, interval_s=10.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=300):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=300,
        Comment="sim2real arm64 architecture read-back"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 timeout_s=timeout_s, interval_s=5.0,
                 what=f"{what}: invocation {command_id} reaching a terminal status")


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None.

    Anchored at the marker rather than split over the whole line so an extra word from the guest's
    own tooling cannot be read as the value.
    """
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value




@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A t4g.micro from the arm64 Amazon Linux AMI is really AArch64: inside the guest `uname -m`
    is aarch64, /bin/sh is an EM_AARCH64 ELF64, the CPU is an Arm implementer with no x86 loader,
    and IMDS names this instance; the control-plane Architecture is checked only as agreement."""
    scenario = "arm64-guest-architecture"
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    # --- the arm64 AMI, resolved rather than pinned, and its declared architecture -----------
    ami = ssm.get_parameter(Name=_ARM64_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_ARM64_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    assert image["Architecture"] == "arm64", (
        f"the arm64 Amazon Linux parameter resolved to {ami!r}, which DescribeImages calls "
        f"{image['Architecture']!r} — the rest of this check would be measuring the wrong image"
    )
    itype = ec2.describe_instance_types(InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"][0]
    assert itype["ProcessorInfo"]["SupportedArchitectures"] == ["arm64"], (
        f"{_INSTANCE_TYPE} must be an arm64-only type, got "
        f"{itype['ProcessorInfo']['SupportedArchitectures']!r}"
    )

    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario, _INSTANCE_TYPE)
    profile_name = _instance_profile(ctx, scenario)

    inst = _launch(ctx, ami=ami, instance_type=_INSTANCE_TYPE, profile_name=profile_name,
                   subnet_id=subnet_id, sg_id=sg_id, scenario=scenario)
    instance_id = inst["InstanceId"]
    # Registered before the first wait: a host that never comes up must not strand a billing
    # instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    info = _wait_online(ctx, instance_id)
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- what the machine itself says, read back through Run Command --------------------------
    inv = _run_shell(ctx, instance_id, [
        "set -uo pipefail",
        'echo "GUEST-UNAME-M $(uname -m)"',
        'echo "GUEST-LONGBIT $(getconf LONG_BIT)"',
        # The ELF header of the guest's OWN shell: e_machine at offset 18, EI_CLASS at offset 4.
        'echo "GUEST-SH-EMACHINE $(od -An -tu2 -j18 -N2 /bin/sh | tr -d \' \')"',
        'echo "GUEST-SH-ELFCLASS $(od -An -tu1 -j4 -N1 /bin/sh | tr -d \' \')"',
        'echo "GUEST-CPU-IMPL $(awk \'/CPU implementer/ {print $4; exit}\' /proc/cpuinfo)"',
        'echo "GUEST-X86-FLAG-LINES $(grep -c \'^flags\' /proc/cpuinfo || true)"',
        'echo "GUEST-X86-LOADERS $(ls -1 /lib64/ld-linux-x86-64.so.2 2>/dev/null | wc -l)"',
        "TOK=$(curl -s -m 10 -X PUT http://169.254.169.254/latest/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')",
        'echo "GUEST-IMDS-TYPE $(curl -s -m 10 -H \"X-aws-ec2-metadata-token: $TOK\"'
        ' http://169.254.169.254/latest/meta-data/instance-type)"',
        'echo "GUEST-IMDS-IID $(curl -s -m 10 -H \"X-aws-ec2-metadata-token: $TOK\"'
        ' http://169.254.169.254/latest/meta-data/instance-id)"',
    ], what="reading the guest's own architecture")

    assert inv["Status"] == "Success", (
        f"the read-back invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"ResponseCode was {inv['ResponseCode']!r}, stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]

    assert _marker(out, "GUEST-UNAME-M") == "aarch64", (
        f"the kernel on a {_INSTANCE_TYPE} launched from an arm64 AMI must report machine "
        f"'aarch64'; the guest reported {_marker(out, 'GUEST-UNAME-M')!r} — the instance is not "
        f"actually running on Graviton. Full stdout: {out!r}"
    )
    assert _marker(out, "GUEST-LONGBIT") == "64", (
        f"an AArch64 userland is 64-bit; getconf LONG_BIT reported "
        f"{_marker(out, 'GUEST-LONGBIT')!r}"
    )
    assert _marker(out, "GUEST-SH-EMACHINE") == _EM_AARCH64, (
        f"the guest's own /bin/sh must be an EM_AARCH64 ({_EM_AARCH64}) object for the kernel to "
        f"have executed it; its ELF header says e_machine="
        f"{_marker(out, 'GUEST-SH-EMACHINE')!r}"
    )
    assert _marker(out, "GUEST-SH-ELFCLASS") == _ELFCLASS64, (
        f"/bin/sh must be ELFCLASS64 ({_ELFCLASS64}); its header says "
        f"{_marker(out, 'GUEST-SH-ELFCLASS')!r}"
    )
    assert _marker(out, "GUEST-CPU-IMPL") == _ARM_IMPLEMENTER, (
        f"a Graviton core identifies itself in /proc/cpuinfo as Arm implementer "
        f"{_ARM_IMPLEMENTER!r}; the guest reported {_marker(out, 'GUEST-CPU-IMPL')!r}"
    )
    assert _marker(out, "GUEST-X86-FLAG-LINES") == "0", (
        f"/proc/cpuinfo on AArch64 has no x86 'flags' line (it reports 'Features'); the guest "
        f"found {_marker(out, 'GUEST-X86-FLAG-LINES')!r} of them"
    )
    assert _marker(out, "GUEST-X86-LOADERS") == "0", (
        f"an arm64 root filesystem carries no x86-64 dynamic loader; the guest found "
        f"{_marker(out, 'GUEST-X86-LOADERS')!r} at /lib64/ld-linux-x86-64.so.2"
    )
    assert _marker(out, "GUEST-IMDS-TYPE") == _INSTANCE_TYPE, (
        f"IMDS read from inside the guest must report the type it was launched as; it reported "
        f"{_marker(out, 'GUEST-IMDS-TYPE')!r}"
    )
    assert _marker(out, "GUEST-IMDS-IID") == instance_id, (
        f"the guest read its own instance id as {_marker(out, 'GUEST-IMDS-IID')!r} from IMDSv2 "
        f"but RunInstances returned {instance_id!r} — the control plane and the running machine "
        f"disagree about which machine this is"
    )

    # --- the control-plane echo, asserted LAST and only as agreement with the guest ----------
    described = [i for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
                 for i in r["Instances"]]
    assert len(described) == 1, f"expected exactly one instance, got {described!r}"
    assert described[0]["Architecture"] == "arm64", (
        f"DescribeInstances must agree with the guest that reported aarch64; it says "
        f"{described[0]['Architecture']!r}"
    )
    assert described[0]["InstanceType"] == _INSTANCE_TYPE, described[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
