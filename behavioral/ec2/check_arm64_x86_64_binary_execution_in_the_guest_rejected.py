"""arm64-x86-64-binary-execution-in-the-guest-rejected."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arm64-x86-64-binary-execution-in-the-guest-rejected"
GROUP = 'arm64-architecture'
SERVICES = ['ec2']

_ARM64_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
_INSTANCE_TYPE = "t4g.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

#: A complete, statically linked 157-byte x86-64 ELF that writes "X86OK\n" via `write(2)` and
#: exits 0 on x86-64. Carried as base64 inside the Run Command document; the guest's sha256 of the
#: reconstructed file is asserted so a truncated transfer cannot pass as an architecture refusal.
_X86_64_ELF_B64 = (
    "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAB"
    "AAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAnQAAAAAAAACdAAAAAAAAAAAQ"
    "AAAAAAAAuAEAAAC/AQAAAL6XAEAAugYAAAAPBbg8AAAAMf8PBVg4Nk9LCg=="
)
#: The marker the payload prints when it DOES execute. Its absence is the effect-absent assertion.
_X86_MARKER = "X86OK"
#: ELF `e_machine` for x86-64 (`EM_X86_64`) and for AArch64 (`EM_AARCH64`), from the ELF ABI.
_EM_X86_64 = "62"
_EM_AARCH64 = "183"
#: `e_type` ET_EXEC and `e_ident[EI_CLASS]` ELFCLASS64.
_ET_EXEC = "2"
_ELFCLASS64 = "2"
#: POSIX shells exit 126 when a file is found and permitted but cannot be executed.
_EXIT_CANNOT_EXEC = "126"


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

    Instance type offerings do not report zone state, and zone listings say nothing about types.
    """
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

    Built rather than borrowed, since an account may have no default VPC; each resource is tagged
    in the call that creates it.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2, instance_type)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.177.0.0/16",
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
        VpcId=vpc_id, CidrBlock="10.177.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-arm64x-"), VpcId=vpc_id,
        Description="sim2real arm64 exec-format egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-arm64x-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real arm64 exec-format managed instance role",
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

    The ENI and root volume only go away at 'terminated'; the later network deletions depend on it.
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
        Comment="sim2real arm64 exec-format read-back"))
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


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An intact x86-64 ELF executable fails on a t4g.micro guest with exit 126 and 'Exec format
    error' and never prints its marker, while a native AArch64 binary at the same path runs.
    """
    scenario = "arm64-exec-format"
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    payload = base64.b64decode(_X86_64_ELF_B64)
    expected_sha = hashlib.sha256(payload).hexdigest()
    expected_size = str(len(payload))

    # --- the arm64 AMI, resolved rather than pinned -------------------------------------------
    ami = ssm.get_parameter(Name=_ARM64_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_ARM64_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    assert image["Architecture"] == "arm64", (
        f"the arm64 Amazon Linux parameter resolved to {ami!r}, which DescribeImages calls "
        f"{image['Architecture']!r} — the refusal below would then prove nothing"
    )

    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario, _INSTANCE_TYPE)
    profile_name = _instance_profile(ctx, scenario)

    inst = _launch(ctx, ami=ami, instance_type=_INSTANCE_TYPE, profile_name=profile_name,
                   subnet_id=subnet_id, sg_id=sg_id, scenario=scenario)
    instance_id = inst["InstanceId"]
    # Registered before the first wait so a host that never comes up is still terminated.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)

    # --- the x86-64 payload and its AArch64 control, in one invocation ------------------------
    inv = _run_shell(ctx, instance_id, [
        "set -uo pipefail",
        "D=$(mktemp -d /tmp/sim2real-arm64.XXXXXX)",
        'cd "$D"',
        f"printf '%s' '{_X86_64_ELF_B64}' | base64 -d > x86only",
        "chmod 755 x86only",
        'echo "GUEST-SHA $(sha256sum x86only | cut -d\' \' -f1)"',
        'echo "GUEST-SIZE $(stat -c %s x86only)"',
        # The reconstructed file's own ELF header: EI_CLASS at 4, e_type at 16, e_machine at 18.
        'echo "GUEST-ELFCLASS $(od -An -tu1 -j4 -N1 x86only | tr -d \' \')"',
        'echo "GUEST-ETYPE $(od -An -tu2 -j16 -N2 x86only | tr -d \' \')"',
        'echo "GUEST-EMACHINE $(od -An -tu2 -j18 -N2 x86only | tr -d \' \')"',
        'echo "GUEST-EXECUTABLE $(test -x x86only && echo yes || echo no)"',
        "X86OUT=$(./x86only 2>x86err) ; X86RC=$?",
        'echo "GUEST-X86-RC $X86RC"',
        'echo "GUEST-X86-STDOUT [$X86OUT]"',
        "echo \"GUEST-X86-STDERR [$(tr '\\n' ' ' < x86err | sed 's/ *$//')]\"",
        # Positive control: a NATIVE AArch64 ELF, same directory, same mode, same invocation form.
        "cp /usr/bin/uname native",
        "chmod 755 native",
        "NATOUT=$(./native -m 2>naterr) ; NATRC=$?",
        'echo "GUEST-NATIVE-RC $NATRC"',
        'echo "GUEST-NATIVE-STDOUT [$NATOUT]"',
        'echo "GUEST-NATIVE-EMACHINE $(od -An -tu2 -j18 -N2 native | tr -d \' \')"',
        "echo \"GUEST-NATIVE-STDERR [$(tr '\\n' ' ' < naterr | sed 's/ *$//')]\"",
        'cd / && rm -rf "$D"',
    ], what="executing the x86-64 payload and its AArch64 control in the guest")

    assert inv["Status"] == "Success", (
        f"the invocation itself must complete — the graded failure is the payload's exit status, "
        f"not the command's; got {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]

    # --- the payload really is an intact x86-64 executable, per the guest itself ---------------
    assert _marker(out, "GUEST-SHA") == expected_sha, (
        f"the guest must have reconstructed the exact payload bytes (sha256 {expected_sha}); it "
        f"computed {_marker(out, 'GUEST-SHA')!r} — a mangled transfer, not an architecture "
        f"refusal. Full stdout: {out!r}"
    )
    assert _marker(out, "GUEST-SIZE") == expected_size, (
        f"the reconstructed file must be {expected_size} bytes; the guest saw "
        f"{_marker(out, 'GUEST-SIZE')!r}"
    )
    assert _marker(out, "GUEST-ELFCLASS") == _ELFCLASS64, (
        f"the payload must be ELFCLASS64 ({_ELFCLASS64}) in the guest's own reading of its header, "
        f"got {_marker(out, 'GUEST-ELFCLASS')!r}"
    )
    assert _marker(out, "GUEST-ETYPE") == _ET_EXEC, (
        f"the payload must be ET_EXEC ({_ET_EXEC}), an executable rather than a shared object; the "
        f"guest read e_type={_marker(out, 'GUEST-ETYPE')!r}"
    )
    assert _marker(out, "GUEST-EMACHINE") == _EM_X86_64, (
        f"the payload must declare EM_X86_64 ({_EM_X86_64}) in the header the kernel dispatches "
        f"on; the guest read e_machine={_marker(out, 'GUEST-EMACHINE')!r}"
    )
    assert _marker(out, "GUEST-EXECUTABLE") == "yes", (
        f"the payload must carry the execute bit, so a refusal cannot be a permission problem; the "
        f"guest reported {_marker(out, 'GUEST-EXECUTABLE')!r}"
    )

    # --- the refusal: exact status, exact kernel diagnostic, effect absent --------------------
    assert _marker(out, "GUEST-X86-RC") == _EXIT_CANNOT_EXEC, (
        f"executing an x86-64 binary on AArch64 must fail with status {_EXIT_CANNOT_EXEC} (found, "
        f"permitted, not executable); the guest's shell reported "
        f"{_marker(out, 'GUEST-X86-RC')!r}. Full stdout: {out!r}"
    )
    x86_stderr = _marker(out, "GUEST-X86-STDERR")
    assert x86_stderr is not None and x86_stderr.endswith("Exec format error]"), (
        f"the kernel must refuse the exec with 'Exec format error'; the guest's shell said "
        f"{x86_stderr!r}"
    )
    assert "cannot execute binary file" in x86_stderr, (
        f"the diagnostic must name the exec failure rather than a missing file or interpreter; got "
        f"{x86_stderr!r}"
    )
    assert _marker(out, "GUEST-X86-STDOUT") == "[]", (
        f"the effect must be ABSENT: the payload prints {_X86_MARKER!r} when it executes, so its "
        f"stdout must be empty on AArch64; the guest captured "
        f"{_marker(out, 'GUEST-X86-STDOUT')!r}"
    )
    assert _X86_MARKER not in out, (
        f"{_X86_MARKER!r} appeared somewhere in the invocation output, which means the x86-64 "
        f"payload executed on a host that reports itself as AArch64: {out!r}"
    )

    # --- positive control: the same act with native machine code succeeds ---------------------
    assert _marker(out, "GUEST-NATIVE-RC") == "0", (
        f"the positive control must succeed — a native AArch64 ELF at the same path, with the same "
        f"mode, invoked the same way; it exited {_marker(out, 'GUEST-NATIVE-RC')!r} with stderr "
        f"{_marker(out, 'GUEST-NATIVE-STDERR')!r}"
    )
    assert _marker(out, "GUEST-NATIVE-STDOUT") == "[aarch64]", (
        f"the native control must run and report the guest's machine as aarch64; it printed "
        f"{_marker(out, 'GUEST-NATIVE-STDOUT')!r}"
    )
    assert _marker(out, "GUEST-NATIVE-EMACHINE") == _EM_AARCH64, (
        f"the control binary must be EM_AARCH64 ({_EM_AARCH64}) — that is the only difference "
        f"between it and the refused payload; the guest read "
        f"{_marker(out, 'GUEST-NATIVE-EMACHINE')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
