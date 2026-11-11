"""arm64-x86-64-payload-runs-on-t3-micro-and-is-rejected-on-t4g-micro."""
from __future__ import annotations

import base64
import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arm64-x86-64-payload-runs-on-t3-micro-and-is-rejected-on-t4g-micro"
GROUP = 'arm64-architecture'
SERVICES = ['ec2']

_ARM64_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
_X86_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_ARM64_TYPE = "t4g.micro"
_X86_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

#: A statically linked x86-64 ELF executable (157 bytes) that writes "X86OK\n" and exits 0;
#: base64 so the same bytes travel to both hosts in one Run Command document.
_X86_64_ELF_B64 = (
    "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAB"
    "AAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAnQAAAAAAAACdAAAAAAAAAAAQ"
    "AAAAAAAAuAEAAAC/AQAAAL6XAEAAugYAAAAPBbg8AAAAMf8PBVg4Nk9LCg=="
)
#: What the payload prints when it executes. It must appear on exactly one of the two hosts.
_X86_MARKER = "X86OK"
#: ELF `e_machine` for x86-64 (`EM_X86_64`), from the ELF ABI.
_EM_X86_64 = "62"
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


def _usable_az(ec2, instance_types):
    """An 'available' AZ that offers every type in instance_types.

    Offerings do not report zone state and AZ listings say nothing about instance types, and AZ
    names are per-account aliases, so both are queried rather than hardcoding a zone.
    """
    offered = None
    for want in instance_types:
        here = {o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want]}],
        )["InstanceTypeOfferings"]}
        offered = here if offered is None else (offered & here)
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers all of {list(instance_types)!r}; the intersection "
        f"of the offerings was {sorted(offered or [])!r} and the available zones were "
        f"{sorted(available)!r}"
    )
    return usable[0]


def _network(ctx, scenario, instance_types):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Built rather than borrowed because an account may have no default VPC; every resource is
    tagged in the call that creates it.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2, instance_types)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.180.0.0/16",
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
        VpcId=vpc_id, CidrBlock="10.180.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-arm64p-"), VpcId=vpc_id,
        Description="sim2real arm64 cross-family payload egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """One instance profile whose role can register with SSM, shared by both hosts."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-arm64p-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real arm64 cross-family managed instance role",
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


def _run_when_profile_ready(ec2, kwargs, attempts=40, delay=5.0):
    """RunInstances, retrying ONLY while IAM has not yet propagated the new instance profile.

    A blanket InvalidParameterValue retry would also swallow the architecture-mismatch refusal.
    """
    last = None
    for attempt in range(attempts):
        try:
            return ec2.run_instances(**kwargs)
        except ClientError as exc:
            last = exc
            message = exc.response.get("Error", {}).get("Message", "")
            profile_not_ready = (_code(exc) == "InvalidParameterValue"
                                 and "iamInstanceProfile" in message)
            if (_code(exc) in _THROTTLE or profile_not_ready) and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise
    raise last


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


def _wait_online(ctx, instance_ids, timeout_s=600):
    """Wait for the SSM agent on every host to report Online, polling all hosts together."""
    ssm = ctx.client("ssm")

    def _view():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in instance_ids:
                    seen[info["InstanceId"]] = info
        return seen

    return _poll(_view,
                 lambda s: all(s.get(i, {}).get("PingStatus") == "Online" for i in instance_ids),
                 timeout_s=timeout_s, interval_s=10.0,
                 what=f"the SSM agents on {sorted(instance_ids)!r} coming Online")


def _marker(stdout, marker):
    """The text after `marker` on the last line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One x86-64 ELF payload sent in one Run Command document runs (exit 0, marker) on a t3.micro
    and is refused (exit 126, 'Exec format error') on a t4g.micro in the same subnet, with both
    guests reporting the same payload sha256, so the difference is the CPU alone.
    """
    scenario = "arm64-cross-family-payload"
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    payload = base64.b64decode(_X86_64_ELF_B64)
    expected_sha = hashlib.sha256(payload).hexdigest()

    amis = {}
    for arch, param in (("arm64", _ARM64_AMI_PARAM), ("x86_64", _X86_AMI_PARAM)):
        ami = ssm.get_parameter(Name=param)["Parameter"]["Value"]
        assert ami.startswith("ami-"), f"{param} did not resolve to an AMI: {ami!r}"
        amis[arch] = ami
    described = {i["ImageId"]: i["Architecture"]
                 for i in ec2.describe_images(ImageIds=sorted(amis.values()))["Images"]}
    for arch, ami in amis.items():
        assert described.get(ami) == arch, (
            f"the {arch} Amazon Linux parameter resolved to {ami!r}, which DescribeImages calls "
            f"{described.get(ami)!r} — the comparison below would not be across architectures"
        )

    subnet_id, sg_id, az = _network(ctx, scenario, (_ARM64_TYPE, _X86_TYPE))
    profile_name = _instance_profile(ctx, scenario)

    launched: list[str] = []

    def _reap_all():
        """Terminate both hosts, issuing every terminate before waiting on any."""
        ids = list(launched)
        if not ids:
            return
        try:
            _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=ids))
        except ClientError as exc:
            if _code(exc) != "InvalidInstanceID.NotFound":
                raise
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if all(_instance_state(ec2, i) in ("terminated", "__gone__") for i in ids):
                return
            time.sleep(5)

    # Registered before the first launch so a host that never comes up cannot strand an instance.
    ctx.on_cleanup(_reap_all)

    hosts = {}
    for arch, instance_type in (("arm64", _ARM64_TYPE), ("x86_64", _X86_TYPE)):
        # A brand-new instance profile is not immediately resolvable by RunInstances.
        resv = _run_when_profile_ready(ec2, {
            "ImageId": amis[arch], "InstanceType": instance_type,
            "MinCount": 1, "MaxCount": 1,
            "SubnetId": subnet_id, "SecurityGroupIds": [sg_id],
            "IamInstanceProfile": {"Name": profile_name},
            "TagSpecifications": [{"ResourceType": rt,
                                   "Tags": [{"Key": "sim2real", "Value": scenario}]}
                                  for rt in ("instance", "volume")],
        })
        inst = resv["Instances"][0]
        launched.append(inst["InstanceId"])
        hosts[arch] = inst["InstanceId"]
        assert inst["Placement"]["AvailabilityZone"] == az, (
            f"the {arch} host landed in {inst['Placement']!r}, not the AZ {az!r} the shared subnet "
            f"pinned — the two hosts must differ only in processor"
        )
        assert inst["InstanceType"] == instance_type, inst

    for arch, instance_id in hosts.items():
        _poll(lambda i=instance_id: _instance_state(ec2, i), lambda s: s == "running",
              timeout_s=600, interval_s=5.0,
              what=f"the {arch} host {instance_id} reaching 'running'")
    _wait_online(ctx, set(hosts.values()))

    commands = [
        "set -uo pipefail",
        "D=$(mktemp -d /tmp/sim2real-arm64.XXXXXX)",
        'cd "$D"',
        f"printf '%s' '{_X86_64_ELF_B64}' | base64 -d > x86only",
        "chmod 755 x86only",
        'echo "GUEST-ARCH $(uname -m)"',
        'echo "GUEST-SHA $(sha256sum x86only | cut -d\' \' -f1)"',
        # e_machine (offset 18 of the ELF header) is the field the kernel dispatches on.
        'echo "GUEST-EMACHINE $(od -An -tu2 -j18 -N2 x86only | tr -d \' \')"',
        "OUT=$(./x86only 2>err) ; RC=$?",
        'echo "GUEST-RC $RC"',
        'echo "GUEST-STDOUT [$OUT]"',
        "echo \"GUEST-STDERR [$(tr '\\n' ' ' < err | sed 's/ *$//')]\"",
        'cd / && rm -rf "$D"',
    ]
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=sorted(hosts.values()), DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=300,
        Comment="sim2real arm64 cross-family payload"))
    command_id = sent["Command"]["CommandId"]

    outputs = {}
    for arch, instance_id in hosts.items():
        def _inv(i=instance_id):
            try:
                return ssm.get_command_invocation(CommandId=command_id, InstanceId=i)
            except ClientError as exc:
                if _code(exc) == "InvocationDoesNotExist":
                    return None
                raise

        inv = _poll(_inv, lambda v: v is not None and v.get("Status") in _TERMINAL,
                    timeout_s=300, interval_s=5.0,
                    what=f"the {arch} invocation of {command_id} reaching a terminal status")
        assert inv["Status"] == "Success", (
            f"the script itself must complete on the {arch} host — the graded failure is the "
            f"payload's exit status, not the command's; got {inv['Status']!r}: "
            f"{inv.get('StatusDetails')!r} stdout={inv.get('StandardOutputContent')!r} "
            f"stderr={inv.get('StandardErrorContent')!r}"
        )
        outputs[arch] = inv["StandardOutputContent"]

    for arch, out in outputs.items():
        assert _marker(out, "GUEST-SHA") == expected_sha, (
            f"the {arch} host must have reconstructed the exact payload (sha256 {expected_sha}); "
            f"it computed {_marker(out, 'GUEST-SHA')!r} — a mangled transfer, not an architecture "
            f"result. Full stdout: {out!r}"
        )
        assert _marker(out, "GUEST-EMACHINE") == _EM_X86_64, (
            f"the payload must declare EM_X86_64 ({_EM_X86_64}) on the {arch} host too; it read "
            f"e_machine={_marker(out, 'GUEST-EMACHINE')!r}"
        )

    x86_out = outputs["x86_64"]
    assert _marker(x86_out, "GUEST-ARCH") == "x86_64", (
        f"the {_X86_TYPE} host must report machine 'x86_64'; it reported "
        f"{_marker(x86_out, 'GUEST-ARCH')!r}"
    )
    assert _marker(x86_out, "GUEST-RC") == "0", (
        f"the payload must execute cleanly on x86-64; the {_X86_TYPE} host's shell reported exit "
        f"{_marker(x86_out, 'GUEST-RC')!r} with stderr {_marker(x86_out, 'GUEST-STDERR')!r}"
    )
    assert _marker(x86_out, "GUEST-STDOUT") == f"[{_X86_MARKER}]", (
        f"the payload prints {_X86_MARKER!r} when it runs; the {_X86_TYPE} host captured "
        f"{_marker(x86_out, 'GUEST-STDOUT')!r}"
    )
    assert _marker(x86_out, "GUEST-STDERR") == "[]", (
        f"a clean execution writes nothing to stderr; the {_X86_TYPE} host captured "
        f"{_marker(x86_out, 'GUEST-STDERR')!r}"
    )

    arm_out = outputs["arm64"]
    assert _marker(arm_out, "GUEST-ARCH") == "aarch64", (
        f"the {_ARM64_TYPE} host must report machine 'aarch64'; it reported "
        f"{_marker(arm_out, 'GUEST-ARCH')!r} — it is not running on Graviton"
    )
    assert _marker(arm_out, "GUEST-RC") == _EXIT_CANNOT_EXEC, (
        f"the same payload must be refused on AArch64 with exit {_EXIT_CANNOT_EXEC}; the "
        f"{_ARM64_TYPE} host's shell reported {_marker(arm_out, 'GUEST-RC')!r}. Full stdout: "
        f"{arm_out!r}"
    )
    arm_stderr = _marker(arm_out, "GUEST-STDERR")
    assert arm_stderr is not None and arm_stderr.endswith("Exec format error]"), (
        f"the AArch64 kernel must refuse the exec with 'Exec format error'; the {_ARM64_TYPE} "
        f"host's shell said {arm_stderr!r}"
    )
    assert _marker(arm_out, "GUEST-STDOUT") == "[]", (
        f"the effect must be ABSENT on AArch64: the payload's stdout must be empty; the "
        f"{_ARM64_TYPE} host captured {_marker(arm_out, 'GUEST-STDOUT')!r}"
    )
    assert _X86_MARKER not in arm_out, (
        f"{_X86_MARKER!r} appeared in the {_ARM64_TYPE} host's output, which means x86-64 machine "
        f"code executed on a host that reports itself as AArch64: {arm_out!r}"
    )

    ran = sorted(arch for arch, out in outputs.items() if _X86_MARKER in out)
    assert ran == ["x86_64"], (
        f"exactly one of the two hosts may execute an x86-64 binary, and it must be the x86_64 "
        f"one; the marker appeared on {ran!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
