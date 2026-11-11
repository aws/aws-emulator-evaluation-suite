"""shutdown-in-guest-halt-with-stop-behavior-leaves-it-stopped-and-restartable."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shutdown-in-guest-halt-with-stop-behavior-leaves-it-stopped-and-restartable"
GROUP = 'guest-shutdown-semantics'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_GUEST_DIR = "/var/lib/sim2real-guest"
_SENTINEL = f"{_GUEST_DIR}/root-sentinel"
#: Seconds the guest waits before halting, so the SSM invocation reports Success before the
#: agent dies with the machine.
_HALT_DELAY_S = 15

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
                       attempts=12, delay=5.0):
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


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type — neither call answers both."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one public subnet and an egress-only security group.

    Cleanups are registered outermost-first so LIFO teardown follows the dependency order.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.191.0.0/16",
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

    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"),
        gone=("InvalidRoute.NotFound", "InvalidRouteTableID.NotFound")))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.191.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-shutdown-"), VpcId=vpc_id,
        Description="sim2real guest shutdown semantics, egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-shutdown-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real guest shutdown managed instance role",
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


def _describe(ec2, instance_id):
    """The instance record, or None once EC2 has forgotten it entirely."""
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _instance_state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated'; the subnet, group and VPC deletions depend on it.
    Clears DisableApiTermination first so the terminate cannot be refused."""
    try:
        _call_with_retry(lambda: ec2.modify_instance_attribute(
            InstanceId=instance_id, DisableApiTermination={"Value": False}))
    except ClientError as exc:
        if _code(exc) not in ("InvalidInstanceID.NotFound", "IncorrectInstanceState"):
            raise
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


def _launch(ctx, *, profile_name, subnet_id, sg_id, scenario, shutdown_behavior):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            InstanceInitiatedShutdownBehavior=shutdown_behavior,
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=40, delay=5.0)
    return resv["Instances"][0]


def _wait_online(ctx, instance_id, timeout_s=600):
    """Wait for the SSM agent on this host to report Online; raises on timeout."""
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


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=420):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=600,
        Comment="sim2real guest shutdown semantics"),
        codes=_THROTTLE + ("InvalidInstanceId",), retries=60, delay=10.0)
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
    """The text after `marker` on the LAST line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _guest(ctx, instance_id, commands, *, what):
    """Run commands in the guest, insist they succeeded, and return the stdout it printed."""
    inv = _run_shell(ctx, instance_id, commands, what=what)
    assert inv["Status"] == "Success", (
        f"{what}: the in-guest command was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: ResponseCode was {inv['ResponseCode']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _observe_guest(ctx, instance_id, *, what):
    """Read the sentinel, the kernel boot id and the IMDSv2 instance id from inside the guest.
    The IMDS instance id binds the output to the instance under test."""
    out = _guest(ctx, instance_id, [
        "set -uo pipefail",
        'echo "GUEST-BOOT-ID $(cat /proc/sys/kernel/random/boot_id)"',
        'echo "GUEST-UPTIME $(cut -d\' \' -f1 /proc/uptime)"',
        f'if [ -f {_SENTINEL} ]; then echo "GUEST-SENTINEL $(cat {_SENTINEL})"; '
        'else echo "GUEST-SENTINEL __absent__"; fi',
        'T=$(curl -sS -X PUT http://169.254.169.254/latest/api/token '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 60")',
        'echo "GUEST-IMDS-IID $(curl -sS -H "X-aws-ec2-metadata-token: $T" '
        'http://169.254.169.254/latest/meta-data/instance-id)"',
    ], what=what)
    boot_id = _marker(out, "GUEST-BOOT-ID")
    assert boot_id, f"{what}: the guest printed no boot id; output was {out!r}"
    return {
        "boot_id": boot_id,
        "uptime": _marker(out, "GUEST-UPTIME"),
        "sentinel": _marker(out, "GUEST-SENTINEL"),
        "imds_iid": _marker(out, "GUEST-IMDS-IID"),
        "stdout": out,
    }


def _wait_stopped_without_terminating(ec2, instance_id, timeout_s=600):
    """Poll to 'stopped', failing the moment a terminate transition is observed instead."""
    seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        state = _instance_state(ec2, instance_id)
        if not seen or seen[-1] != state:
            seen.append(state)
        assert state not in ("shutting-down", "terminated", "__gone__"), (
            f"the in-guest halt must STOP this instance, not terminate it: EC2 reported "
            f"{state!r} (states observed in order: {seen!r})"
        )
        if state == "stopped":
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"instance {instance_id} did not reach 'stopped' within {timeout_s}s after the "
                f"in-guest halt (states observed in order: {seen!r})"
            )
        time.sleep(5)


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """With InstanceInitiatedShutdownBehavior=stop, an in-guest `shutdown -h now` stops (never
    terminates) the instance with StateReason Client.InstanceInitiatedShutdown; it restarts on a
    new boot id with the same root volume and the sentinel written before the halt."""
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ChangingInstanceInitiatedShutdownBehavior.html
    scenario = "shutdown-stop-behavior"
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, shutdown_behavior="stop")
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    attr = ec2.describe_instance_attribute(
        InstanceId=instance_id, Attribute="instanceInitiatedShutdownBehavior")
    assert attr["InstanceInitiatedShutdownBehavior"]["Value"] == "stop", (
        f"RunInstances was asked for 'stop' and the attribute reads "
        f"{attr['InstanceInitiatedShutdownBehavior']!r}"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)

    root_device = _describe(ec2, instance_id)["RootDeviceName"]
    root_volume = next(
        b["Ebs"]["VolumeId"] for b in _describe(ec2, instance_id)["BlockDeviceMappings"]
        if b["DeviceName"] == root_device)

    nonce = uuid.uuid4().hex
    wrote = _guest(ctx, instance_id, [
        "set -euo pipefail",
        f"mkdir -p {_GUEST_DIR}",
        f"printf '%s' '{nonce}' > {_SENTINEL}",
        "sync",
        f'echo "GUEST-WROTE $(cat {_SENTINEL})"',
    ], what="writing the sentinel onto the root volume")
    assert _marker(wrote, "GUEST-WROTE") == nonce, (
        f"the guest did not read back the sentinel it just wrote: expected {nonce!r}, the guest "
        f"printed {_marker(wrote, 'GUEST-WROTE')!r} (stdout {wrote!r})"
    )

    before = _observe_guest(ctx, instance_id, what="reading the guest before the halt")
    assert before["sentinel"] == nonce, (
        f"the sentinel must be readable in-guest before the halt; the guest reports "
        f"{before['sentinel']!r}"
    )
    assert before["imds_iid"] == instance_id, (
        f"IMDS inside the guest must identify the instance under test: it served "
        f"{before['imds_iid']!r}, not {instance_id!r}"
    )

    issued = _guest(ctx, instance_id, [
        "set -uo pipefail",
        'echo "GUEST-HALT-BOOT-ID $(cat /proc/sys/kernel/random/boot_id)"',
        f"setsid sh -c 'sleep {_HALT_DELAY_S}; /sbin/shutdown -h now' "
        "</dev/null >/dev/null 2>&1 &",
        'echo "GUEST-HALT-ISSUED yes"',
    ], what="issuing shutdown -h now inside the guest")
    assert _marker(issued, "GUEST-HALT-ISSUED") == "yes", (
        f"the guest did not confirm it issued the halt; stdout was {issued!r}"
    )
    assert _marker(issued, "GUEST-HALT-BOOT-ID") == before["boot_id"], (
        f"the halt was issued on a different boot than the one that wrote the sentinel: "
        f"{_marker(issued, 'GUEST-HALT-BOOT-ID')!r} vs {before['boot_id']!r}"
    )

    _wait_stopped_without_terminating(ec2, instance_id)
    stopped = _describe(ec2, instance_id)
    assert stopped["StateReason"]["Code"] == "Client.InstanceInitiatedShutdown", (
        f"a halt issued inside the guest must be attributed to the instance, not to an API "
        f"caller: StateReason was {stopped['StateReason']!r}"
    )
    expected_reason = "Client.InstanceInitiatedShutdown: Instance initiated shutdown"
    assert stopped["StateReason"].get("Message") == expected_reason, (
        f"expected StateReason message {expected_reason!r}, got {stopped['StateReason']!r}"
    )

    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]),
                     codes=_THROTTLE + ("IncorrectInstanceState",), retries=40, delay=10.0)
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=10.0,
          what=f"instance {instance_id} returning to 'running' after the in-guest halt")
    _wait_online(ctx, instance_id)

    after = _observe_guest(ctx, instance_id, what="reading the guest after the restart")
    assert after["boot_id"] != before["boot_id"], (
        f"the restart must have produced a new kernel boot id — without that this check proves "
        f"nothing about a real power cycle. Before {before['boot_id']!r}, after "
        f"{after['boot_id']!r}"
    )
    assert after["sentinel"] == nonce, (
        f"the root volume must survive an in-guest halt with shutdown-behavior=stop: the guest "
        f"reports {after['sentinel']!r} instead of the sentinel {nonce!r} it wrote before halting"
    )
    assert after["imds_iid"] == instance_id, (
        f"the restarted guest must still be the instance under test; IMDS served "
        f"{after['imds_iid']!r}"
    )
    restarted_root = next(
        b["Ebs"]["VolumeId"] for b in _describe(ec2, instance_id)["BlockDeviceMappings"]
        if b["DeviceName"] == root_device)
    assert restarted_root == root_volume, (
        f"the restarted instance must carry the SAME root volume: {restarted_root!r} replaced "
        f"{root_volume!r}"
    )

    # Terminated here because cleanup is time-bounded and the network teardown needs 'terminated'.
    _terminate_and_wait(ec2, instance_id)
    assert _instance_state(ec2, instance_id) in ("terminated", "__gone__"), (
        f"the instance must be gone before the network teardown, it is "
        f"{_instance_state(ec2, instance_id)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
