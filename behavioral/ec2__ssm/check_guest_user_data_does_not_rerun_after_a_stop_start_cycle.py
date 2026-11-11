"""guest-user-data-does-not-rerun-after-a-stop-start-cycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guest-user-data-does-not-rerun-after-a-stop-start-cycle"
GROUP = 'guest-execution'
SERVICES = ['ec2', 'ssm']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_GUEST_DIR = "/var/lib/sim2real-guest"
_RUNS_FILE = f"{_GUEST_DIR}/userdata-runs"


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

    Built rather than borrowed: a fresh account may have no default VPC, and every resource is
    tagged in the same call that creates it, because an untagged EC2 resource is invisible to a
    tag search forever.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.173.0.0/16",
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
        VpcId=vpc_id, CidrBlock="10.173.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-guest-"), VpcId=vpc_id,
        Description="sim2real guest-execution egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return vpc_id, subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-guest-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real guest-execution managed instance role",
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
    """Terminate and wait for 'terminated' — the subnet, group and VPC deletions depend on it."""
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


def _launch(ctx, *, profile_name, subnet_id, sg_id, user_data, scenario, metadata_options=None):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    kw = {}
    if metadata_options is not None:
        kw["MetadataOptions"] = metadata_options
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            UserData=user_data,
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
            **kw,
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


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=420):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=600,
        Comment="sim2real guest-execution user-data rerun probe"),
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


def _observe_guest(ctx, instance_id, *, what):
    """Read the run ledger the user-data script appends to, plus the CURRENT boot id.

    The boot id is the positive control for the stop/start: the kernel mints a fresh one every
    boot, so a changed boot id proves the machine really came up again rather than never having
    gone down.
    """
    # Every read is guarded so that "the script has not run yet" reports GUEST-RUNS 0 rather than
    # failing the command: an absent ledger is a state to poll through, not an error.
    inv = _run_shell(ctx, instance_id, [
        "set -uo pipefail",
        f"F={_RUNS_FILE}",
        'if [ -f "$F" ]; then',
        '  echo "GUEST-RUNS $(wc -l < "$F" | tr -d \' \')"',
        '  echo "GUEST-FIRST-RUN $(head -n 1 "$F")"',
        '  echo "GUEST-LAST-RUN $(tail -n 1 "$F")"',
        'else',
        '  echo "GUEST-RUNS 0"',
        'fi',
        'echo "GUEST-BOOT-ID $(cat /proc/sys/kernel/random/boot_id)"',
        'echo "GUEST-CLOUD-INIT $(cloud-init status || true)"',
    ], what=what)
    assert inv["Status"] == "Success", (
        f"{what}: the read-back command was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: ResponseCode was {inv['ResponseCode']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]
    runs = _marker(out, "GUEST-RUNS")
    assert runs is not None and runs.isdigit(), (
        f"{what}: the guest did not report a line count for {_RUNS_FILE}; output was {out!r}"
    )
    return {
        "runs": int(runs),
        "first": _marker(out, "GUEST-FIRST-RUN"),
        "last": _marker(out, "GUEST-LAST-RUN"),
        "boot_id": _marker(out, "GUEST-BOOT-ID"),
        "cloud_init": _marker(out, "GUEST-CLOUD-INIT"),
        "stdout": out,
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """EC2 runs user data on the FIRST boot only: after a stop/start (proved by a new boot id)
    the guest's run ledger still holds the single first-boot line and cloud-init reports done.
    """
    scenario = "guest-user-data-rerun"
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    # Appends, never overwrites: if EC2 ran this a second time the file would carry two lines.
    user_data = (
        "#!/bin/bash\n"
        f"mkdir -p {_GUEST_DIR}\n"
        f"cat /proc/sys/kernel/random/boot_id >> {_RUNS_FILE}\n"
    )
    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, user_data=user_data)
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)

    # --- first boot: the script ran exactly once, on THIS boot -------------------
    first = _poll(lambda: _observe_guest(ctx, instance_id, what="reading the ledger on first boot"),
                  lambda o: o["runs"] >= 1, timeout_s=420, interval_s=20.0,
                  what=f"the user-data script on {instance_id} writing its first ledger line")
    assert first["runs"] == 1, (
        f"the user-data script must have run exactly once on the first boot, the ledger holds "
        f"{first['runs']} lines: {first['stdout']!r}"
    )
    first_boot_id = first["first"]
    assert first_boot_id and first_boot_id == first["boot_id"], (
        f"the ledger line must carry the boot id of the boot that wrote it; the ledger says "
        f"{first_boot_id!r} and the running kernel says {first['boot_id']!r}"
    )
    assert "status: done" in (first["cloud_init"] or ""), (
        f"cloud-init must have finished before the rule is meaningful, it reported "
        f"{first['cloud_init']!r}"
    )

    # --- the cycle: a full stop, then a start -----------------------------------
    _call_with_retry(lambda: ec2.stop_instances(InstanceIds=[instance_id]))
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "stopped",
          timeout_s=600, interval_s=10.0, what=f"instance {instance_id} reaching 'stopped'")
    _call_with_retry(lambda: ec2.start_instances(InstanceIds=[instance_id]),
                     codes=_THROTTLE + ("IncorrectInstanceState",), retries=40, delay=10.0)
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=10.0,
          what=f"instance {instance_id} returning to 'running' after the restart")
    # PingStatus can still read Online from before the stop, so the boot id proves the cycle.
    _wait_online(ctx, instance_id)

    # --- second boot: a new kernel, and still one run ---------------------------
    second = _observe_guest(ctx, instance_id, what="reading the ledger after the stop/start cycle")
    assert second["boot_id"] and second["boot_id"] != first_boot_id, (
        f"the restart must have produced a new kernel boot id — otherwise this check proves "
        f"nothing about a second boot. Before: {first_boot_id!r}, after: {second['boot_id']!r}"
    )
    assert second["runs"] == 1, (
        f"user data must NOT re-run on a later boot: after the stop/start the ledger holds "
        f"{second['runs']} lines instead of 1: {second['stdout']!r}"
    )
    assert second["last"] == first_boot_id, (
        f"the single ledger line must still be the one the FIRST boot wrote ({first_boot_id!r}); "
        f"the guest now reports {second['last']!r}, so something rewrote it"
    )
    assert "status: done" in (second["cloud_init"] or ""), (
        f"cloud-init must have completed on the second boot too — the rule under test is that it "
        f"ran and declined to repeat the once-per-instance module, not that it never ran. It "
        f"reported {second['cloud_init']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
