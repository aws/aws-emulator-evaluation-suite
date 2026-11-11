"""capres-cancel-with-a-running-instance-releases-it-without-stopping-the-guest."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capres-cancel-with-a-running-instance-releases-it-without-stopping-the-guest"
GROUP = 'capacity-reservation-consumption'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_PLATFORM = "Linux/UNIX"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_IMDS = "http://169.254.169.254/latest"
_MICRO_VCPUS = 2
# How long the released state must HOLD. A cancel that frees the seat and then quietly reclaims it
# is a different service from one that frees it, so the release is re-read until this window ends.
_HOLD_S = 45


# ===== helpers =====
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


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency",
                                             "DeleteConflict"), attempts=40, delay=5.0):
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


def _usable_azs(ec2, *instance_types):
    """AZs that are BOTH 'available' and offer every one of instance_types."""
    offered = None
    for want in instance_types:
        here = {o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
        offered = here if offered is None else (offered & here)
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in this region offers all of {instance_types!r}; the offerings were "
        f"{sorted(offered)!r}"
    )
    return usable


def _network(ctx, scenario, az, cidr16):
    """A dedicated VPC with one public subnet in `az` and an egress-only security group."""
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]

    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr16}/16",
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
        VpcId=vpc_id, CidrBlock=f"{cidr16.rsplit('.', 2)[0]}.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-capres-"), VpcId=vpc_id,
        Description="sim2real capacity-reservation guest egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-capres-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real capacity-reservation managed instance role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_role():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
        except ClientError as exc:
            if _code(exc) != "NoSuchEntity":
                raise
        _delete_with_retry(lambda: iam.delete_role(RoleName=name), gone=("NoSuchEntity",))

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)

    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": scenario}])

    def _drop_profile():
        _delete_with_retry(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=name, RoleName=name), gone=("NoSuchEntity",))
        _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=name),
                           gone=("NoSuchEntity",))

    ctx.on_cleanup(_drop_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return name


def _instance_view(ec2, instance_id):
    """This instance's DescribeInstances record, or None while the id is not resolvable yet."""
    try:
        pages = ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}])
        for page in pages:
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    if inst["InstanceId"] == instance_id:
                        return inst
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    return None


def _instance_state(ec2, instance_id):
    inst = _instance_view(ec2, instance_id)
    return None if inst is None else inst["State"]["Name"]


def _instances_holding(ec2, cr_id):
    """Every instance the SERVER says occupies this reservation, via its own filter."""
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "capacity-reservation-id", "Values": [cr_id]}]):
        for resv in page["Reservations"]:
            found += [i["InstanceId"] for i in resv["Instances"]
                      if i["State"]["Name"] not in ("terminated", "shutting-down")]
    return sorted(found)


def _cr_view(ec2, cr_id):
    return ec2.describe_capacity_reservations(
        CapacityReservationIds=[cr_id])["CapacityReservations"][0]


def _make_cr(ctx, scenario, *, instance_type, criteria, az, count=1):
    """An active On-Demand Capacity Reservation, cancelled on cleanup."""
    ec2 = ctx.client("ec2")
    cr = ec2.create_capacity_reservation(
        InstanceType=instance_type, InstancePlatform=_PLATFORM, AvailabilityZone=az,
        InstanceCount=count, InstanceMatchCriteria=criteria,
        TagSpecifications=[{"ResourceType": "capacity-reservation",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["CapacityReservation"]
    cr_id = cr["CapacityReservationId"]
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id),
        gone=("InvalidCapacityReservationId.NotFound",)))
    _poll(lambda: _cr_view(ec2, cr_id)["State"], lambda s: s == "active", 180, 3.0,
          what=f"capacity reservation {cr_id} reaching 'active'")
    return cr


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
        if _instance_state(ec2, instance_id) in ("terminated", None):
            return
        time.sleep(5)


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    return ami


def _launch(ctx, *, instance_type, subnet_id, sg_id, scenario, profile_name=None, cr_spec=None,
            warm_profile=True):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    kw = {}
    if profile_name is not None:
        kw["IamInstanceProfile"] = {"Name": profile_name}
    if cr_spec is not None:
        kw["CapacityReservationSpecification"] = cr_spec
    codes = _THROTTLE + (("InvalidParameterValue",) if warm_profile else ())
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=_ami(ctx), InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            TagSpecifications=[{"ResourceType": rt,
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}
                               for rt in ("instance", "volume")],
            **kw),
        codes=codes, retries=40, delay=5.0)
    return resv["Instances"][0]


def _refused_launch(ctx, *, scenario, instance_type, subnet_id, sg_id, cr_spec):
    """Attempt a launch that must be refused and return the error code.

    No instance profile and no retry: the refusal must be the FIRST answer, and the retry that
    makes a fresh instance profile resolvable also retries InvalidParameterValue. An accepted
    launch is registered for termination before it is reported.
    """
    try:
        inst = _launch(ctx, instance_type=instance_type, subnet_id=subnet_id, sg_id=sg_id,
                       scenario=scenario, profile_name=None, cr_spec=cr_spec,
                       warm_profile=False)
    except ClientError as exc:
        return _code(exc)
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx.client("ec2"), inst["InstanceId"]))
    return f"ACCEPTED:{inst['InstanceId']}"


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
        Comment="sim2real capacity-reservation guest probe"))
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


def _guest_facts_script():
    """A guest script reporting the machine's own identity, hardware and boot.

    boot_id is generated by the running kernel at boot and never changes while it runs, so it is
    the one value that distinguishes 'the same machine, still up' from 'something rebooted or was
    replaced underneath the same instance id'.
    """
    return [
        "set -uo pipefail",
        f"T=$(curl -s -m 5 -X PUT {_IMDS}/api/token"
        " -H 'X-aws-ec2-metadata-token-ttl-seconds: 120')",
        'H="X-aws-ec2-metadata-token: $T"',
        f'echo "GUEST-IID $(curl -s -m 5 -H "$H" {_IMDS}/meta-data/instance-id)"',
        f'echo "GUEST-TYPE $(curl -s -m 5 -H "$H" {_IMDS}/meta-data/instance-type)"',
        f'echo "GUEST-AZ $(curl -s -m 5 -H "$H" {_IMDS}/meta-data/placement/availability-zone)"',
        'echo "GUEST-CPUS $(nproc)"',
        "echo \"GUEST-MEMKB $(awk '/MemTotal/{print $2}' /proc/meminfo)\"",
        'echo "GUEST-BOOTID $(cat /proc/sys/kernel/random/boot_id)"',
        'echo "GUEST-UPTIME $(cut -d. -f1 /proc/uptime)"',
    ]


def _marker(stdout, marker):
    """The text after `marker` on the LAST line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


def _guest_facts(ctx, instance_id, *, what):
    """Run the probe in the guest and return its parsed markers, asserting the run itself."""
    inv = _run_shell(ctx, instance_id, _guest_facts_script(), what=what)
    assert inv["Status"] == "Success", (
        f"{what}: the invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: ResponseCode was {inv['ResponseCode']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]
    return {k: _marker(out, "GUEST-" + k) for k in
            ("IID", "TYPE", "AZ", "CPUS", "MEMKB", "BOOTID", "UPTIME")}, out


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """Cancelling a reservation a running instance occupies is accepted: the seat is released and
    stays released, while the guest keeps the same boot_id with advancing uptime (no stop/replace)."""
    scenario = "capres-cancel-while-running"
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]

    az = _usable_azs(ec2, _INSTANCE_TYPE)[0]
    subnet_id, sg_id = _network(ctx, scenario, az, "10.183.0.0")
    profile_name = _instance_profile(ctx, scenario)

    cr_id = _make_cr(ctx, scenario, instance_type=_INSTANCE_TYPE, criteria="targeted",
                     az=az)["CapacityReservationId"]
    inst = _launch(ctx, instance_type=_INSTANCE_TYPE, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, profile_name=profile_name,
                   cr_spec={"CapacityReservationTarget": {"CapacityReservationId": cr_id}})
    instance_id = inst["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # --- the reservation really is occupied before it is cancelled -----------
    occupied = _poll(lambda: _cr_view(ec2, cr_id), lambda v: v["AvailableInstanceCount"] == 0,
                     timeout_s=300, interval_s=5.0,
                     what=f"reservation {cr_id} reporting its seat as taken")
    total = occupied["TotalInstanceCount"]
    assert occupied.get("CapacityAllocations") == [{"AllocationType": "used", "Count": 1}], (
        f"the reservation must hold one used seat before the cancel, got "
        f"{occupied.get('CapacityAllocations')!r}"
    )
    before_usage = ec2.get_capacity_reservation_usage(CapacityReservationId=cr_id)
    assert before_usage["InstanceUsages"] == [{"AccountId": account, "UsedInstanceCount": 1}], (
        f"before the cancel the seat must be attributed to {account!r}, got "
        f"{before_usage['InstanceUsages']!r}"
    )
    assert _instances_holding(ec2, cr_id) == [instance_id], (
        f"before the cancel the reservation must hold {instance_id!r}, EC2's filter returned "
        f"{_instances_holding(ec2, cr_id)!r}"
    )

    _wait_online(ctx, instance_id)
    before, before_out = _guest_facts(ctx, instance_id, what="the guest before the cancel")
    assert before["IID"] == instance_id, (
        f"the guest must report its own instance id {instance_id!r}; it printed {before['IID']!r}. "
        f"Full probe output: {before_out!r}"
    )
    assert before["TYPE"] == _INSTANCE_TYPE, (
        f"the reserved seat is for {_INSTANCE_TYPE!r}; the guest printed {before['TYPE']!r}. Full "
        f"probe output: {before_out!r}"
    )
    assert before["AZ"] == az, (
        f"the reservation is pinned to {az!r}; the guest printed {before['AZ']!r}. Full probe "
        f"output: {before_out!r}"
    )
    assert int(before["CPUS"]) == _MICRO_VCPUS, (
        f"a {_INSTANCE_TYPE} has {_MICRO_VCPUS} vCPUs; nproc printed {before['CPUS']!r}. Full "
        f"probe output: {before_out!r}"
    )
    assert before["BOOTID"], (
        f"the guest must report the running kernel's boot id. Full probe output: {before_out!r}"
    )

    # --- cancel while it is occupied: accepted, not refused ------------------
    cancelled_at = time.monotonic()
    result = _call_with_retry(
        lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))
    assert result["Return"] is True, (
        "cancelling a reservation with a running instance in it must be accepted, not refused; "
        f"CancelCapacityReservation returned {result.get('Return')!r}"
    )

    released = _poll(lambda: _cr_view(ec2, cr_id), lambda v: v["State"] == "cancelled",
                     timeout_s=300, interval_s=5.0,
                     what=f"reservation {cr_id} reaching 'cancelled'")
    assert released["AvailableInstanceCount"] == total, (
        f"a cancelled reservation must release every seat it held: AvailableInstanceCount must be "
        f"back to TotalInstanceCount {total!r}, got {released['AvailableInstanceCount']!r}"
    )
    assert released.get("CapacityAllocations") in ([], None), (
        f"a cancelled reservation must allocate nothing, got "
        f"{released.get('CapacityAllocations')!r}"
    )
    after_usage = ec2.get_capacity_reservation_usage(CapacityReservationId=cr_id)
    assert after_usage["InstanceUsages"] == [], (
        f"a cancelled reservation must attribute no usage to anyone, got "
        f"{after_usage['InstanceUsages']!r}"
    )
    assert after_usage["State"] == "cancelled", f"usage after the cancel: {after_usage!r}"

    # --- the instance kept running and is not attributed to it --------------
    detached = _poll(lambda: _instance_view(ec2, instance_id),
                     lambda i: i is not None and "CapacityReservationId" not in i,
                     timeout_s=300, interval_s=5.0,
                     what=f"instance {instance_id} losing its reservation attribution")
    assert detached["State"]["Name"] == "running", (
        "cancelling the reservation must not disturb the instance occupying it; the instance is "
        f"{detached['State']!r}"
    )
    spec = detached.get("CapacityReservationSpecification", {})
    assert spec.get("CapacityReservationTarget", {}).get("CapacityReservationId") == cr_id, (
        "the instance's own specification must still name the target it was launched with even "
        f"though the reservation is gone, got {spec!r}"
    )
    assert _instances_holding(ec2, cr_id) == [], (
        f"a cancelled reservation must hold no instances, EC2's filter returned "
        f"{_instances_holding(ec2, cr_id)!r}"
    )

    # --- a launch into the cancelled reservation is refused -----------------
    refused = _refused_launch(ctx, scenario=scenario, instance_type=_INSTANCE_TYPE,
                              subnet_id=subnet_id, sg_id=sg_id,
                              cr_spec={"CapacityReservationTarget":
                                       {"CapacityReservationId": cr_id}})
    assert refused == "InvalidParameterValue", (
        "a cancelled reservation must not accept new launches; RunInstances answered "
        f"{refused!r}"
    )

    # --- a second cancel of the same reservation is accepted ----------------
    again = _call_with_retry(
        lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))
    assert again["Return"] is True, (
        f"cancelling an already-cancelled reservation must be accepted, got {again.get('Return')!r}"
    )

    # --- the machine kept running, and the release still holds after that --
    after, after_out = _guest_facts(ctx, instance_id, what="the guest after the cancel")
    # Re-read the release until _HOLD_S after the cancel, so a seat reclaimed meanwhile shows here.
    while True:
        held = _cr_view(ec2, cr_id)
        assert (held["State"], held["AvailableInstanceCount"]) == ("cancelled", total), (
            f"within {_HOLD_S}s after the cancel the reservation must stay cancelled with all "
            f"{total!r} seats free, got {(held['State'], held['AvailableInstanceCount'])!r}"
        )
        assert held.get("CapacityAllocations") in ([], None), (
            f"within {_HOLD_S}s after the cancel the reservation must still allocate nothing, got "
            f"{held.get('CapacityAllocations')!r}"
        )
        if time.monotonic() - cancelled_at >= _HOLD_S:
            break
        time.sleep(2)
    assert after["BOOTID"] == before["BOOTID"], (
        "the instance must be the SAME booted machine across the cancel: its kernel's boot id "
        f"was {before['BOOTID']!r} before and is {after['BOOTID']!r} after, which means it "
        f"rebooted or was replaced. Full probe output: {after_out!r}"
    )
    assert int(after["UPTIME"]) > int(before["UPTIME"]), (
        f"the same machine must have kept running across the cancel, so its uptime must have "
        f"advanced past {before['UPTIME']!r}; it reported {after['UPTIME']!r}. Full probe output: "
        f"{after_out!r}"
    )
    assert after["IID"] == instance_id, (
        f"the guest must still be {instance_id!r}; it printed {after['IID']!r}. Full probe "
        f"output: {after_out!r}"
    )
    assert after["TYPE"] == _INSTANCE_TYPE, (
        f"a reservation released underneath a running instance must not change its hardware; the "
        f"guest printed {after['TYPE']!r}. Full probe output: {after_out!r}"
    )
    assert after["AZ"] == az, (
        f"the instance must still be in {az!r}; the guest printed {after['AZ']!r}. Full probe "
        f"output: {after_out!r}"
    )
    assert after["MEMKB"] == before["MEMKB"], (
        f"the machine's memory must be unchanged across the cancel: {before['MEMKB']!r} before, "
        f"{after['MEMKB']!r} after. Full probe output: {after_out!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
