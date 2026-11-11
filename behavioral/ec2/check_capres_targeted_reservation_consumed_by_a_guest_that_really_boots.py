"""capres-targeted-reservation-consumed-by-a-guest-that-really-boots."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capres-targeted-reservation-consumed-by-a-guest-that-really-boots"
GROUP = 'capacity-reservation-consumption'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_PLATFORM = "Linux/UNIX"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_IMDS = "http://169.254.169.254/latest"
# A t3.micro is 1 GiB / 2 vCPU. The guest's own /proc reports slightly less than the nominal
# gibibyte once the kernel's reserved pages are subtracted (about 935152 kB), so the window is
# wide enough to survive a kernel change and still far below the 2 GiB a t3.small would report.
_MICRO_MEM_KB = (800000, 1200000)
_MICRO_VCPUS = 2

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
    """AZs that are BOTH 'available' and offer every one of instance_types.

    Neither call answers both questions: describe_instance_type_offerings does not report zone
    state, and describe_availability_zones says nothing about instance types. An empty
    intersection means this region cannot run the check at all, which is a FAIL naming what it
    saw rather than an AZ to guess at.
    """
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
    """A dedicated VPC with one public subnet in `az` and an egress-only security group.

    Built rather than borrowed, as an account may have no default VPC. Every resource is tagged in the call that creates it, because an untagged
    EC2 resource cannot be found for cleanup.
    """
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
    """This instance's DescribeInstances record, or None while the id is not resolvable yet.

    Paginated and filtered, because other instances in the account can push this one off page one.
    RunInstances is eventually consistent (DescribeInstances can raise InvalidInstanceID.NotFound for
    an id RunInstances just returned), so 'not there yet' is a poll state, not an error.
    """
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
    """Every instance the SERVER says occupies this reservation, via its own filter.

    This is a join computed by EC2, not a field echoed back from RunInstances: the request never
    carried an instance id, and the answer is whatever the reservation currently holds.
    """
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


def _launch(ctx, *, instance_type, subnet_id, sg_id, scenario, profile_name=None, cr_spec=None,
            warm_profile=True):
    """RunInstances with the instance AND its root volume tagged at launch.

    `warm_profile` retries InvalidParameterValue, because a brand-new instance profile is not
    immediately resolvable by RunInstances. A launch that is EXPECTED to be refused must pass
    warm_profile=False and no profile at all, or the retry would swallow the refusal for 200 s and
    then report it as a timeout.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    kw = {}
    if profile_name is not None:
        kw["IamInstanceProfile"] = {"Name": profile_name}
    if cr_spec is not None:
        kw["CapacityReservationSpecification"] = cr_spec
    codes = _THROTTLE + (("InvalidParameterValue",) if warm_profile else ())
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            TagSpecifications=[{"ResourceType": rt,
                                "Tags": [{"Key": "sim2real", "Value": scenario}]}
                               for rt in ("instance", "volume")],
            **kw),
        codes=codes, retries=40, delay=5.0)
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
    """A guest script that reports what the MACHINE says about itself.

    Every line is read inside the instance: IMDS is link-local, so no caller outside the guest can
    reach 169.254.169.254 at all, and /proc is the kernel that is actually running on the
    hardware the reservation set aside.
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


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A launch with an explicit CapacityReservationTarget occupies the reservation (Available 0, one usage,
    the instance filter returns it) and the guest boots and reports its instance id, type, zone and t3.micro
    vCPU/memory from inside."""
    scenario = "capres-targeted-consumed"
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    az = _usable_azs(ec2, _INSTANCE_TYPE)[0]
    subnet_id, sg_id = _network(ctx, scenario, az, "10.180.0.0")
    profile_name = _instance_profile(ctx, scenario)

    cr = _make_cr(ctx, scenario, instance_type=_INSTANCE_TYPE, criteria="targeted", az=az)
    cr_id = cr["CapacityReservationId"]
    assert (cr["AvailableInstanceCount"], cr["TotalInstanceCount"]) == (1, 1), (
        f"a one-instance reservation must start with one seat free and one seat total, got "
        f"{(cr['AvailableInstanceCount'], cr['TotalInstanceCount'])!r}"
    )
    assert _instances_holding(ec2, cr_id) == [], (
        f"a reservation nothing has launched into must hold no instances, EC2 reported "
        f"{_instances_holding(ec2, cr_id)!r}"
    )

    inst = _launch(ctx, instance_type=_INSTANCE_TYPE, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, profile_name=profile_name,
                   cr_spec={"CapacityReservationTarget": {"CapacityReservationId": cr_id}})
    instance_id = inst["InstanceId"]
    # Registered immediately, before the first assertion: a machine that never comes up must not
    # be able to strand a billing instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))

    assert "CapacityReservationId" not in inst, (
        "the RunInstances accept envelope must not claim the reservation is consumed — consumption "
        f"is an effect observed afterwards, not part of the accept — got {inst!r}"
    )
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet and the "
        f"reservation both pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=600, interval_s=5.0, what=f"instance {instance_id} reaching 'running'")

    # --- the reservation's own bookkeeping moved -----------------------------
    view = _poll(lambda: _cr_view(ec2, cr_id), lambda v: v["AvailableInstanceCount"] == 0,
                 timeout_s=300, interval_s=5.0,
                 what=f"reservation {cr_id} reporting its seat as taken")
    assert view["TotalInstanceCount"] == 1, (
        f"consuming a seat must not change how many seats exist, got {view!r}"
    )
    assert view["State"] == "active", (
        f"a reservation with a running instance in it stays active, got {view['State']!r}"
    )
    assert view.get("CapacityAllocations") == [{"AllocationType": "used", "Count": 1}], (
        "the reservation must allocate exactly one used seat, got "
        f"{view.get('CapacityAllocations')!r}"
    )

    usage = ec2.get_capacity_reservation_usage(CapacityReservationId=cr_id)
    assert usage["AvailableInstanceCount"] == 0, (
        f"GetCapacityReservationUsage must agree that no seat is free, got {usage!r}"
    )
    assert usage["TotalInstanceCount"] == 1, f"usage reports {usage!r}"
    assert usage["InstanceUsages"] == [{"AccountId": account, "UsedInstanceCount": 1}], (
        f"the one used seat must be attributed to this account {account!r}, got "
        f"{usage['InstanceUsages']!r}"
    )

    # --- and EC2's own join says it is THIS instance that occupies it --------
    holders = _poll(lambda: _instances_holding(ec2, cr_id), lambda h: h == [instance_id],
                    timeout_s=300, interval_s=5.0,
                    what=f"the capacity-reservation-id filter resolving to {instance_id}")
    assert holders == [instance_id], (
        f"the reservation must hold exactly the instance launched into it; EC2's "
        f"capacity-reservation-id filter returned {holders!r}"
    )
    recorded = _instance_view(ec2, instance_id)
    assert recorded["CapacityReservationId"] == cr_id, (
        f"the instance must report the reservation backing it, got "
        f"{recorded.get('CapacityReservationId')!r}"
    )

    # --- the machine behind the bookkeeping actually runs --------------------
    _wait_online(ctx, instance_id)
    facts, out = _guest_facts(ctx, instance_id, what="reading the reserved guest's own view")
    assert facts["IID"] == instance_id, (
        f"the guest must report its own instance id {instance_id!r} from IMDS; it printed "
        f"{facts['IID']!r}. Full probe output: {out!r}"
    )
    assert facts["TYPE"] == _INSTANCE_TYPE, (
        f"the reserved seat is for {_INSTANCE_TYPE!r}, so the guest must report that type; it "
        f"printed {facts['TYPE']!r}. Full probe output: {out!r}"
    )
    assert facts["AZ"] == az, (
        f"the reservation is pinned to {az!r}, so the guest must report running there; it printed "
        f"{facts['AZ']!r}. Full probe output: {out!r}"
    )
    assert int(facts["CPUS"]) == _MICRO_VCPUS, (
        f"a {_INSTANCE_TYPE} has {_MICRO_VCPUS} vCPUs and the guest's own kernel must see them; "
        f"nproc printed {facts['CPUS']!r}. Full probe output: {out!r}"
    )
    mem_kb = int(facts["MEMKB"])
    assert _MICRO_MEM_KB[0] <= mem_kb <= _MICRO_MEM_KB[1], (
        f"a {_INSTANCE_TYPE} has 1 GiB, so the guest's /proc/meminfo must report between "
        f"{_MICRO_MEM_KB[0]} and {_MICRO_MEM_KB[1]} kB; it reported {mem_kb!r}. Full probe "
        f"output: {out!r}"
    )
    assert int(facts["UPTIME"]) >= 0, (
        f"the guest must report its own uptime, it printed {facts['UPTIME']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
