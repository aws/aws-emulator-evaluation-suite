"""cpuopts-topology-survives-a-stop-start-cycle."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cpuopts-topology-survives-a-stop-start-cycle"
GROUP = 'cpu-topology-data-plane'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: m5.large is 2 threads per core by default, so ThreadsPerCore=1 halves the guest's vCPUs; the
#: derivation in run() refuses to proceed if the type is not hyperthreaded.
_INSTANCE_TYPE = "m5.large"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=100, delay=2.0):
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


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="", ctx=None):
    """Poll probe() until predicate(result); AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s:.0f}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=100, delay=2.0):
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
    """An AZ that is both 'available' and offers instance_type.

    Neither API answers both: offerings omit zone state, and zones omit instance types.
    """
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

    Built rather than borrowed, since an account may have no default VPC.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.185.0.0/16",
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
        VpcId=vpc_id, CidrBlock="10.185.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-cpuopts-"), VpcId=vpc_id,
        Description="sim2real cpu-options guest topology egress only",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _instance_profile(ctx, scenario):
    """An instance profile whose role can register with SSM, so Run Command can reach the guest."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cpuopts-")
    trust = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":'
             '{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}')
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                    Description="sim2real cpu-options managed instance role",
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
    """Terminate and wait for 'terminated', not merely 'shutting-down'.

    The ENI and root volume only go away at 'terminated', and the later network deletions need that.
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
        time.sleep(2)


def _launch(ctx, *, profile_name, subnet_id, sg_id, scenario, cpu_options=None):
    """RunInstances with the instance AND its root volume tagged at launch."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    tag = [{"Key": "sim2real", "Value": scenario}]
    kw = {}
    if cpu_options is not None:
        kw["CpuOptions"] = cpu_options
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    resv = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
            **kw,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=100, delay=2.0)
    return resv["Instances"][0]


def _wait_online(ctx, instance_id, timeout_s=900, since=None):
    """Wait for the SSM agent on this host to report Online, with a ping after `since` if given."""
    ssm = ctx.client("ssm")

    def _view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    def _fresh(info):
        if info is None or info.get("PingStatus") != "Online":
            return False
        ping = info.get("LastPingDateTime")
        return since is None or (ping is not None and ping >= since)

    return _poll(_view, _fresh,
                 ctx=ctx, timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0,
                 what=f"the SSM agent on {instance_id} coming Online")


def _run_shell(ctx, instance_id, commands, *, what, timeout_s=300):
    """Send commands to the guest and return the terminal invocation record."""
    ssm = ctx.client("ssm")
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands}, TimeoutSeconds=300,
        Comment="sim2real cpu-options topology read-back"))
    command_id = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    return _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                 ctx=ctx, timeout_s=_budget_s(ctx, timeout_s), interval_s=1.0,
                 what=f"{what}: invocation {command_id} reaching a terminal status")


def _marker(stdout, marker):
    """The text after `marker` on the last line that starts with it, or None."""
    value = None
    for line in stdout.splitlines():
        if line.startswith(marker + " "):
            value = line[len(marker) + 1:].strip()
        elif line.strip() == marker:
            value = ""
    return value


#: Independent views of the guest's CPU topology (sysfs/procfs and lscpu), plus the kernel boot id
#: that distinguishes two readings as two boots.
_TOPOLOGY_COMMANDS = [
    "set -euo pipefail",
    'echo "GUEST-NPROC $(nproc)"',
    'echo "GUEST-BOOTID $(cat /proc/sys/kernel/random/boot_id)"',
    'echo "GUEST-ONLINE $(cat /sys/devices/system/cpu/online)"',
    'echo "GUEST-PROCESSORS $(grep -c ^processor /proc/cpuinfo)"',
    'echo "GUEST-SIBLINGS $(cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list)"',
    'echo "GUEST-LSCPU-CPUS $(LC_ALL=C lscpu | grep "^CPU(s):" | cut -d: -f2 | tr -d " ")"',
    'echo "GUEST-LSCPU-TPC $(LC_ALL=C lscpu | grep "^Thread(s) per core:"'
    ' | cut -d: -f2 | tr -d " ")"',
    'echo "GUEST-LSCPU-CPS $(LC_ALL=C lscpu | grep "^Core(s) per socket:"'
    ' | cut -d: -f2 | tr -d " ")"',
]


def _cpu_list_len(spec):
    """How many CPUs a Linux cpu-list names ("0", "0-1", "0,2-3").

    Parsed, not string-matched: the kernel may render the same set as a range or a list.
    """
    total = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            total += int(hi) - int(lo) + 1
        else:
            int(part)
            total += 1
    return total


def _guest_topology(ctx, instance_id, *, what):
    """Read the guest's own view of its CPU topology, via a command that ran INSIDE it."""
    inv = _run_shell(ctx, instance_id, _TOPOLOGY_COMMANDS, what=what)
    assert inv["Status"] == "Success", (
        f"{what}: the invocation was {inv['Status']!r}: {inv.get('StatusDetails')!r} "
        f"stdout={inv.get('StandardOutputContent')!r} stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: ResponseCode was {inv['ResponseCode']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    out = inv["StandardOutputContent"]
    seen = {name: _marker(out, "GUEST-" + name) for name in
            ("NPROC", "BOOTID", "ONLINE", "PROCESSORS", "SIBLINGS", "LSCPU-CPUS", "LSCPU-TPC",
             "LSCPU-CPS")}
    missing = sorted(k for k, v in seen.items() if not v)
    assert not missing, (
        f"{what}: the guest did not report {missing!r}; its stdout was {out!r}"
    )
    return {
        "nproc": int(seen["NPROC"]),
        "boot_id": seen["BOOTID"],
        "online": _cpu_list_len(seen["ONLINE"]),
        "online_raw": seen["ONLINE"],
        "processors": int(seen["PROCESSORS"]),
        "siblings": _cpu_list_len(seen["SIBLINGS"]),
        "siblings_raw": seen["SIBLINGS"],
        "lscpu_cpus": int(seen["LSCPU-CPUS"]),
        "lscpu_tpc": int(seen["LSCPU-TPC"]),
        "lscpu_cps": int(seen["LSCPU-CPS"]),
    }


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CpuOptions ThreadsPerCore=1 survives a stop/start: the guest, read via SSM Run Command, reports
    the same reduced topology on a new boot id, and DescribeInstances still records the CpuOptions.
    """
    scenario = "cpuopts-stop-start-persistence"
    ec2 = ctx.client("ec2")

    # Expected counts are derived from DescribeInstanceTypes, not hardcoded.
    vcpu = ec2.describe_instance_types(
        InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"][0]["VCpuInfo"]
    default_cores = vcpu["DefaultCores"]
    default_tpc = vcpu["DefaultThreadsPerCore"]
    default_vcpus = vcpu["DefaultVCpus"]
    valid_tpc = vcpu["ValidThreadsPerCore"]
    assert default_tpc > 1 and 1 in valid_tpc, (
        f"{_INSTANCE_TYPE} must be hyperthreaded by default and accept ThreadsPerCore=1 for this "
        f"check to observe anything; it reports {vcpu!r}"
    )
    reduced_vcpus = default_cores * 1
    assert reduced_vcpus < default_vcpus, (
        f"ThreadsPerCore=1 on {_INSTANCE_TYPE} must yield fewer vCPUs than the default "
        f"{default_vcpus!r}, but the derivation gives {reduced_vcpus!r}: {vcpu!r}"
    )

    subnet_id, sg_id, az = _network(ctx, scenario)
    profile_name = _instance_profile(ctx, scenario)

    requested = {"CoreCount": default_cores, "ThreadsPerCore": 1}
    inst = _launch(ctx, profile_name=profile_name, subnet_id=subnet_id, sg_id=sg_id,
                   scenario=scenario, cpu_options=requested)
    instance_id = inst["InstanceId"]
    # Registered before the first wait: a host that never comes up must not strand a billing
    # instance.
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    assert inst["Placement"]["AvailabilityZone"] == az, (
        f"the instance landed in {inst['Placement']!r}, not the AZ {az!r} the subnet pinned"
    )

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2.0,
          what=f"instance {instance_id} reaching 'running'")
    _wait_online(ctx, instance_id)
    before = _guest_topology(ctx, instance_id, what="the first boot's CPU topology")
    assert before["nproc"] == reduced_vcpus and before["lscpu_tpc"] == 1, (
        f"before any restart the guest must already report {reduced_vcpus!r} CPUs and 1 thread per "
        f"core; it reported {before!r}"
    )

    # --- stop it fully, then start it again ---------------------------------------
    ec2.stop_instances(InstanceIds=[instance_id])
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "stopped",
          ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2.0,
          what=f"instance {instance_id} reaching 'stopped'")
    stopped = ec2.describe_instances(
        InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert stopped["CpuOptions"] == requested, (
        f"a stopped instance must still carry the CpuOptions it launched with {requested!r}; "
        f"DescribeInstances reports {stopped['CpuOptions']!r}"
    )

    # A PingStatus of Online can be left over from the first boot: wait for a ping after the start.
    started_at = datetime.now(timezone.utc)
    ec2.start_instances(InstanceIds=[instance_id])
    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2.0,
          what=f"instance {instance_id} returning to 'running' after the restart")
    _wait_online(ctx, instance_id, since=started_at)
    after = _guest_topology(ctx, instance_id, what="the second boot's CPU topology")

    # --- the second reading is from a genuinely different boot --------------------
    assert after["boot_id"] != before["boot_id"], (
        f"/proc/sys/kernel/random/boot_id is {after['boot_id']!r} both before and after the "
        f"stop/start, so the machine never actually rebooted and the second reading proves nothing"
    )

    # --- and it reports the same reduced topology --------------------------------
    assert after["nproc"] == reduced_vcpus, (
        f"after the stop/start the guest ran `nproc` and printed {after['nproc']!r}, expected the "
        f"same {reduced_vcpus!r} it reported on the first boot — the restarted machine is running "
        f"the default {default_vcpus!r}-vCPU topology, so CpuOptions did not survive the cycle "
        f"(full guest view: {after!r})"
    )
    assert after["lscpu_tpc"] == 1, (
        f"after the stop/start lscpu inside the guest reported Thread(s) per core="
        f"{after['lscpu_tpc']!r}, expected 1 ({_INSTANCE_TYPE} serves {default_tpc!r} by default)"
    )
    assert after["siblings"] == 1, (
        f"after the stop/start cpu0's thread_siblings_list is {after['siblings_raw']!r}, naming "
        f"{after['siblings']!r} sibling threads; with hyperthreading disabled a core has exactly one"
    )
    for field in ("nproc", "online", "processors", "siblings", "lscpu_cpus", "lscpu_tpc",
                  "lscpu_cps"):
        assert after[field] == before[field], (
            f"the guest's {field!r} changed across the stop/start, {before[field]!r} -> "
            f"{after[field]!r}; the topology must be identical on both boots (before={before!r} "
            f"after={after!r})"
        )

    restarted = ec2.describe_instances(
        InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert restarted["CpuOptions"] == requested, (
        f"after the restart DescribeInstances reports CpuOptions {restarted['CpuOptions']!r}, not "
        f"the {requested!r} the instance launched with"
    )
    recorded_vcpus = (restarted["CpuOptions"]["CoreCount"]
                      * restarted["CpuOptions"]["ThreadsPerCore"])
    assert recorded_vcpus == after["nproc"], (
        f"after the restart the control plane's record implies {recorded_vcpus!r} vCPUs but the "
        f"guest itself counted {after['nproc']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
