"""cpucredit-unlimited-sustains-guest-throughput-on-surplus-credits."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cpucredit-unlimited-sustains-guest-throughput-on-surplus-credits"
GROUP = "cpu-credit-accounting"
SERVICES = ["ec2"]

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")

#: The instance type under test: burstable accounting only exists on a burstable family, so the
#: type IS the subject. The AZ is derived (see `_pick_az`).
_ITYPE = "t3.micro"
_WINDOW_S = 20
#: Sustained load between the two measured windows. A t3.micro accrues 0.2 credits/minute and a
#: single thread spends 1.0, so ~7 minutes of burning is several minutes past the point where any
#: plausible starting balance is gone and the only thing funding the CPU is surplus.
_DRAIN_S = 420
#: `unlimited` must NOT collapse toward the baseline: the second window has to hold most of the
#: first window's rate. Loose on purpose — the failing case is the ~0.2x collapse of the first
#: window's rate that a standard-mode instance shows, not a few percent of scheduler noise.
_THROUGHPUT_HOLD_RATIO = 0.7
#: Surplus credits (credits spent that were never earned) must be visible, not merely non-negative.
_MIN_SURPLUS = 0.5
#: Surplus is only ever spent once the earned balance is exhausted, so the balance must read ~0
#: across the same window.
_MAX_BALANCE_WHILE_SURPLUS = 0.25

_RUNNING_BUDGET_S = 600.0
_AGENT_BUDGET_S = 600.0
_SURPLUS_BUDGET_S = 600.0
_GUEST_BUDGET_S = 900.0


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


def _pick_az(ec2, want):
    """The first AZ that BOTH offers `want` and is reported `available`.

    Both halves are load-bearing: `describe_instance_type_offerings` does not report zone state, and
    `describe_availability_zones` says nothing about instance types. A literal AZ name would be a
    capacity gamble wearing a fixed name, since AZ names are per-account aliases.
    """
    offered = set()
    for page in ec2.get_paginator("describe_instance_type_offerings").paginate(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}],
    ):
        offered |= {o["Location"] for o in page["InstanceTypeOfferings"]}
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no available AZ in this region offers {want!r} — offerings were {sorted(offered)!r}; "
        f"this region cannot run this check"
    )
    return usable[0]


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded: a DependencyViolation that never clears is a leak to declare, not a loop to sit in.
    """
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                             "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                             "InvalidAssociationID.NotFound", "Gateway.NotAttached"):
                return None
            raise


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with a public subnet in `az`.

    Deliberately not the account's default VPC: a fresh account need not have one, and a shared default subnet makes the check assert a property of the account. The SSM
    agent needs egress to reach its endpoint, so the subnet gets an internet gateway, a default route
    and auto-assigned public addressing. Every piece is tagged at creation — an untagged VPC object
    cannot be found for cleanup.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
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
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-cpucr-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav cpu-credit data-plane role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                               Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
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


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
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


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=900):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects SendCommand
    with InvalidInstanceId until its agent has registered, so retrying that call polls an observable
    condition instead of sleeping a guessed interval. A host that never accepts a command is a FAIL.
    """
    deadline = time.monotonic() + ready_timeout_s
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav cpu-credit data plane",
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
                timeout_s=run_timeout_s, interval_s=10.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    assert inv["ResponseCode"] == 0, (
        f"{what}: the guest script exited {inv['ResponseCode']!r}; "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _report(stdout, marker):
    """The `key=value` fields of the last line starting with `marker`, as a dict."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith(marker):
            continue
        out = {}
        for field in line[len(marker):].split():
            if "=" in field:
                k, _, v = field.partition("=")
                out[k] = v
        return out
    return None


#: Marker the guest prints its two measurements under.
_MARKER = "SIM2REAL-CPUCREDIT"


def _burn_script(window_s, drain_s):
    """A pure-bash CPU-bound loop, timed IN THE GUEST, run twice around a sustained drain.

    Work per unit time is the observable, so the loop must not be dominated by
    anything that is not CPU: the inner 5000-iteration block does only shell arithmetic and forks
    nothing, and `date` is consulted once per block rather than once per iteration. One thread, not
    two, so a throttled host would still have enough CPU left to report the result back — which is
    what makes the absence of throttling here a positive finding rather than a silent timeout.
    """
    return [
        "set -uo pipefail",
        "burn() {",
        '  local secs="$1" start end n x i',
        "  start=$(date +%s)",
        "  end=$(( start + secs ))",
        "  n=0; x=0",
        "  while : ; do",
        "    i=0",
        '    while [ "$i" -lt 5000 ]; do x=$(( (x + i * i + 7) % 1000003 )); i=$(( i + 1 )); done',
        "    n=$(( n + 5000 ))",
        '    [ "$(date +%s)" -ge "$end" ] && break',
        "  done",
        '  echo "$n"',
        "}",
        "T0=$(date +%s)",
        f"W1=$(burn {int(window_s)})",
        "T1=$(date +%s)",
        f"burn {int(drain_s)} >/dev/null",
        "T2=$(date +%s)",
        f"W2=$(burn {int(window_s)})",
        "T3=$(date +%s)",
        f'echo "{_MARKER} w1=$W1 w2=$W2 w1_secs=$(( T1 - T0 ))'
        ' drain_secs=$(( T2 - T1 )) w2_secs=$(( T3 - T2 ))'
        ' nproc=$(nproc) uptime=$(cut -d. -f1 /proc/uptime)"',
    ]


def _credit_metric(cw, metric, instance_id, since_epoch):
    """Raw AWS/EC2 credit datapoints for one instance, oldest first.

    Period=300 matches the 5-minute grid these metrics publish on, and Minimum/Maximum are read
    rather than Average so that a finer publication cadence (if the target has one) still yields the
    trough and the peak within each bucket instead of smoothing them away.
    """
    start = datetime.fromtimestamp(since_epoch, tz=timezone.utc) - timedelta(seconds=600)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName=metric,
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start,
        EndTime=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
        Period=300,
        Statistics=["Minimum", "Maximum", "Sum"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _after(dps, burn_start_epoch):
    """Buckets whose 300 s period ends after the burn began.

    Split on the period END rather than its timestamp because a CloudWatch timestamp names the START
    of the bucket, so a datapoint describing the burn is timestamped up to 300 s before it finished.
    """
    return [d for d in dps if d["Timestamp"].timestamp() + 300 > burn_start_epoch]


# ===== end helpers =====


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances-monitoring-cpu-credits.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An `unlimited` t3.micro that has exhausted its earned credits keeps its in-guest throughput across
    seven minutes of sustained load, while CPUSurplusCreditBalance goes positive and CPUCreditBalance stays
    zero: surplus is drawn only once the earned balance is exhausted."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    cw = ctx.client("cloudwatch")
    scenario = "ec2-cpucredit-unlimited"

    # --- everything decidable, before anything is created ---------------------
    az = _pick_az(ec2, _ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    # --- one burstable instance, explicitly in `unlimited` credit mode --------
    tag_spec = [
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": profile},
                                      {"Key": "sim2real", "Value": scenario}]}
        for rt in ("instance", "volume")
    ]
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    reservation = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            CreditSpecification={"CpuCredits": "unlimited"},
            IamInstanceProfile={"Name": profile}, TagSpecifications=tag_spec,
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    launched_at = time.time()

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
          what=f"instance {instance_id} reaching 'running'")

    # The premise, asserted rather than assumed.
    spec = _poll(
        lambda: ec2.describe_instance_credit_specifications(InstanceIds=[instance_id])[
            "InstanceCreditSpecifications"],
        lambda s: bool(s), timeout_s=120.0, interval_s=5.0,
        what=f"a credit specification appearing for {instance_id}")[0]
    assert spec["CpuCredits"] == "unlimited", (
        f"this check only means anything on an unlimited-mode instance, but {instance_id} reports "
        f"CpuCredits={spec['CpuCredits']!r}"
    )

    # --- the agent must register: a host that never registers is a FAIL -------
    def _agent_view():
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == instance_id:
                    return info
        return None

    info = _poll(_agent_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=_AGENT_BUDGET_S, interval_s=5.0,
                 what=f"the SSM agent on {instance_id} coming Online")
    assert info["PlatformType"] == "Linux", (
        f"an AL2023 host must register as PlatformType Linux, got {info.get('PlatformType')!r}"
    )

    # --- burn, continuously, well past the point of credit exhaustion ---------
    burn_start = time.time()
    out = _run_guest(ssm, instance_id, _burn_script(_WINDOW_S, _DRAIN_S),
                     "burning CPU past the credit balance and into surplus",
                     run_timeout_s=_GUEST_BUDGET_S)
    seen = _report(out, _MARKER)
    assert seen and all(k in seen for k in ("w1", "w2", "w1_secs", "w2_secs", "nproc")), (
        f"the guest did not report a pair of measured windows; its stdout was {out!r}"
    )
    assert seen["nproc"] == "2", (
        f"a t3.micro has 2 vCPUs, so the baseline this check compares against is 0.2 of one; the "
        f"guest reported nproc={seen['nproc']!r}, which changes what the numbers mean"
    )
    w1, w2 = int(seen["w1"]), int(seen["w2"])
    s1, s2 = max(int(seen["w1_secs"]), 1), max(int(seen["w2_secs"]), 1)
    rate1, rate2 = w1 / s1, w2 / s2
    assert w1 > 0 and w2 > 0, (
        f"both windows must do measurable work for the comparison to mean anything; the guest "
        f"reported {seen!r}"
    )

    # --- (1) the guest was never throttled --------------------------------
    assert rate2 >= rate1 * _THROUGHPUT_HOLD_RATIO, (
        f"an unlimited-mode t3.micro must NOT be held to its 0.2 vCPU baseline when its credits run "
        f"out. Measured INSIDE the guest: {rate1:.0f} iterations/s over the first {s1}s "
        f"({w1} iterations), then {rate2:.0f} iterations/s over the last {s2}s ({w2} iterations) "
        f"after {seen.get('drain_secs')}s of sustained load — a ratio of {rate2 / rate1:.2f}, "
        f"which is below {_THROUGHPUT_HOLD_RATIO}. Full guest report: {seen!r}"
    )

    # --- (2) AWS accounts for it as SURPLUS, against a zero earned balance ----
    def _surplus():
        surplus = _after(_credit_metric(cw, "CPUSurplusCreditBalance", instance_id, launched_at),
                         burn_start)
        balance = _after(_credit_metric(cw, "CPUCreditBalance", instance_id, launched_at),
                         burn_start)
        if not surplus or not balance:
            return None
        return max(d["Maximum"] for d in surplus), min(d["Minimum"] for d in balance)

    peak_surplus, low_balance = _poll(
        _surplus, lambda r: r is not None and r[0] >= _MIN_SURPLUS,
        timeout_s=_SURPLUS_BUDGET_S, interval_s=20.0,
        what=(f"CloudWatch reporting at least {_MIN_SURPLUS} surplus CPU credits for {instance_id} "
              f"after {int(_DRAIN_S + 2 * _WINDOW_S)}s of sustained load"))
    assert peak_surplus >= _MIN_SURPLUS, (
        f"seven minutes of full-speed CPU on a t3.micro costs far more credits than it can earn, so "
        f"an unlimited-mode instance must report the difference as surplus; CPUSurplusCreditBalance "
        f"peaked at {peak_surplus}, under the {_MIN_SURPLUS} floor"
    )
    assert low_balance <= _MAX_BALANCE_WHILE_SURPLUS, (
        f"surplus credits are only ever drawn once the earned balance is exhausted, so a reported "
        f"surplus of {peak_surplus} is only coherent against a balance at zero; CPUCreditBalance "
        f"never fell below {low_balance} over the same window"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
