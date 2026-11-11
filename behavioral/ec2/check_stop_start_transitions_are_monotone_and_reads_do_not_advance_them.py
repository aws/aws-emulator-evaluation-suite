"""stop-start-transitions-are-monotone-and-reads-do-not-advance-them."""
from __future__ import annotations

import datetime
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-start-transitions-are-monotone-and-reads-do-not-advance-them"
GROUP = "state-machine"
SERVICES = ["ec2"]

_VPC_CIDR = "10.79.0.0/16"
_SUBNET_CIDR = "10.79.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: InstanceState.Code is a FIXED API constant, identical in every account and not adjustable, so
#: pinning it is part of the contract rather than a quota assumption.
_STATE_CODES = {
    "pending": 0,
    "running": 16,
    "shutting-down": 32,
    "terminated": 48,
    "stopping": 64,
    "stopped": 80,
}
_STOP_PHASE = ("running", "stopping", "stopped")
_START_PHASE = ("stopped", "pending", "running")
_TERMINATE_PHASE = ("running", "shutting-down", "terminated")
_REASON_USER_STOP = "Client.UserInitiatedShutdown"
_REASON_USER_STOP_MESSAGE = "Client.UserInitiatedShutdown: User initiated shutdown"
_TRANSITION_FORMAT = "User initiated (%Y-%m-%d %H:%M:%S GMT)"
_FREEZE_READS = 5
_ERR_WRONG_STATE = "IncorrectInstanceState"
_GONE_CODES = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
               "InvalidInstanceID.NotFound")
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Stop/start/terminate walk modelled states with fixed codes, forwards only, with transient
    states in the call responses and user-initiated reasons; repeated reads of a stopped instance
    do not advance it, and a terminated instance refuses a further stop.
    """
    ec2 = ctx.client("ec2")
    st: dict = {"instances": [], "sgs": [], "subnets": []}
    try:
        _build(ctx, ec2, st)
        _legs(ec2, st)
    finally:
        _teardown(ec2, st)


# ===== the legs ==============================================================


def _legs(ec2, st) -> None:
    instance_id = st["instance"]
    private_ip = st["private_ip"]

    # --- the stop. The response must describe the TRANSIENT state, not the destination. ---
    stop_started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    stopping = ec2.stop_instances(InstanceIds=[instance_id])["StoppingInstances"]
    assert len(stopping) == 1 and stopping[0]["InstanceId"] == instance_id, (
        f"StopInstances must report exactly this instance, got {stopping!r}"
    )
    _assert_state(stopping[0]["PreviousState"], "running",
                  f"StopInstances' PreviousState for {instance_id}")
    _assert_state(stopping[0]["CurrentState"], "stopping",
                  f"StopInstances' CurrentState for {instance_id} — a target that answers "
                  f"'stopped' here has written a field instead of starting a state machine")

    observed = _observe(ec2, instance_id, until="stopped", timeout_s=600.0)
    _assert_phase(observed, _STOP_PHASE, f"the stop of {instance_id}")
    assert "stopping" in [name for name, _ in observed], (
        f"the stop must pass through the transient 'stopping' state; the poll observed only "
        f"{[name for name, _ in observed]!r}"
    )

    # --- the terminal state's reason, read through DescribeInstances ---
    stopped = _describe(ec2, instance_id)
    assert stopped is not None, f"DescribeInstances lost {instance_id!r} after it stopped"
    _assert_state(stopped["State"], "stopped", f"DescribeInstances' State for {instance_id}")
    reason = stopped.get("StateReason", {})
    assert reason == {"Code": _REASON_USER_STOP, "Message": _REASON_USER_STOP_MESSAGE}, (
        f"an API-initiated stop must be attributed to {_REASON_USER_STOP!r} with message "
        f"{_REASON_USER_STOP_MESSAGE!r}; DescribeInstances reports StateReason {reason!r}"
    )
    _assert_transition_reason(stopped.get("StateTransitionReason", ""), stop_started,
                              f"the stop of {instance_id}")

    # --- the freeze detector: reads must not advance the machine ---
    frozen = [
        (i["State"]["Name"], i["State"]["Code"], i.get("StateReason", {}).get("Code"),
         i.get("StateTransitionReason", ""))
        for i in (_describe(ec2, instance_id) for _ in range(_FREEZE_READS))
        if i is not None
    ]
    assert len(frozen) == _FREEZE_READS, (
        f"all {_FREEZE_READS} freeze-detector reads must return the instance; got {len(frozen)}"
    )
    assert len(set(frozen)) == 1, (
        f"{_FREEZE_READS} consecutive DescribeInstances reads of a STOPPED instance must return the "
        f"identical state, reason and transition reason — reading must not advance the machine. The "
        f"reads returned {sorted(set(frozen))!r}"
    )
    # a second operation agrees, and DescribeInstanceStatus does not invent a running instance
    listed = ec2.describe_instance_status(
        InstanceIds=[instance_id], IncludeAllInstances=True)["InstanceStatuses"]
    assert len(listed) == 1, (
        f"DescribeInstanceStatus(IncludeAllInstances=True) must report exactly one status for "
        f"{instance_id}, got {listed!r}"
    )
    _assert_state(listed[0]["InstanceState"], "stopped",
                  f"DescribeInstanceStatus' InstanceState for {instance_id}")

    # --- the start. Same shape, opposite direction, and the private address is retained. ---
    starting = ec2.start_instances(InstanceIds=[instance_id])["StartingInstances"]
    assert len(starting) == 1, f"StartInstances must report exactly one instance, got {starting!r}"
    _assert_state(starting[0]["PreviousState"], "stopped",
                  f"StartInstances' PreviousState for {instance_id}")
    _assert_state(starting[0]["CurrentState"], "pending",
                  f"StartInstances' CurrentState for {instance_id} — a target that answers "
                  f"'running' here has no pending phase")
    started = _observe(ec2, instance_id, until="running", timeout_s=600.0)
    _assert_phase(started, _START_PHASE, f"the start of {instance_id}")
    running = _describe(ec2, instance_id)
    assert running is not None and running["PrivateIpAddress"] == private_ip, (
        f"a stop/start must retain the instance's private IPv4 address {private_ip!r}; after the "
        f"start DescribeInstances reports {running and running.get('PrivateIpAddress')!r}"
    )
    assert running["InstanceId"] == instance_id, (
        f"a stop/start must retain the instance id {instance_id!r}, got {running['InstanceId']!r}"
    )

    # --- the terminate, and the dead id refuses a mutation ---
    terminating = ec2.terminate_instances(InstanceIds=[instance_id])["TerminatingInstances"]
    _assert_state(terminating[0]["PreviousState"], "running",
                  f"TerminateInstances' PreviousState for {instance_id}")
    _assert_state(terminating[0]["CurrentState"], "shutting-down",
                  f"TerminateInstances' CurrentState for {instance_id}")
    gone = _observe(ec2, instance_id, until="terminated", timeout_s=600.0)
    _assert_phase(gone, _TERMINATE_PHASE, f"the terminate of {instance_id}")
    dead = _describe(ec2, instance_id)
    assert dead is not None, (
        f"a terminated instance stays describable for a while, so {instance_id!r} must still be "
        f"readable here; DescribeInstances lost it"
    )
    _assert_state(dead["State"], "terminated", f"DescribeInstances' State for {instance_id}")
    assert dead.get("StateReason") == {"Code": _REASON_USER_STOP,
                                       "Message": _REASON_USER_STOP_MESSAGE}, (
        f"an API-initiated terminate must be attributed to {_REASON_USER_STOP!r} with message "
        f"{_REASON_USER_STOP_MESSAGE!r}; got {dead.get('StateReason')!r}"
    )
    err = _client_error(lambda: ec2.stop_instances(InstanceIds=[instance_id]))
    assert err.get("Code") == _ERR_WRONG_STATE, (
        f"stopping a TERMINATED instance must fail with {_ERR_WRONG_STATE} — the same call "
        f"demonstrably succeeded earlier in this run; got {err.get('Code')!r} "
        f"({err.get('Message')!r})"
    )
    expected = f"This instance '{instance_id}' is not in a state from which it can be stopped."
    assert err.get("Message") == expected, (
        f"stopping a TERMINATED instance must be refused with {expected!r}, got "
        f"{err.get('Message')!r}"
    )


def _assert_state(state, expected_name, where):
    """Both halves of an InstanceState, against the fixed API constants."""
    assert state.get("Name") == expected_name, (
        f"{where} must be {expected_name!r}, got {state.get('Name')!r} (full state {state!r})"
    )
    assert state.get("Code") == _STATE_CODES[expected_name], (
        f"{where} must carry the modelled numeric code {_STATE_CODES[expected_name]} for "
        f"{expected_name!r}, got {state.get('Code')!r} (full state {state!r})"
    )


def _assert_transition_reason(transition, started, where):
    """StateTransitionReason is exactly `User initiated (<UTC time> GMT)`, with the time inside
    the window between the request and now."""
    try:
        at = datetime.datetime.strptime(transition, _TRANSITION_FORMAT).replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        raise AssertionError(
            f"{where}: StateTransitionReason must read exactly 'User initiated (YYYY-MM-DD "
            f"HH:MM:SS GMT)', got {transition!r}") from None
    now = datetime.datetime.now(datetime.timezone.utc)
    assert started <= at <= now, (
        f"{where}: StateTransitionReason {transition!r} names a time outside the request window "
        f"[{started.isoformat()}, {now.isoformat()}]"
    )
    assert transition == at.strftime(_TRANSITION_FORMAT), (
        f"{where}: StateTransitionReason {transition!r} is not in canonical form"
    )


def _assert_phase(observed, phase, where):
    """Every observation is a modelled state, and the sequence walks `phase` forwards only."""
    names = [name for name, _ in observed]
    unknown = [n for n in names if n not in _STATE_CODES]
    assert not unknown, (
        f"{where} passed through states that are not in the modelled set {sorted(_STATE_CODES)!r}: "
        f"{unknown!r} (full sequence {names!r})"
    )
    for name, code in observed:
        assert code == _STATE_CODES[name], (
            f"{where} reported state {name!r} with numeric code {code} instead of the modelled "
            f"{_STATE_CODES[name]} (full sequence {observed!r})"
        )
    off_phase = [n for n in names if n not in phase]
    assert not off_phase, (
        f"{where} must stay inside {phase!r}; it also visited {off_phase!r} (full sequence "
        f"{names!r})"
    )
    ranks = [phase.index(n) for n in names]
    assert ranks == sorted(ranks), (
        f"{where} must advance through {phase!r} monotonically and never go backwards; the observed "
        f"sequence was {names!r}"
    )
    assert names[-1] == phase[-1], (
        f"{where} must END at {phase[-1]!r}; the observed sequence was {names!r}"
    )


def _observe(ec2, instance_id, *, until, timeout_s, interval_s=1.0):
    """The ORDERED list of distinct (name, code) states seen on the way to `until`.

    Polls at 1 s so a transient state is caught, records only changes, and raises on timeout.
    """
    deadline = time.monotonic() + timeout_s
    seen: list[tuple[str, int]] = []
    while time.monotonic() < deadline:
        inst = _describe(ec2, instance_id)
        if inst is not None:
            current = (inst["State"]["Name"], inst["State"]["Code"])
            if not seen or seen[-1] != current:
                seen.append(current)
            if current[0] == until:
                return seen
        time.sleep(interval_s)
    raise AssertionError(
        f"{STATE_MARKER}: instance {instance_id} never reached {until!r} within {timeout_s}s; the "
        f"states observed were {seen!r}"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, st) -> None:
    """A VPC and one private subnet of this check's own making — nothing here needs the internet,
    and nothing depends on an ambient default VPC."""
    name = ctx.unique_name("sim2real-b1life-")
    st["name"] = name

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _tolerate_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = sorted(_zones_offering(ec2, _INSTANCE_TYPE))[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    ctx.on_cleanup(lambda: _tolerate_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real instance lifecycle state-machine check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": _tags_for(name)},
            {"ResourceType": "volume", "Tags": _tags_for(name)},
        ],
    )["Instances"][0]["InstanceId"]
    st["instances"].append(instance_id)
    st["instance"] = instance_id
    ctx.on_cleanup(lambda: _tolerate_gone(
        lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    launch_phase = _observe(ec2, instance_id, until="running", timeout_s=600.0)
    _assert_phase(launch_phase, ("pending", "running"), f"the launch of {instance_id}")
    inst = _describe(ec2, instance_id)
    assert inst is not None and inst.get("PrivateIpAddress"), (
        f"a running instance must report a private IPv4 address; got {inst!r}"
    )
    st["private_ip"] = inst["PrivateIpAddress"]


# ===== in-band teardown ======================================================


def _assert_absent(listed):
    """Teardown step: a deleted resource must no longer be listed."""
    if listed:
        raise AssertionError(f"still describable after its delete: {listed!r}")


def _teardown(ec2, st) -> None:
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _wait_gone(ec2, i))
    if st.get("vpc"):
        _step("eni-drain", lambda: _wait_enis_gone(ec2, st["vpc"]))
    for sg in st.get("sgs", []):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s)))
    for subnet in st.get("subnets", []):
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s)))
    if st.get("vpc"):
        _step("vpc", lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=st["vpc"])))
        _step("vpc-gone", lambda: _assert_absent(ec2.describe_vpcs(VpcIds=[st["vpc"]])["Vpcs"]))
    left: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if _code(exc) not in _GONE_CODES:
                left.append(f"{label}: {_code(exc)}")
        except Exception as exc:  # noqa: BLE001 — every step runs; the failures are raised together
            left.append(f"{label}: {exc!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError(
            (f"{found!r}; " if found else "")
            + f"teardown could not remove everything the check created: {left!r}"
        )


def _wait_gone(ec2, instance_id, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe(ec2, instance_id)
        if inst is None or inst["State"]["Name"] == "terminated":
            return
        time.sleep(5.0)
    raise AssertionError(f"instance {instance_id} never reached 'terminated' within {timeout_s}s")


def _wait_enis_gone(ec2, vpc_id, timeout_s=420.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _vpc_enis(ec2, vpc_id)
        if last == []:
            return
        time.sleep(2)
    raise AssertionError(f"ENIs in {vpc_id} never drained within {timeout_s}s; last {last!r}")


# ===== helpers =====


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _tolerate_gone(fn):
    """A cleanup net: the in-band teardown usually removed the resource already."""
    try:
        fn()
    except ClientError as exc:
        if _code(exc) not in _GONE_CODES:
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _retry_dependency(fn, attempts=24, delay=10.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE_CODES:
                return
            if _code(exc) not in ("DependencyViolation", "InvalidParameterDependency",
                                  "RequestLimitExceeded") or attempt == attempts - 1:
                raise
            time.sleep(delay)


def _describe(ec2, instance_id):
    """The instance dict, or None while it is eventually-consistently invisible or truly gone."""
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _zones_offering(ec2, instance_type):
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }
    assert usable, f"no available zone in this region offers {instance_type!r}"
    return usable


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
