"""hibernate-stop-with-hibernate-on-an-instance-not-configured-for-it-rejected."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hibernate-stop-with-hibernate-on-an-instance-not-configured-for-it-rejected"
GROUP = "hibernation-preconditions"
SERVICES = ["ec2"]

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_ERR_HIBERNATION = "UnsupportedHibernationConfiguration"
_REASON_HIBERNATE = "Client.UserInitiatedHibernate"
#: The family this row measures hibernation on.
_INSTANCE_TYPE = "m5.large"


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=2.0, what="", ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=60, delay=2.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return None
            raise


def _usable_az(ec2, itype):
    """An AZ this region reports available that also offers `itype`.

    Offerings never report zone state and AZ listings say nothing about instance types.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [itype]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no AZ this region reports as available offers {itype}; offered in {sorted(offered)!r}, "
        f"available {sorted(available)!r}. This region cannot run the check."
    )
    return usable[0]


def _own_vpc(ctx, ec2, az, scenario):
    """A tagged VPC and subnet of this check's own making, with no internet gateway.

    Not the default VPC: an account need not have one, and using it makes the check account-bound.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                              TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _newest_al2023(ec2, ssm):
    """The current AL2023 x86_64 AMI, its root device name and the smallest root it permits."""
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"
    img = ec2.describe_images(ImageIds=[ami])["Images"][0]
    root_gib = max((b["Ebs"]["VolumeSize"] for b in img["BlockDeviceMappings"] if "Ebs" in b),
                   default=8)
    return ami, img["RootDeviceName"], root_gib


def _describe(ec2, instance_id):
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
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI clears only at the
    end, and the subnet/VPC teardown registered earlier cannot proceed until it does."""
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


def _hibernate_when_ready(ec2, instance_id, timeout_s=900, interval_s=2.0, ctx=None):
    """StopInstances(Hibernate=True), retrying UnsupportedOperation ("not ready to hibernate").

    A configured instance refuses for minutes after launch, and no field reports when that ends.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return ec2.stop_instances(InstanceIds=[instance_id], Hibernate=True)
        except ClientError as exc:
            if _code(exc) not in _THROTTLE + ("UnsupportedOperation",):
                raise
            last = exc
            if time.monotonic() >= deadline:
                if ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"{instance_id} becoming ready to hibernate: the run budget ended "
                                       "first; not graded") from exc
                raise AssertionError(
                    f"{instance_id} never became ready to hibernate within {timeout_s}s; the last "
                    f"answer was {_code(last)}: {last.response.get('Error', {}).get('Message')!r}"
                ) from exc
            time.sleep(interval_s)


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """StopInstances(Hibernate=True) on an instance launched without hibernation is refused and it
    stays running; it then stops plainly, and its configured twin hibernates.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/hibernating-prerequisites.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    scenario = ctx.unique_name("hib-not-configured-")

    # --- everything decidable, before anything is created ---------------------
    info = ec2.describe_instance_types(InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"]
    assert info, f"{_INSTANCE_TYPE} is not offered in {ctx.region}"
    assert info[0].get("HibernationSupported") is True, (
        f"both twins must be a type that CAN hibernate, so that the launch-time flag is the only "
        f"difference, but {_INSTANCE_TYPE} reports HibernationSupported "
        f"{info[0].get('HibernationSupported')!r}"
    )
    mem_gib = math.ceil(info[0]["MemoryInfo"]["SizeInMiB"] / 1024)
    az = _usable_az(ec2, _INSTANCE_TYPE)
    ami, root_device, ami_gib = _newest_al2023(ec2, ssm)
    root_gib = max(ami_gib, mem_gib * 2 + 20)  # RAM image + filesystem + OS, on both twins
    subnet = _own_vpc(ctx, ec2, az, scenario)

    # Twins: same AMI, type, subnet and encrypted root; only HibernationOptions.Configured differs.
    def launch(configured, role):
        resp = _call_with_retry(lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            HibernationOptions={"Configured": configured},
            BlockDeviceMappings=[{"DeviceName": root_device,
                                  "Ebs": {"Encrypted": True, "VolumeSize": root_gib,
                                          "VolumeType": "gp3", "DeleteOnTermination": True}}],
            TagSpecifications=[
                {"ResourceType": rt,
                 "Tags": [{"Key": "sim2real", "Value": scenario},
                          {"Key": "sim2real-role", "Value": role}]}
                for rt in ("instance", "volume")]))
        iid = resp["Instances"][0]["InstanceId"]
        ctx.on_cleanup(lambda: _terminate_and_wait(ec2, iid))
        return iid

    subject = launch(False, "not-configured")
    control = launch(True, "configured")

    for iid, want in ((subject, False), (control, True)):
        inst = _poll(lambda i=iid: _describe(ec2, i),
                     lambda i: i is not None and i["State"]["Name"] in ("running", "terminated"),
                     ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2.0,
                     what=f"instance {iid} reaching running")
        assert inst["State"]["Name"] == "running", (
            f"{iid} did not reach running; DescribeInstances reported {inst['State']!r} with "
            f"{inst.get('StateReason')!r}"
        )
        assert inst.get("HibernationOptions") == {"Configured": want}, (
            f"{iid} was launched with HibernationOptions.Configured={want} but DescribeInstances "
            f"reports {inst.get('HibernationOptions')!r}; the twins do not differ in the one field "
            f"this check is about"
        )

    # --- the refusal ----------------------------------------------------------
    # Only the code is asserted; the message wording is not part of the contract here.
    try:
        resp = ec2.stop_instances(InstanceIds=[subject], Hibernate=True)
        raise AssertionError(
            f"StopInstances(Hibernate=True) ACCEPTED a hibernating stop of {subject}, which was "
            f"launched with HibernationOptions.Configured=False; it answered {resp!r}"
        )
    except ClientError as exc:
        code = _code(exc)
    assert code == _ERR_HIBERNATION, (
        f"a hibernating stop of {subject}, launched without hibernation configured, must be refused "
        f"with {_ERR_HIBERNATION!r}, but StopInstances answered {code!r}"
    )

    # --- and the effect is ABSENT --------------------------------------------
    # Not one sample: a refusal that nonetheless started a shutdown would show up a few seconds
    # later, so the instance is sampled every 2 s for 6 s and must stay running throughout.
    deadline = time.monotonic() + 6
    while True:
        inst = _describe(ec2, subject)
        assert inst is not None and inst["State"]["Name"] == "running", (
            f"the refused hibernating stop must leave {subject} running, but it is now "
            f"{inst and inst['State']!r} with {inst and inst.get('StateReason')!r}"
        )
        assert inst.get("StateReason", {}).get("Code") != _REASON_HIBERNATE, (
            f"{subject} reports StateReason {inst['StateReason']!r} after a REFUSED hibernating "
            f"stop, so the refusal was not the whole of what happened"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2)

    # --- control A: the same instance stops plainly, with the ordinary reason --
    _call_with_retry(lambda: ec2.stop_instances(InstanceIds=[subject]))
    inst = _poll(lambda: _describe(ec2, subject),
                 lambda i: i is not None and i["State"]["Name"] in ("stopped", "terminated"),
                 ctx=ctx, timeout_s=_budget_s(ctx, 600), interval_s=2.0, what=f"{subject} reaching stopped")
    assert inst["State"]["Name"] == "stopped", (
        f"{subject} did not reach stopped under a plain StopInstances; it is {inst['State']!r}"
    )
    assert inst.get("StateReason", {}).get("Code") != _REASON_HIBERNATE, (
        f"{subject} was stopped WITHOUT Hibernate=True, so its StateReason must not be "
        f"{_REASON_HIBERNATE!r}; DescribeInstances reports {inst.get('StateReason')!r}"
    )

    # --- control B: the configured twin hibernates ----------------------------
    _hibernate_when_ready(ec2, control, ctx=ctx, timeout_s=_budget_s(ctx, 900))
    inst = _poll(lambda: _describe(ec2, control),
                 lambda i: i is not None and i["State"]["Name"] in ("stopped", "terminated"),
                 ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2.0,
                 what=f"{control} reaching stopped by hibernation")
    assert inst["State"]["Name"] == "stopped", (
        f"the configured twin {control} did not reach stopped; it is {inst['State']!r} with "
        f"{inst.get('StateReason')!r}"
    )
    assert inst.get("StateReason", {}).get("Code") == _REASON_HIBERNATE, (
        f"the configured twin {control} stopped, but its StateReason is {inst.get('StateReason')!r} "
        f"rather than {_REASON_HIBERNATE!r} — it was shut down, not hibernated, so the acceptance "
        f"above did not mean what the refusal is being contrasted with"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
