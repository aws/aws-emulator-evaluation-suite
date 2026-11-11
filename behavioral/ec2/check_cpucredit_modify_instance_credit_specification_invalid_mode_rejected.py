"""cpucredit-modify-instance-credit-specification-invalid-mode-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cpucredit-modify-instance-credit-specification-invalid-mode-rejected"
GROUP = "cpu-credit-accounting"
SERVICES = ["ec2"]

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded")

#: Burstable family, because a credit specification only exists on one.
_ITYPE = "t3.micro"
#: `standard` and `unlimited` are the only two modes EC2 defines. This is a value of the right type
#: in the right place that is not one of them — the mode is a closed enum, not free text.
_INVALID_MODE = "turbo"
#: The code AWS returns, asserted exactly: this operation answers a parameter-specific code, not
#: the generic InvalidParameterValue a malformed enum usually draws.
_EXPECTED_CODE = "InvalidCpuCredits.Malformed"
#: The refusal arrives as a per-instance entry in UnsuccessfulInstanceCreditSpecifications under a
#: 200, not as a raised error: a caller's try/except sees success, so the channel is part of the
#: claim.
_EXPECTED_CHANNEL = "unsuccessful"

_RUNNING_BUDGET_S = 600.0


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
    """The first AZ that BOTH offers `want` and is reported `available`."""
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
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) == "DependencyViolation" and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return None
            raise


def _private_vpc(ctx, ec2, az, scenario):
    """A VPC and subnet of this check's own making.

    No internet gateway: nothing in this check runs inside the guest, so the instance needs to exist
    and reach `running`, not to reach the network. Not the account's default VPC — a fresh account
    need not have one, and using a shared default would make the check assert a property of the
    account rather than of the API. Tagged at creation, so cleanup can find it.
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


def _refusal(fn):
    """Call `fn` and report HOW it was refused, as `(channel, code)`.

    Both of ModifyInstanceCreditSpecification's refusal channels are covered, because which one
    carries a given class of error is itself part of the contract. An accepted call is not a refusal
    and raises here rather than returning a falsy sentinel the caller might compare against a string
    and silently pass.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return "exception", _code(exc)
    unsuccessful = resp.get("UnsuccessfulInstanceCreditSpecifications") or []
    if unsuccessful:
        return "unsuccessful", unsuccessful[0].get("Error", {}).get("Code")
    raise AssertionError(
        f"the call was expected to be refused but succeeded; response was {resp!r}"
    )


def _credit_mode(ec2, instance_id):
    specs = _poll(
        lambda: ec2.describe_instance_credit_specifications(InstanceIds=[instance_id])[
            "InstanceCreditSpecifications"],
        lambda s: bool(s), timeout_s=120.0, interval_s=5.0,
        what=f"a credit specification appearing for {instance_id}")
    return specs[0]["CpuCredits"]


# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """ModifyInstanceCreditSpecification refuses a CpuCredits value outside {standard, unlimited} with
    InvalidCpuCredits.Malformed as a per-instance failure under a 200, and the instance's already-modified
    `unlimited` mode is left as it was."""
    ec2 = ctx.client("ec2")
    scenario = "ec2-cpucredit-invalid-mode"

    az = _pick_az(ec2, _ITYPE)
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"
    subnet = _private_vpc(ctx, ec2, az, scenario)

    name = ctx.unique_name("sim2real-cpucr-")
    reservation = ec2.run_instances(
        ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
        CreditSpecification={"CpuCredits": "standard"},
        TagSpecifications=[
            {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name},
                                          {"Key": "sim2real", "Value": scenario}]}
            for rt in ("instance", "volume")
        ],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))

    _poll(lambda: _instance_state(ec2, instance_id), lambda s: s == "running",
          timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
          what=f"instance {instance_id} reaching 'running'")
    assert _credit_mode(ec2, instance_id) == "standard", (
        "the instance was launched with CpuCredits=standard and must report it before anything is "
        "modified"
    )

    # --- positive control: the same call, with a value from the enum ----------
    # In the same file and against the same instance, so a blanket refusal of every
    # ModifyInstanceCreditSpecification cannot be mistaken for correct validation.
    ok = _call_with_retry(lambda: ec2.modify_instance_credit_specification(
        InstanceCreditSpecifications=[
            {"InstanceId": instance_id, "CpuCredits": "unlimited"}]))
    assert not ok.get("UnsuccessfulInstanceCreditSpecifications"), (
        f"the positive control must be accepted; it reported "
        f"{ok.get('UnsuccessfulInstanceCreditSpecifications')!r}"
    )
    assert [s["InstanceId"] for s in ok.get("SuccessfulInstanceCreditSpecifications", [])] == [
        instance_id], (
        f"a successful modification must name the instance it applied to; got "
        f"{ok.get('SuccessfulInstanceCreditSpecifications')!r}"
    )
    mode = _poll(lambda: _credit_mode(ec2, instance_id), lambda m: m == "unlimited",
                 timeout_s=120.0, interval_s=5.0,
                 what=f"{instance_id} reporting CpuCredits=unlimited after the positive control")
    assert mode == "unlimited", mode

    # --- the refusal ---------------------------------------------------------
    channel, code = _refusal(lambda: ec2.modify_instance_credit_specification(
        InstanceCreditSpecifications=[
            {"InstanceId": instance_id, "CpuCredits": _INVALID_MODE}]))
    assert code == _EXPECTED_CODE, (
        f"CpuCredits is a closed enum of 'standard' and 'unlimited', so {_INVALID_MODE!r} must be "
        f"refused with {_EXPECTED_CODE!r}; real AWS refused it with {code!r} (via {channel})"
    )
    assert channel == _EXPECTED_CHANNEL, (
        f"real AWS reports an out-of-enum CpuCredits value as a per-instance entry in "
        f"UnsuccessfulInstanceCreditSpecifications under a 200 — the SDK call returns and raises "
        f"nothing — so a caller's try/except never fires; this target refused it with the right "
        f"code ({code!r}) on the wrong channel ({channel!r}), which changes the control flow of "
        f"every client written against the real service"
    )

    # --- and the effect is ABSENT -------------------------------------------
    after = _credit_mode(ec2, instance_id)
    assert after == "unlimited", (
        f"a refused modification must leave the credit specification untouched; {instance_id} was "
        f"'unlimited' before the rejected call to {_INVALID_MODE!r} and reports {after!r} after it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
