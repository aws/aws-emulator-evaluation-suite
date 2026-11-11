"""spotint-one-time-spot-request-refuses-interruption-behavior-stop."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "spotint-one-time-spot-request-refuses-interruption-behavior-stop"
GROUP = 'spot-interruption'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE = "t3.micro"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_VPC_CIDR = "10.185.0.0/16"
_SUBNET_CIDR = "10.185.1.0/24"
#: Both requests in this file are priced far below market ON PURPOSE: the subject is the
#: *acceptance* decision, so neither arm — not even the positive control — may ever be fulfilled
#: into a billable instance. `price-too-low` is asserted in a sibling check; here it is a guard.
_UNFULFILLABLE_PRICE = "0.001"

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
    """An AZ that is BOTH 'available' and offers instance_type — neither call answers both.

    An empty intersection means this region cannot run the check at all, which is a finding rather
    than an AZ to guess at, so it is asserted instead of defaulted.
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
    """A dedicated VPC with one subnet and one security group, built rather than borrowed.

    A fresh account may have no default VPC, so a check that reaches for one is overfitted to this
    account. Every resource is tagged in the same call that creates it, because an untagged EC2
    resource cannot be found for cleanup.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-spotint-"), VpcId=vpc_id,
        Description="sim2real spot-interruption request validation",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _requests_tagged(ec2, marker):
    """Every spot request carrying our one-run marker tag, off a PAGINATED describe.

    Scoped to a tag only this run mints, so the assertion is about what THIS check created and not
    about the account being otherwise empty — a sibling suite's spot requests are invisible to it.
    """
    found = []
    for page in ec2.get_paginator("describe_spot_instance_requests").paginate(
            Filters=[{"Name": "tag:sim2real-spotint-run", "Values": [marker]}]):
        found.extend(page["SpotInstanceRequests"])
    return found


def _cancel_quietly(ec2, request_id):
    try:
        _call_with_retry(
            lambda: ec2.cancel_spot_instance_requests(SpotInstanceRequestIds=[request_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidSpotInstanceRequestID.NotFound":
            raise


def _reap_tagged_requests(ec2, marker):
    """Cancel anything carrying our marker, whatever id it got.

    The teardown is written against the TAG rather than against a captured id so that a target which
    wrongly accepts the rejected request still gets that request cleaned up: the arm under test is
    the one whose id we never learn.
    """
    for req in _requests_tagged(ec2, marker):
        if req["State"] in ("open", "active"):
            _cancel_quietly(ec2, req["SpotInstanceRequestId"])


# ===== end helpers =====


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RequestSpotInstances with Type 'one-time' and InstanceInterruptionBehavior 'stop' is rejected
    InvalidParameterCombination and creates no request (proved against a warm tag filter), while the same
    specification as 'persistent' is accepted and carries the behaviour on the request record."""
    scenario = "spotint-interruption-behavior-validation"
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-spotint-run-")
    ctx.on_cleanup(lambda: _reap_tagged_requests(ec2, marker))

    subnet_id, sg_id, az = _network(ctx, scenario)
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"

    launch_spec = {
        "ImageId": ami,
        "InstanceType": _INSTANCE_TYPE,
        "SubnetId": subnet_id,
        "SecurityGroupIds": [sg_id],
    }
    request_tags = [{"ResourceType": "spot-instances-request", "Tags": [
        {"Key": "sim2real", "Value": scenario},
        {"Key": "sim2real-spotint-run", "Value": marker},
    ]}]

    # --- the rejection -----------------------------------------------------------------------------
    try:
        accepted = ec2.request_spot_instances(
            Type="one-time", InstanceInterruptionBehavior="stop",
            SpotPrice=_UNFULFILLABLE_PRICE, InstanceCount=1,
            LaunchSpecification=launch_spec, TagSpecifications=request_tags,
        )["SpotInstanceRequests"]
    except ClientError as exc:
        assert _code(exc) == "InvalidParameterCombination", (
            f"a one-time request asking for InstanceInterruptionBehavior 'stop' must be rejected "
            f"with exactly 'InvalidParameterCombination'; got {_code(exc)!r}: "
            f"{exc.response.get('Error', {}).get('Message')!r}"
        )
        expected_message = (
            "The request with type 'one-time' is not supported when "
            "instanceInterruptionBehavior is set to 'stop'."
        )
        assert exc.response.get("Error", {}).get("Message") == expected_message, (
            f"expected message {expected_message!r}, got "
            f"{exc.response.get('Error', {}).get('Message')!r}"
        )
    else:
        raise AssertionError(
            f"RequestSpotInstances accepted Type='one-time' with "
            f"InstanceInterruptionBehavior='stop' and returned "
            f"{[r.get('SpotInstanceRequestId') for r in accepted]!r}. A one-time request is "
            f"consumed by its single fulfilment and cannot restart a stopped instance, so "
            f"accepting the combination promises an interruption behaviour that cannot be performed."
        )

    # --- the effect must be ABSENT: the rejected call created nothing ------------------------------
    # Read twice: once here, and once after the control has proven the tag index is warm. This first
    # read is the cheap one and cannot distinguish "nothing was created" from "not indexed yet"; the
    # exactly-one assertion at the end of the file is the assertion that can.
    leftover = _requests_tagged(ec2, marker)
    assert leftover == [], (
        f"the rejected request must leave no spot request behind, but a describe filtered to this "
        f"run's marker tag found "
        f"{[(r['SpotInstanceRequestId'], r['State'], r['Status']['Code']) for r in leftover]!r}"
    )

    # --- positive control, in this file: only the Type differs -------------------------------------
    control = ec2.request_spot_instances(
        Type="persistent", InstanceInterruptionBehavior="stop",
        SpotPrice=_UNFULFILLABLE_PRICE, InstanceCount=1,
        LaunchSpecification=launch_spec, TagSpecifications=request_tags,
    )["SpotInstanceRequests"]
    assert len(control) == 1, (
        f"InstanceCount=1 must mint exactly one request, got {len(control)}: {control!r}"
    )
    control_id = control[0]["SpotInstanceRequestId"]
    # A persistent request keeps retrying forever if abandoned, so the cancel is registered before
    # anything else is asserted about it.
    ctx.on_cleanup(lambda: _cancel_quietly(ec2, control_id))

    assert control[0]["Type"] == "persistent", (
        f"the control request must come back Type='persistent', got {control[0].get('Type')!r}"
    )
    assert control[0]["InstanceInterruptionBehavior"] == "stop", (
        f"a persistent request must carry the interruption behaviour it asked for; expected 'stop', "
        f"got {control[0].get('InstanceInterruptionBehavior')!r}"
    )
    assert control[0]["State"] == "open", (
        f"a freshly created, unfulfillable request is 'open'; got {control[0]['State']!r} "
        f"({control[0].get('Status')!r})"
    )
    assert control[0]["LaunchSpecification"]["SubnetId"] == subnet_id, (
        f"the control request must be bound to the subnet it was given ({subnet_id!r} in {az!r}), "
        f"got {control[0]['LaunchSpecification'].get('SubnetId')!r}"
    )
    assert "InstanceId" not in control[0], (
        f"an unfulfilled request names no instance; it reported "
        f"{control[0].get('InstanceId')!r}"
    )

    # The same absence oracle, now proven capable of seeing a request that WAS created — without
    # this, the assertion above would also pass if the filter simply never returned anything.
    # EC2's tag index is eventually consistent (measured: the control took ~10 s to appear), so this
    # waits for the tag filter to warm up and only then reads its full membership.
    found = _poll(lambda: _requests_tagged(ec2, marker), lambda rs: rs != [],
                  timeout_s=180, interval_s=5.0,
                  what=f"the marker-tag describe seeing the accepted control request {control_id}")
    assert [r["SpotInstanceRequestId"] for r in found] == [control_id], (
        f"once the tag index is warm it must show exactly the one request this check created — the "
        f"accepted control {control_id!r} — and nothing from the rejected arm; it showed "
        f"{[(r['SpotInstanceRequestId'], r['State'], r['Status']['Code']) for r in found]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
