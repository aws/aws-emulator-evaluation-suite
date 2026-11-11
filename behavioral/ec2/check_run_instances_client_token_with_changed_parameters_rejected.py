"""run-instances-client-token-with-changed-parameters-rejected."""
from __future__ import annotations

import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-instances-client-token-with-changed-parameters-rejected"
GROUP = "concurrency"
SERVICES = ["ec2"]

_VPC_CIDR = "10.76.0.0/16"
_SUBNET_CIDR = "10.76.1.0/24"
_TYPE_A = "t3.micro"
_TYPE_B = "t3.small"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_ERR_MISMATCH = "IdempotentParameterMismatch"
_MISMATCH_MESSAGE = (
    "Arguments on this idempotent request are inconsistent with arguments used in previous request(s)."
)
_GONE_CODES = (
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidGroup.NotFound",
    "InvalidInstanceID.NotFound",
)
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Reusing a RunInstances ClientToken with the same request returns the same instance; with
    changed parameters it fails IdempotentParameterMismatch and creates nothing. The original still
    replays, and a fresh token with identical parameters launches a new instance.
    """
    ec2 = ctx.client("ec2")
    st: dict = {"instances": [], "sgs": [], "subnets": []}
    try:
        _build(ctx, ec2, st)
        _legs(ctx, ec2, st)
    finally:
        _teardown(ec2, st)


# ===== the legs ==============================================================


def _legs(ctx, ec2, st) -> None:
    token = ctx.unique_name("sim2real-b1token-")
    st["token"] = token

    def launch(*, instance_type=_TYPE_A, max_count=1, client_token=token):
        return ec2.run_instances(
            ImageId=st["ami"], InstanceType=instance_type, MinCount=1, MaxCount=max_count,
            SubnetId=st["subnet"], SecurityGroupIds=[st["sg"]], ClientToken=client_token,
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": _tags_for(st["name"])},
                {"ResourceType": "volume", "Tags": _tags_for(st["name"])},
            ],
        )

    # --- beat 1: the positive control. The original request succeeds. ---
    first = launch()
    assert len(first["Instances"]) == 1, (
        f"the original request asked for exactly one instance; RunInstances returned "
        f"{len(first['Instances'])}: {[i['InstanceId'] for i in first['Instances']]!r}"
    )
    original_id = first["Instances"][0]["InstanceId"]
    st["instances"].append(original_id)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[original_id]))
    assert first["Instances"][0]["InstanceType"] == _TYPE_A, (
        f"the original launch must report InstanceType {_TYPE_A!r}, got "
        f"{first['Instances'][0]['InstanceType']!r}"
    )
    # the eventually-consistent window: the id RunInstances minted is not immediately describable
    described = _poll(
        lambda: _describe(ec2, original_id),
        lambda i: i is not None,
        timeout_s=180.0, interval_s=5.0,
        what=f"{STATE_MARKER}: instance {original_id} becoming visible to DescribeInstances",
    )
    assert described["InstanceType"] == _TYPE_A, (
        f"DescribeInstances must report InstanceType {_TYPE_A!r} for {original_id}, got "
        f"{described['InstanceType']!r}"
    )

    # --- beat 1b: the identical request under the same token returns the SAME instance ---
    replay = launch()
    replay_ids = [i["InstanceId"] for i in replay["Instances"]]
    assert replay_ids == [original_id], (
        f"an identical retry under ClientToken {token!r} must return only the original instance "
        f"{original_id!r}, got {replay_ids!r}"
    )

    # --- beat 2: break exactly one thing — the instance type, same token ---
    err = _client_error(lambda: launch(instance_type=_TYPE_B))
    assert err.get("Code") == _ERR_MISMATCH, (
        f"reusing ClientToken {token!r} with InstanceType {_TYPE_B!r} instead of {_TYPE_A!r} must "
        f"be refused with {_ERR_MISMATCH}; got {err.get('Code')!r} ({err.get('Message')!r})"
    )
    assert err.get("Message") == _MISMATCH_MESSAGE, err.get("Message")

    # --- beat 3: effect absent, via an independent read (a filtered list, not the launch reply) ---
    live = _by_token(ec2, token)
    assert live == {original_id}, (
        f"the refused reuse must have created nothing: DescribeInstances filtered on client-token "
        f"{token!r} must report exactly {{{original_id!r}}}, got {sorted(live)!r}"
    )
    unchanged = _describe(ec2, original_id)
    assert unchanged is not None and unchanged["InstanceType"] == _TYPE_A, (
        f"the refused reuse must not have re-typed the original instance: expected InstanceType "
        f"{_TYPE_A!r} on {original_id}, got {unchanged!r}"
    )

    # --- beat 2b: a SECOND mutation, so a target cannot pass by special-casing InstanceType ---
    err2 = _client_error(lambda: launch(max_count=2))
    assert err2.get("Code") == _ERR_MISMATCH, (
        f"reusing ClientToken {token!r} with MaxCount=2 instead of 1 must be refused with "
        f"{_ERR_MISMATCH}; got {err2.get('Code')!r} ({err2.get('Message')!r})"
    )
    assert err2.get("Message") == _MISMATCH_MESSAGE, err2.get("Message")
    live2 = _by_token(ec2, token)
    assert live2 == {original_id}, (
        f"the second refused reuse must also have created nothing: expected "
        f"{{{original_id!r}}} for client-token {token!r}, got {sorted(live2)!r}"
    )

    # --- beat 4: restore. The IDENTICAL original request still works under the same token. ---
    restored = launch()
    restored_ids = [i["InstanceId"] for i in restored["Instances"]]
    assert restored_ids == [original_id], (
        f"after two rejected reuses the ORIGINAL request under ClientToken {token!r} must still "
        f"return {original_id!r}, got {restored_ids!r} — a target that invalidated the token on a "
        f"mismatch has turned a retry-safe API into a launch-twice API"
    )

    # --- the token is the key, not the request body: a fresh token must launch a NEW instance ---
    # A target deduplicating on request content passes every other leg and fails this one.
    other_token = ctx.unique_name("sim2real-b1token2-")
    second = launch(client_token=other_token)
    second_id = second["Instances"][0]["InstanceId"]
    st["instances"].append(second_id)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[second_id]))
    assert second_id != original_id, (
        f"byte-identical parameters under a DIFFERENT ClientToken {other_token!r} must launch a "
        f"new instance, not return {original_id!r} again — a target deduplicating on request "
        f"content instead of on the token loses a launch the caller paid for"
    )
    # the same eventually-consistent window beat 1 waited out for `original_id`: a client-token
    # filter on a just-minted instance is not guaranteed to be immediately queryable.
    live_second = _poll(
        lambda: _by_token(ec2, other_token),
        lambda ids: ids == {second_id},
        timeout_s=180.0, interval_s=5.0,
        what=f"{STATE_MARKER}: client-token {other_token!r} filter reflecting new instance {second_id}",
    )
    assert live_second == {second_id}, (
        f"DescribeInstances filtered on client-token {other_token!r} must report exactly "
        f"{{{second_id!r}}}, got {sorted(live_second)!r}"
    )
    assert _by_token(ec2, token) == {original_id}, (
        f"the first token must still resolve to exactly {{{original_id!r}}} after the second "
        f"launch, got {sorted(_by_token(ec2, token))!r}"
    )


# ===== the fixture ===========================================================


def _build(ctx, ec2, st) -> None:
    """A VPC and one private subnet of this check's own making, with no internet gateway."""
    name = ctx.unique_name("sim2real-b1tok-")
    st["name"] = name

    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_for(name)}],
    )["Vpc"]["VpcId"]
    st["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _tolerate_gone(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # ONE zone that offers BOTH types, so the mismatch leg's rejection cannot be about capacity or
    # about the type not existing here — the only thing wrong with that request is the token.
    shared = sorted(_zones_offering(ec2, _TYPE_A) & _zones_offering(ec2, _TYPE_B))
    assert shared, (
        f"need an available zone offering BOTH {_TYPE_A!r} and {_TYPE_B!r} in {ctx.region}: "
        f"{_TYPE_A} is offered in {sorted(_zones_offering(ec2, _TYPE_A))!r} and {_TYPE_B} in "
        f"{sorted(_zones_offering(ec2, _TYPE_B))!r}"
    )
    az = shared[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_for(name)}],
    )["Subnet"]["SubnetId"]
    st["subnets"].append(subnet_id)
    st["subnet"] = subnet_id
    ctx.on_cleanup(lambda: _tolerate_gone(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        GroupName=name + "-sg", VpcId=vpc_id,
        Description="sim2real RunInstances ClientToken mismatch check",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(name)}],
    )["GroupId"]
    st["sgs"].append(sg_id)
    st["sg"] = sg_id

    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    st["ami"] = ami


# ===== in-band teardown ======================================================


def _assert_absent(listed):
    """Teardown step: a deleted resource must no longer be listed."""
    if listed:
        raise AssertionError(f"still describable after its delete: {listed!r}")


def _teardown(ec2, st) -> None:
    """Ordered teardown with waits too long for the default cleanup window. Runs every step, then
    raises what it could not remove."""
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    for iid in st.get("instances", []):
        _step(f"instance {iid}", lambda i=iid: ec2.terminate_instances(InstanceIds=[i]))
    for iid in st.get("instances", []):
        _step(f"instance-wait {iid}", lambda i=iid: _poll(
            lambda: _state(ec2, i), lambda s: s in ("terminated", "__gone__"),
            timeout_s=600.0, interval_s=5.0, what=f"instance {i} reaching 'terminated'"))
    if st.get("vpc"):
        _step("eni-drain", lambda: _poll(
            lambda: _vpc_enis(ec2, st["vpc"]), lambda enis: enis == [],
            timeout_s=420.0, interval_s=10.0, what=f"every ENI in {st['vpc']!r} draining"))
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


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    """Bounded retry that RAISES on timeout — never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


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
    """The instance dict, or None while it is still eventually-consistently invisible."""
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _by_token(ec2, token):
    """Non-terminated instance ids DescribeInstances attributes to this client token."""
    found = set()
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "client-token", "Values": [token]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] != "terminated":
                    found.add(inst["InstanceId"])
    return found


def _vpc_enis(ec2, vpc_id):
    return [
        eni["NetworkInterfaceId"]
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        for eni in page["NetworkInterfaces"]
    ]


def _zones_offering(ec2, instance_type):
    """Available AZ names that offer instance_type — read from the region, never hardcoded."""
    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    return {
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
