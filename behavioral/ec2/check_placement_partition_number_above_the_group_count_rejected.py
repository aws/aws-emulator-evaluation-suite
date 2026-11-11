"""placement-partition-number-above-the-group-count-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "placement-partition-number-above-the-group-count-rejected"
GROUP = 'placement-rejection'
SERVICES = ['ec2']

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
#: The cheapest type the model says supports the partition strategy, asserted before anything is
#: spent. A partition number is a property of the GROUP, not of the machine's size.
_ITYPE = "t3.micro"
#: A two-partition group, so exactly one integer above the last valid partition is asked for.
#: Derived from the group this check created rather than written as a limit: `_OUT_OF_RANGE` is
#: `_PARTITIONS + 1`, so the check states a relationship and not an AWS constant.
_PARTITIONS = 2
_OUT_OF_RANGE = _PARTITIONS + 1


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _expected_failure(fn, on_success):
    """Call `fn`; return its AWS error (code, message). An unexpected success raises.

    Whatever the call created is handed to `on_success` to register teardown before the raise.
    """
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    on_success(result)
    raise AssertionError(
        f"the request was expected to be refused, but it SUCCEEDED: {result!r}"
    )


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


def _retry_delete(fn, retries=450, delay=2.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded at fifteen minutes: a terminated instance's ENI can take that long to be released.
    """
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency",
                              "InvalidPlacementGroup.InUse") and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                              "InvalidPlacementGroup.Unknown"):
                return None
            raise


def _usable_az(ec2, itype):
    """The AZ to use: offered for `itype` AND reported available, intersected.

    Type offerings do not report zone state, and AZ names are per-account aliases.
    """
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"this region cannot run the check: no AVAILABLE availability zone offers {itype!r}; "
        f"offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _private_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with one subnet in `az` and no egress.

    Not the default VPC, which an account need not have; every piece is tagged at creation.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    return subnet


def _instance_states(ec2, ids):
    """State per id, with a terminated/absent instance reported as '__gone__'."""
    out = {i: "__gone__" for i in ids}
    try:
        pages = ec2.get_paginator("describe_instances").paginate(InstanceIds=list(ids))
        for page in pages:
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    out[inst["InstanceId"]] = inst["State"]["Name"]
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    return out


def _terminate_and_wait(ec2, ids, timeout_s=900):
    """Issue every terminate first, then wait once for all of them to reach 'terminated'.

    The ENI and placement-group membership only clear at 'terminated', which later deletes need.
    """
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=list(ids)))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        states = _instance_states(ec2, ids)
        if all(s in ("terminated", "__gone__") for s in states.values()):
            return
        time.sleep(2)


def _members(ec2, group_name):
    """Every non-terminated instance the API places in `group_name`, paginated."""
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[
            {"Name": "placement-group-name", "Values": [group_name]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]},
        ]
    ):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                found.append(inst["InstanceId"])
    return sorted(found)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Launching into partition 3 of a two-partition group is refused with InvalidParameterValue
    and creates nothing; the same launch into partition 2 succeeds and DescribeInstances records
    it there, so the bound comes from the group's PartitionCount, not the request alone.
    """
    ec2 = ctx.client("ec2")
    scenario = "placement-partition-range"

    # --- everything decidable, before anything is created ---------------------
    strategies = ec2.describe_instance_types(
        InstanceTypes=[_ITYPE])["InstanceTypes"][0]["PlacementGroupInfo"]["SupportedStrategies"]
    assert "partition" in strategies, (
        f"{_ITYPE!r} must support the partition strategy for this check to mean anything, but the "
        f"model reports {strategies!r}"
    )
    az = _usable_az(ec2, _ITYPE)
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    subnet = _private_vpc(ctx, ec2, az, scenario)

    pg = ctx.unique_name("sim2real-placement-range-")
    ec2.create_placement_group(
        GroupName=pg, Strategy="partition", PartitionCount=_PARTITIONS,
        TagSpecifications=[{"ResourceType": "placement-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_placement_group(GroupName=pg)))
    described = ec2.describe_placement_groups(GroupNames=[pg])["PlacementGroups"][0]
    assert described["PartitionCount"] == _PARTITIONS, (
        f"the group we just created does not have {_PARTITIONS!r} partitions: {described!r}"
    )
    assert _members(ec2, pg) == [], (
        f"a freshly created placement group must hold nothing: {_members(ec2, pg)!r}"
    )

    def _tag_spec(role):
        return [
            {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": f"{pg}-{role}"},
                                          {"Key": "sim2real", "Value": scenario}]}
            for rt in ("instance", "volume")
        ]

    # --- the one thing that is broken: a partition the group does not have ----
    def _register_unexpected(result):
        ids = [i["InstanceId"] for i in result.get("Instances", [])]
        if ids:
            ctx.on_cleanup(lambda: _terminate_and_wait(ec2, ids))

    code, message = _expected_failure(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            Placement={"GroupName": pg, "PartitionNumber": _OUT_OF_RANGE},
            TagSpecifications=_tag_spec("out-of-range"),
        ),
        _register_unexpected,
    )
    expected = (
        "InvalidParameterValue",
        f"Value '{_OUT_OF_RANGE}' is not a valid value for PartitionNumber. "
        f"Use a value between 1 and {_PARTITIONS}.",
    )
    assert (code, message) == expected, (
        f"launching into partition {_OUT_OF_RANGE!r} of a {_PARTITIONS!r}-partition group must be "
        f"refused with {expected!r}, got {(code, message)!r}"
    )
    assert _members(ec2, pg) == [], (
        f"the refused launch must have created nothing, but the group holds {_members(ec2, pg)!r}"
    )

    # --- the positive control: the highest partition the group DOES have ------
    control = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            Placement={"GroupName": pg, "PartitionNumber": _PARTITIONS},
            TagSpecifications=_tag_spec("control"),
        )
    )["Instances"][0]
    control_id = control["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, [control_id]))
    # RunInstances returns only the group id here (GroupName is ''), not the partition number;
    # the partition is asserted below off DescribeInstances, where AWS publishes it.
    assert control["Placement"].get("GroupId") == described["GroupId"], (
        f"the accepted launch must report the id of the group it was placed in "
        f"({described['GroupId']!r}), but its Placement reads {control['Placement']!r}"
    )

    _poll(lambda: _instance_states(ec2, [control_id]),
          lambda s: all(v in ("pending", "running") for v in s.values()),
          ctx=ctx, timeout_s=_budget_s(ctx, 300), interval_s=2.0,
          what=f"{control_id} being recorded as pending or running")
    assert _members(ec2, pg) == [control_id], (
        f"the group must hold exactly the one instance the control launched, but it holds "
        f"{_members(ec2, pg)!r}"
    )
    placements = []
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[control_id]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                placements.append(inst["Placement"])
    assert len(placements) == 1 and placements[0].get("PartitionNumber") == _PARTITIONS, (
        f"DescribeInstances must place the control in partition {_PARTITIONS!r} of {pg!r}: "
        f"{placements!r}"
    )
    assert placements[0].get("AvailabilityZone") == az, (
        f"the control must be in the derived zone {az!r}: {placements[0]!r}"
    )




    # Tear down inside the check's own budget: instances must reach 'terminated' before the network
    # and placement group can go, which outlasts the default cleanup window.
    ctx.run_cleanups()


# Instances and other ENI owners delete asynchronously, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc can fail with DependencyViolation until their ENIs go. Wait (bounded) for the ENIs,
# retry DependencyViolation in the same window, and raise naming any ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
