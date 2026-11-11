"""placement-spread-group-rejects-more-instances-than-one-zone-can-place."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "placement-spread-group-rejects-more-instances-than-one-zone-can-place"
GROUP = 'placement-rejection'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: The cheapest type the model says supports the spread strategy; a spread group places one
#: instance per distinct rack, which is a property of the GROUP and not of the machine's size.
_ITYPE = "t3.micro"
#: One more than the fixed per-zone spread ceiling (seven; not a Service Quota). Requested via
#: MinCount so the refusal is atomic: EC2 places all of them or creates nothing.
_OVER_CEILING = 8

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _expected_failure(fn, on_success):
    """Call `fn`; return its AWS error (code, message). An unexpected success raises, after handing
    the result to `on_success` so whatever it created gets a teardown."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message", "")
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

    Bounded at fifteen minutes; a terminated instance's ENI can take minutes to be released.
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
                              "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                              "InvalidAssociationID.NotFound", "InvalidGroup.NotFound",
                              "InvalidPlacementGroup.Unknown", "Gateway.NotAttached"):
                return None
            raise


def _usable_az(ec2, itype):
    """The AZ to use: offered for `itype` AND reported available.

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


def _public_vpc(ctx, ec2, az, scenario):
    """A VPC of this check's own making, with one public subnet in `az` (the ceiling is per zone).

    The SSM agent needs egress, so the subnet gets an internet gateway and public addressing.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return subnet


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-pls-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav spread-group guest role",
                    Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": scenario}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(30):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 29:
                raise
            time.sleep(2)
    for attempt in range(30):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    for attempt in range(30):
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 29:
                raise
            time.sleep(2)


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

    ENIs and placement-group membership only clear at 'terminated', which later deletes need.
    """
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=list(ids)))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        states = _instance_states(ec2, ids)
        last = states
        if all(s in ("terminated", "__gone__") for s in states.values()):
            return
        time.sleep(2)
    raise RuntimeError(f"instances {list(ids)} were not terminated: {last!r}")


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


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    A just-booted host rejects SendCommand with InvalidInstanceId until its agent registers, so the
    retry is the wait for the agent.
    """
    deadline = time.monotonic() + _budget_s(ctx, ready_timeout_s)
    sent = None
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": script},
                TimeoutSeconds=600,
                Comment="sim2real-behav placement group guest read",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and _budget_spent(ctx):
                raise TimeoutError(f"{what}: SendCommand to {instance_id} being accepted: the run "
                                   "budget ended first; not graded") from exc
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
                ctx=ctx, timeout_s=_budget_s(ctx, run_timeout_s), interval_s=2.0,
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


def _reports(stdout, marker):
    """Every `key=value` line starting with `marker`, parsed, in order."""
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith(marker):
            continue
        rec = {}
        for field in line[len(marker):].split():
            if "=" in field:
                k, _, v = field.partition("=")
                rec[k] = v
        out.append(rec)
    return out


#: The guest's placement as read from IMDS. `field` prints `__http<code>` on any non-200 so an
#: absent category (a spread member has no partition-number) is readable as a value.
_IMDS_FACTS = [
    "set -uo pipefail",
    'TOK=$(curl -sS -X PUT --max-time 5 --retry 3'
    ' -H "X-aws-ec2-metadata-token-ttl-seconds: 120"'
    ' http://169.254.169.254/latest/api/token)',
    'get() { curl -sS --max-time 5 -o /tmp/imds.body -w "%{http_code}"'
    ' -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/$1"; }',
    'field() { c=$(get "$1");'
    ' if [ "$c" = "200" ]; then tr -d "\\n" </tmp/imds.body; else printf "__http%s" "$c"; fi; }',
    'ID=$(field instance-id)',
    'AZ=$(field placement/availability-zone)',
    'GRP=$(field placement/group-name)',
    'PART=$(field placement/partition-number)',
    'echo "SIM2REAL-IMDS id=$ID az=$AZ group=$GRP partition=$PART"',
]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A spread group refuses 8 instances in one AZ with InsufficientInstanceCapacity and creates none,
    while one instance in the same group and subnet launches and its IMDS reports the group and no
    partition number.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-strategies.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "placement-spread-ceiling"

    strategies = ec2.describe_instance_types(
        InstanceTypes=[_ITYPE])["InstanceTypes"][0]["PlacementGroupInfo"]["SupportedStrategies"]
    assert "spread" in strategies, (
        f"{_ITYPE!r} must support the spread strategy for this check to mean anything, but the "
        f"model reports {strategies!r}"
    )
    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    pg = ctx.unique_name("sim2real-placement-spread-")
    ec2.create_placement_group(
        GroupName=pg, Strategy="spread",
        TagSpecifications=[{"ResourceType": "placement-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_placement_group(GroupName=pg)))
    described = ec2.describe_placement_groups(GroupNames=[pg])["PlacementGroups"][0]
    assert described["Strategy"] == "spread" and described["State"] == "available", (
        f"the group we just created is not an available spread group: {described!r}"
    )
    assert "PartitionCount" not in described, (
        f"a spread group has no partitions, but the API reports one: {described!r}"
    )
    assert _members(ec2, pg) == [], (
        f"a freshly created placement group must hold nothing: {_members(ec2, pg)!r}"
    )

    def _tag_spec(role):
        return [
            {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": f"{profile}-{role}"},
                                          {"Key": "sim2real", "Value": scenario}]}
            for rt in ("instance", "volume")
        ]

    def _register_unexpected(result):
        ids = [i["InstanceId"] for i in result.get("Instances", [])]
        if ids:
            ctx.on_cleanup(lambda: _terminate_and_wait(ec2, ids))

    # No instance profile here: a just-created profile can make RunInstances refuse with
    # InvalidParameterValue, which would mask the placement refusal under test.
    code, message = _expected_failure(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE,
            MinCount=_OVER_CEILING, MaxCount=_OVER_CEILING,
            SubnetId=subnet,
            Placement={"GroupName": pg}, TagSpecifications=_tag_spec("over-ceiling"),
        ),
        _register_unexpected,
    )
    assert code == "InsufficientInstanceCapacity", (
        f"asking a spread placement group for {_OVER_CEILING} instances in one availability zone "
        f"must be refused with InsufficientInstanceCapacity, got {code!r}"
    )
    assert message == (
        "You've reached the limit of instances in this spread placement group. A spread placement "
        "group can have up to seven instances per Availability Zone."
    ), message
    assert _members(ec2, pg) == [], (
        f"the refused launch must have created nothing, but the group holds "
        f"{_members(ec2, pg)!r}"
    )

    # A brand-new instance profile is not immediately resolvable by RunInstances.
    control = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            IamInstanceProfile={"Name": profile}, Placement={"GroupName": pg},
            TagSpecifications=_tag_spec("control"),
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
    )["Instances"][0]
    control_id = control["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, [control_id]))

    _poll(lambda: _instance_states(ec2, [control_id]),
          lambda s: all(v == "running" for v in s.values()),
          ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2.0,
          what=f"{control_id} reaching 'running'")
    assert _members(ec2, pg) == [control_id], (
        f"the group must hold exactly the one instance the control launched, but it holds "
        f"{_members(ec2, pg)!r}"
    )

    out = _run_guest(ctx, ssm, control_id, _IMDS_FACTS,
                     f"reading IMDS placement facts on {control_id}")
    recs = _reports(out, "SIM2REAL-IMDS")
    assert len(recs) == 1, f"the guest on {control_id} did not report one IMDS line; stdout={out!r}"
    facts = recs[0]
    assert facts.get("id") == control_id, (
        f"the guest that answered for {control_id} reports instance-id {facts.get('id')!r}; the "
        f"reading would be about a different machine"
    )
    assert facts["group"] == pg, (
        f"the guest on {control_id} reads its own placement group as {facts['group']!r} from IMDS, "
        f"not {pg!r} -- the placement reached the instance record but not the machine"
    )
    assert facts["az"] == az, (
        f"the guest on {control_id} reports zone {facts['az']!r}, not the derived {az!r}"
    )
    assert facts["partition"] == "__http404", (
        f"a spread group has no partitions, so IMDS must not serve placement/partition-number to "
        f"its member, but the guest on {control_id} read {facts['partition']!r}"
    )



    # Run teardown inside the check's budget: instances must reach 'terminated' before the network
    # and placement group can be deleted, which takes longer than the default cleanup bound.
    ctx.run_cleanups()


# Network deletes wait (bounded) for AWS-managed ENIs to leave: resources in the VPC delete
# asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
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
