"""placement-partition-group-serves-distinct-partition-numbers-to-the-guests."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "placement-partition-group-serves-distinct-partition-numbers-to-the-guests"
GROUP = 'placement-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: The smallest type that carries this contract. Unlike the cluster strategy -- which burstable
#: types do not support at all -- partition placement is supported by t3, and the check asserts
#: that from the model before it spends anything. Nothing about a partition number depends on the
#: size of the machine, so the cheapest supported one is the honest choice.
_ITYPE = "t3.micro"
#: Three partitions, two used. The unused one matters: it proves the two instances were PLACED in
#: distinct partitions rather than simply filling the only two that existed.
_PARTITIONS = 3
_USED = (1, 3)

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


def _retry_delete(fn, retries=90, delay=10.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded at fifteen minutes: a DependencyViolation that never clears is a leak to declare,
    not a loop to sit in -- but the two minutes this allowed before was not enough for a
    terminated instance's ENI to be released, and every delete behind it was abandoned.
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
    """The AZ to use: offered for `itype` AND reported available, intersected.

    Both halves are load-bearing. `describe_instance_type_offerings` does not report zone state,
    so an impaired zone still appears as offering the type; `describe_availability_zones` says
    nothing about instance types. A literal AZ name would be a capacity gamble wearing a fixed
    name, since AZ names are per-account aliases for different physical zones.
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
    """A VPC of this check's own making, with one public subnet in `az`.

    Not the account's default VPC, which a fresh account need not have. The SSM agent needs egress
    to its endpoint, so the subnet gets an internet gateway, a default route and public addressing.
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
    role = ctx.unique_name("sim2real-plp-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav partition-group guest role",
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
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
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
    """Issue every terminate FIRST, then wait once for all of them.

    Waiting for 'terminated' rather than 'shutting-down' is required: the ENIs, the placement-group
    membership and the instance-profile association only clear at the end, and the subnet and
    placement-group teardown registered earlier cannot proceed until they do.
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
        time.sleep(10)


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects
    SendCommand with InvalidInstanceId until its agent has registered, so retrying that call polls
    an observable condition instead of sleeping a guessed interval. A host that never accepts a
    command is a FAIL -- 'the machine never came up' is the fidelity defect this check exists to
    catch, not an environment limitation.
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
                Comment="sim2real-behav placement group guest read",
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
                timeout_s=run_timeout_s, interval_s=5.0,
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


#: What the guest itself says about its placement, read from IMDS inside the machine. `field`
#: prints `__http<code>` instead of a body on any non-200, which keeps the output parseable AND
#: makes an absent category readable as a value -- `placement/partition-number` is served only to
#: an instance that really is in a partition group, so a 404 here is a finding, not a parse error.
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

# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Two instances launched into partitions 1 and 3 of a three-partition placement group each read
    their own partition number, group name and zone from IMDS inside the guest, distinct and equal to
    the requested ones, so the placement reaches the machine and not just the instance record."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "placement-partition-guest-imds"

    # --- everything decidable, before anything is created ---------------------
    strategies = ec2.describe_instance_types(
        InstanceTypes=[_ITYPE])["InstanceTypes"][0]["PlacementGroupInfo"]["SupportedStrategies"]
    assert "partition" in strategies, (
        f"{_ITYPE!r} must support the partition strategy for this check to mean anything, but the "
        f"model reports {strategies!r}"
    )
    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    subnet = _public_vpc(ctx, ec2, az, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    pg = ctx.unique_name("sim2real-placement-partition-")
    ec2.create_placement_group(
        GroupName=pg, Strategy="partition", PartitionCount=_PARTITIONS,
        TagSpecifications=[{"ResourceType": "placement-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_placement_group(GroupName=pg)))
    described = ec2.describe_placement_groups(GroupNames=[pg])["PlacementGroups"][0]
    assert described["Strategy"] == "partition", (
        f"the group we just created is not a partition group: {described!r}"
    )
    assert described["PartitionCount"] == _PARTITIONS, (
        f"the group reports {described.get('PartitionCount')!r} partitions, not {_PARTITIONS!r}: "
        f"{described!r}"
    )

    # --- one instance per requested partition ---------------------------------
    launched = {}
    for partition in _USED:
        # A brand-new instance profile is not immediately resolvable by RunInstances.
        inst = _call_with_retry(
            lambda partition=partition: ec2.run_instances(
                ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
                IamInstanceProfile={"Name": profile},
                Placement={"GroupName": pg, "PartitionNumber": partition},
                TagSpecifications=[
                    {"ResourceType": rt,
                     "Tags": [{"Key": "Name", "Value": f"{profile}-p{partition}"},
                              {"Key": "sim2real", "Value": scenario}]}
                    for rt in ("instance", "volume")
                ],
            ),
            codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
        )["Instances"][0]
        iid = inst["InstanceId"]
        ctx.on_cleanup(lambda iid=iid: _terminate_and_wait(ec2, [iid]))
        launched[partition] = iid

    all_ids = sorted(launched.values())
    _poll(lambda: _instance_states(ec2, all_ids),
          lambda s: all(v == "running" for v in s.values()),
          timeout_s=900, interval_s=10.0, what=f"{all_ids!r} all reaching 'running'")

    # --- the control plane's own account of the placement ---------------------
    api_partition = {}
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=all_ids):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                api_partition[inst["InstanceId"]] = inst["Placement"]
    for partition, iid in launched.items():
        assert api_partition[iid].get("GroupName") == pg, (
            f"DescribeInstances does not place {iid} in {pg!r}: {api_partition[iid]!r}"
        )
        assert api_partition[iid].get("PartitionNumber") == partition, (
            f"DescribeInstances reports {iid} in partition "
            f"{api_partition[iid].get('PartitionNumber')!r}, not the requested {partition!r}"
        )

    # --- what the GUESTS say: their own partition, from inside ----------------
    guest = {}
    for partition, iid in launched.items():
        out = _run_guest(ssm, iid, _IMDS_FACTS, f"reading IMDS placement facts on {iid}")
        recs = _reports(out, "SIM2REAL-IMDS")
        assert len(recs) == 1, f"the guest on {iid} did not report one IMDS line; stdout={out!r}"
        assert recs[0].get("id") == iid, (
            f"the guest that answered for {iid} reports instance-id {recs[0].get('id')!r}; the "
            f"measurement would be about a different machine"
        )
        guest[partition] = recs[0]

    for partition, iid in launched.items():
        assert guest[partition]["partition"] == str(partition), (
            f"the guest on {iid} reads its own IMDS placement/partition-number as "
            f"{guest[partition]['partition']!r}, not the requested {partition!r} -- the placement "
            f"decision reached the instance record but not the machine"
        )
        assert guest[partition]["group"] == pg, (
            f"the guest on {iid} reads its own placement group as {guest[partition]['group']!r} "
            f"from IMDS, not {pg!r}"
        )
        assert guest[partition]["az"] == az, (
            f"the guest on {iid} reports zone {guest[partition]['az']!r}, not the derived {az!r}"
        )

    read_numbers = sorted(g["partition"] for g in guest.values())
    assert len(set(read_numbers)) == len(_USED), (
        f"instances placed in distinct partitions must read distinct partition numbers from "
        f"inside the guest, but they read {read_numbers!r}"
    )
    assert read_numbers == sorted(str(p) for p in _USED), (
        f"the guests read {read_numbers!r} where partitions {sorted(_USED)!r} were requested"
    )



    # Teardown runs here, inside the check's own budget: the instances must reach 'terminated'
    # before the security group, subnet, gateway, VPC and placement group can go, which outlasts
    # the default cleanup window. On any failure path above the same LIFO chain still runs.
    ctx.run_cleanups()


# Network teardown: an async delete's AWS-managed ENIs hold the subnet / security group / VPC in
# DependencyViolation, so wait for them to go and retry DependencyViolation to one deadline shared by
# all of a check's network deletes (within the suite cleanup budget), then raise naming the ENIs left.
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
