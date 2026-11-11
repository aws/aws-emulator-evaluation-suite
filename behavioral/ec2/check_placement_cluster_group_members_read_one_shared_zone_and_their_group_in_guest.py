"""placement-cluster-group-members-read-one-shared-zone-and-their-group-in-guest."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "placement-cluster-group-members-read-one-shared-zone-and-their-group-in-guest"
GROUP = 'placement-data-plane'
SERVICES = ['ec2']

_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: Burstable types do not support cluster placement groups at all, so a non-burstable type is
#: required; the check asserts that support from the model before launching.
_ITYPE = "c5.large"
#: Packets per round: 20 at 50 ms is enough for the minimum RTT to settle.
_PACKETS = 20

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


def _retry_delete(fn, retries=450, delay=2.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind.

    Bounded at fifteen minutes: a terminated instance's ENI can take minutes to be released.
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
    """A VPC of this check's own making, with one public subnet in `az`.

    The SSM agent needs egress to reach its endpoint, hence the internet gateway and public IPs.
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
    return vpc, subnet


def _icmp_sg(ctx, ec2, vpc, scenario):
    """A security group that admits ICMP from itself; default egress lets the SSM agent out."""
    sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-placement-sg-"),
        Description="sim2real placement-group guest RTT measurement",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg)))
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[{"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1,
                        "UserIdGroupPairs": [{"GroupId": sg}]}],
    )
    return sg


def _instance_profile(ctx, iam, scenario):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name("sim2real-plc-")[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav placement-group guest role",
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
    """Terminate all instances, then wait for 'terminated'.

    ENIs and placement-group membership only clear then, and network teardown depends on that.
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


def _wait_agents_online(ssm, ids, timeout_s=600):
    """Every instance's SSM agent reaching PingStatus Online; a host that never registers fails."""
    def _online():
        seen = {}
        for page in ssm.get_paginator("describe_instance_information").paginate():
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") in ids:
                    seen[info["InstanceId"]] = info.get("PingStatus")
        return seen

    return _poll(_online, lambda s: all(s.get(i) == "Online" for i in ids),
                 timeout_s=timeout_s, interval_s=2.0,
                 what=f"the SSM agents on {sorted(ids)!r} all coming Online")


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=600, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand returns InvalidInstanceId until the agent registers, so its retry is the wait.
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


#: The guest's own placement facts from IMDS. `field` prints `__http<code>` on any non-200, so an
#: absent category (no placement/group-name outside a group) reads as a value.
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
    'echo "SIM2REAL-IMDS id=$ID az=$AZ group=$GRP"',
]

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "dp:native", "plane:data")
def run(ctx) -> None:
    """Inside the guests, two cluster placement group members read one shared AZ and their group
    name from IMDS, an ungrouped instance in the same subnet reads no group name, and in-guest
    ping between the members and to the outsider loses no packets."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    scenario = "placement-cluster-guest-rtt"

    # --- everything decidable, before anything is created ---------------------
    itype_model = ec2.describe_instance_types(InstanceTypes=[_ITYPE])["InstanceTypes"][0]
    strategies = itype_model["PlacementGroupInfo"]["SupportedStrategies"]
    assert "cluster" in strategies, (
        f"{_ITYPE!r} must support the cluster strategy for this check to mean anything, but the "
        f"model reports {strategies!r}"
    )
    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 parameter did not resolve to an AMI: {ami!r}"

    vpc, subnet = _public_vpc(ctx, ec2, az, scenario)
    sg = _icmp_sg(ctx, ec2, vpc, scenario)
    profile = _instance_profile(ctx, iam, scenario)

    pg = ctx.unique_name("sim2real-placement-cluster-")
    ec2.create_placement_group(
        GroupName=pg, Strategy="cluster",
        TagSpecifications=[{"ResourceType": "placement-group",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_placement_group(GroupName=pg)))
    described = ec2.describe_placement_groups(GroupNames=[pg])["PlacementGroups"][0]
    assert described["Strategy"] == "cluster" and described["State"] == "available", (
        f"the group we just created is not an available cluster group: {described!r}"
    )

    def _tag_spec(role):
        return [
            {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": f"{profile}-{role}"},
                                          {"Key": "sim2real", "Value": scenario}]}
            for rt in ("instance", "volume")
        ]

    # --- two members of the group, launched together --------------------------
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    members = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=2, MaxCount=2, SubnetId=subnet,
            SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
            Placement={"GroupName": pg}, TagSpecifications=_tag_spec("member"),
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
    )["Instances"]
    member_ids = [i["InstanceId"] for i in members]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, member_ids))
    assert len(member_ids) == 2, f"asked for exactly two group members, got {members!r}"

    # --- one instance outside the group, same subnet, same zone, same type ----
    outsider = _call_with_retry(
        lambda: ec2.run_instances(
            ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
            SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
            TagSpecifications=_tag_spec("outsider"),
        ),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
    )["Instances"][0]
    outsider_id = outsider["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, [outsider_id]))

    all_ids = member_ids + [outsider_id]
    _poll(lambda: _instance_states(ec2, all_ids),
          lambda s: all(v == "running" for v in s.values()),
          ctx=ctx, timeout_s=_budget_s(ctx, 900), interval_s=2.0,
          what=f"{all_ids!r} all reaching 'running'")

    # --- the control plane's own account of the placement ---------------------
    api_view = {}
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=all_ids):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                api_view[inst["InstanceId"]] = (inst["Placement"], inst.get("PrivateIpAddress"))
    for mid in member_ids:
        assert api_view[mid][0].get("GroupName") == pg, (
            f"DescribeInstances does not place member {mid} in {pg!r}: {api_view[mid][0]!r}"
        )
    assert not api_view[outsider_id][0].get("GroupName"), (
        f"the outsider {outsider_id} must belong to no placement group, but DescribeInstances "
        f"reports {api_view[outsider_id][0]!r}"
    )

    # --- what the GUESTS say: same zone, own group name -----------------------
    guest = {}
    for iid in all_ids:
        out = _run_guest(ctx, ssm, iid, _IMDS_FACTS, f"reading IMDS placement facts on {iid}")
        recs = _reports(out, "SIM2REAL-IMDS")
        assert len(recs) == 1, f"the guest on {iid} did not report one IMDS line; stdout={out!r}"
        guest[iid] = recs[0]
        assert recs[0].get("id") == iid, (
            f"the guest that answered for {iid} reports instance-id {recs[0].get('id')!r}; the "
            f"measurement would be about a different machine"
        )

    for mid in member_ids:
        assert guest[mid]["group"] == pg, (
            f"the guest on cluster member {mid} reads its own placement group as "
            f"{guest[mid]['group']!r} from IMDS, not {pg!r}"
        )
    assert guest[outsider_id]["group"] == "__http404", (
        f"an instance in no placement group must have no IMDS placement/group-name, but the guest "
        f"on {outsider_id} read {guest[outsider_id]['group']!r}"
    )
    zones = {iid: guest[iid]["az"] for iid in all_ids}
    assert zones[member_ids[0]] == zones[member_ids[1]] == az, (
        f"a cluster group's members must be in ONE availability zone; the guests report "
        f"{zones!r} against the derived zone {az!r}"
    )
    assert zones[outsider_id] == az, (
        f"the comparison is only fair if the outsider shares the zone; the guests report {zones!r}"
    )

    # --- what the guest MEASURES: the members reach each other, and at what cost
    peer_ip = api_view[member_ids[1]][1]
    outsider_ip = api_view[outsider_id][1]
    assert peer_ip and outsider_ip, (
        f"both targets need a private address to ping; got peer={peer_ip!r} "
        f"outsider={outsider_ip!r}"
    )
    rtt_script = [
        "set -uo pipefail",
        f'PEER={peer_ip}',
        f'OUT={outsider_ip}',
        'measure() {',
        f'  o=$(ping -c {_PACKETS} -i 0.05 -W 1 -q "$2" 2>&1)'
        ' || { echo "SIM2REAL-RTT target=$1 ok=0"; return 0; }',
        '  loss=$(printf "%s\\n" "$o"'
        ' | sed -n "s/.*, \\([0-9.]*\\)% packet loss.*/\\1/p" | head -1)',
        '  r=$(printf "%s\\n" "$o"'
        ' | sed -n "s|^rtt min/avg/max/mdev = \\([^ ]*\\) ms.*|\\1|p")',
        '  echo "SIM2REAL-RTT target=$1 ok=1 loss=$loss'
        ' min=$(printf %s "$r" | cut -d/ -f1) avg=$(printf %s "$r" | cut -d/ -f2)"',
        '}',
        # Warm up the ARP entry for each target so the first packet of a measured round is not the
        # one that pays for address resolution.
        'ping -c 3 -i 0.2 -q -W 2 "$PEER" >/dev/null 2>&1 || true',
        'ping -c 3 -i 0.2 -q -W 2 "$OUT" >/dev/null 2>&1 || true',
        'for round in 1 2 3; do',
        '  measure "peer" "$PEER"',
        '  measure "outsider" "$OUT"',
        'done',
    ]
    out = _run_guest(ctx, ssm, member_ids[0], rtt_script,
                     f"measuring RTT from {member_ids[0]} to its group peer and to the outsider")
    rtt = _reports(out, "SIM2REAL-RTT")
    assert len(rtt) == 6, (
        f"expected three interleaved rounds against each target (six lines); the guest printed "
        f"{rtt!r} (stdout={out!r})"
    )
    for rec in rtt:
        assert rec.get("ok") == "1", (
            f"a ping round to {rec.get('target')!r} did not complete inside the guest: {rec!r}"
        )
        assert rec.get("loss") == "0", (
            f"the RTT comparison is only meaningful at zero loss, but the round to "
            f"{rec.get('target')!r} lost packets: {rec!r}"
        )
    peer_mins = [float(r["min"]) for r in rtt if r["target"] == "peer"]
    outsider_mins = [float(r["min"]) for r in rtt if r["target"] == "outsider"]
    assert len(peer_mins) == 3 and len(outsider_mins) == 3, (
        f"the rounds are not three-and-three: {rtt!r}"
    )
    # Each round must have produced a real timing from the guest's own kernel. Asserted rather than
    # merely parsed, so a canned `rtt min/avg/max/mdev = 0/0/0/0` cannot satisfy the records above.
    # No ordering between the targets is asserted: the ungrouped instance may land on the same
    # rack, so "in-group is closer" is a scheduler tendency, not a contract.
    assert all(v > 0.0 for v in peer_mins + outsider_mins), (
        f"every ping round must report a positive minimum round trip measured in the guest on "
        f"{member_ids[0]}, to its group peer {member_ids[1]} and to the ungrouped {outsider_id}, "
        f"but the minima were peer={peer_mins!r} outsider={outsider_mins!r} ({rtt!r})"
    )



    # Teardown runs here, inside the check's own budget: waiting for instances to terminate and
    # then deleting the network takes longer than the default cleanup bound allows.
    ctx.run_cleanups()


# AWS-managed ENIs of resources deleted asynchronously linger in the VPC, so network deletes wait
# (bounded) for them and retry DependencyViolation before raising with the ENIs still attached.
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
